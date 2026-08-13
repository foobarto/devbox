#!/usr/bin/env python3
"""devbox-ai-proxy — zero-dependency host-side credential proxy.

Keeps real credentials on the *host* so disposable devboxes never hold them.
For each route it injects auth from one of:

  * a static API key         -> "env:OPENAI_API_KEY"
  * a token read *fresh* from a file on every request (OAuth access tokens that
    the host keeps refreshed) -> "token-file:~/.claude/.credentials.json#claudeAiOauth.accessToken"
  * the output of a command  -> "token-cmd:some-command"
  * automatic Anthropic auth -> prefer ANTHROPIC_API_KEY, then host Claude OAuth
  * automatic GitHub auth    -> host `gh auth token` for GitHub CLI traffic

Responses are streamed (SSE-friendly). Python standard library only — no pip.
For `gh`, a GitHub-only CONNECT proxy terminates TLS with a per-host Devbox CA,
replaces the guest's routing marker with the host `gh` token, and then connects
to GitHub. The guest never receives the real token.

Config: JSON at $DEVBOX_PROXY_CONFIG (defaults to proxy.config.example.json next
to this file). See that file for the shape.
"""
import base64
import hashlib
import html
import hmac
import http.client
import ipaddress
import json
import os
import select
import secrets
import socket
import ssl
import subprocess
import sys
import tempfile
import threading
import time
from datetime import UTC, datetime
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import urlencode, urlsplit

CONFIG_PATH = os.environ.get(
    "DEVBOX_PROXY_CONFIG",
    os.path.join(os.path.dirname(os.path.abspath(__file__)), "proxy.config.example.json"),
)
with open(CONFIG_PATH) as _f:
    CONFIG = json.load(_f)

LISTEN = CONFIG.get("listen", "0.0.0.0:4141")
_HOST, _PORT = LISTEN.rsplit(":", 1)
BIND_HOST = "" if _HOST in ("0.0.0.0", "*") else _HOST
BIND_PORT = int(_PORT)
ROUTES = CONFIG.get("routes", [])
STATE_DIR = os.path.expanduser(
    os.environ.get("DEVBOX_PROXY_STATE_DIR", os.path.join("~", ".config", "devbox"))
)
_AUDIT_CONFIG = CONFIG.get("audit", {})
if not isinstance(_AUDIT_CONFIG, dict):
    _AUDIT_CONFIG = {}
_audit_enabled = os.environ.get("DEVBOX_PROXY_AUDIT")
AUDIT_ENABLED = (
    _AUDIT_CONFIG.get("enabled", True)
    if _audit_enabled is None
    else _audit_enabled.lower() not in ("0", "false", "no", "off")
)
AUDIT_PATH = os.path.abspath(os.path.expanduser(os.environ.get(
    "DEVBOX_PROXY_AUDIT_PATH",
    _AUDIT_CONFIG.get("path", os.path.join(STATE_DIR, "proxy-audit.jsonl")),
)))
try:
    AUDIT_MAX_BODY_BYTES = max(
        0,
        int(os.environ.get("DEVBOX_PROXY_AUDIT_MAX_BODY_BYTES", _AUDIT_CONFIG.get("max_body_bytes", 1048576))),
    )
except (TypeError, ValueError):
    AUDIT_MAX_BODY_BYTES = 1048576
AUDIT_SCHEMA = "devbox.proxy.audit/v1"
_AUDIT_LOCK = threading.Lock()

# OAuth credentials stay on the host. Access tokens are reread for every
# request, refreshed before expiry, and retried once after an auth failure.
CLAUDE_OAUTH_SOURCE = "token-file:~/.claude/.credentials.json#claudeAiOauth.accessToken"
CLAUDE_OAUTH_BETA = "oauth-2025-04-20"
CLAUDE_CREDENTIALS_PATH = os.path.expanduser("~/.claude/.credentials.json")
# Claude Code's current public OAuth client identifier. This identifies the
# CLI, not the user, and is the same value shipped by the official client.
CLAUDE_TOKEN_URL = "https://platform.claude.com/v1/oauth/token"
CLAUDE_CLIENT_ID = "9d1c250a-e61b-44d9-88ed-5944d1962f5e"

CODEX_CREDENTIALS_PATH = os.path.expanduser("~/.codex/auth.json")
CODEX_TOKEN_URL = "https://auth.openai.com/oauth/token"
REFRESH_SKEW_SECONDS = 300
REFRESH_POLL_SECONDS = 60
_REFRESH_LOCKS = {"anthropic": threading.Lock(), "openai": threading.Lock()}
_GITHUB_CERT_LOCK = threading.Lock()
_GITHUB_CAPABILITY_LOCK = threading.Lock()
_TRAFFIC_CAPABILITY_LOCK = threading.Lock()
GITHUB_MITM_HOSTS = {"api.github.com", "uploads.github.com"}
GITHUB_PROXY_TOKEN_TTL_SECONDS = 8 * 60 * 60
TRAFFIC_PROXY_TOKEN_TTL_SECONDS = 8 * 60 * 60

# hop-by-hop + length/host headers we never forward verbatim
DROP = {
    "connection", "keep-alive", "proxy-authenticate", "proxy-authorization",
    "te", "trailers", "transfer-encoding", "upgrade", "content-length", "host",
}

# Audit records intentionally omit all request headers. Redact the credential
# fields that may occur in JSON request bodies too, while preserving prompts,
# GitHub payloads, and a hash of the original bytes for forensic correlation.
AUDIT_SECRET_KEYS = {
    "access_token", "api_key", "authorization", "client_secret", "cookie",
    "password", "proxy_authorization", "refresh_token", "secret", "token",
}


def _audit_key_is_secret(key: object) -> bool:
    normalized = str(key).lower().replace("-", "_")
    return normalized in AUDIT_SECRET_KEYS or normalized.endswith("_token") or normalized.endswith("_secret")


def _redact_audit_value(value):
    if isinstance(value, dict):
        return {
            str(key): "[redacted]" if _audit_key_is_secret(key) else _redact_audit_value(item)
            for key, item in value.items()
        }
    if isinstance(value, list):
        return [_redact_audit_value(item) for item in value]
    return value


def audit_body(body: bytes | None, content_type: str = "") -> dict | None:
    """Capture a request payload without retaining headers or known secrets."""
    if body is None:
        return None
    captured = body[:AUDIT_MAX_BODY_BYTES]
    record = {
        "bytes": len(body),
        "sha256": hashlib.sha256(body).hexdigest(),
        "truncated": len(captured) != len(body),
    }
    if not captured:
        return record
    try:
        text = captured.decode("utf-8")
    except UnicodeDecodeError:
        record["encoding"] = "binary"
        return record
    media_type = content_type.partition(";")[0].strip().lower()
    if not record["truncated"] and (media_type.endswith("/json") or media_type.endswith("+json")):
        try:
            record["json"] = _redact_audit_value(json.loads(text))
            return record
        except json.JSONDecodeError:
            pass
    record["text"] = text
    return record


def audit_action(method: str, path: str, body: bytes | None) -> tuple[str, bool]:
    """Classify the externally observable operation without guessing its result."""
    method = method.upper()
    if path.rstrip("/") == "/graphql" and method == "POST":
        try:
            payload = json.loads((body or b"").decode("utf-8"))
            query = payload.get("query", "") if isinstance(payload, dict) else ""
        except (UnicodeDecodeError, json.JSONDecodeError):
            query = ""
        operation = query.lstrip().lower()
        if operation.startswith("mutation"):
            return "graphql-mutation", True
        if operation.startswith(("query", "subscription", "{")):
            return "graphql-query", False
        return "graphql-operation", False
    if method in ("GET", "HEAD", "OPTIONS"):
        return "read", False
    if method == "POST":
        return "create-or-action", True
    if method in ("PUT", "PATCH"):
        return "modify", True
    if method == "DELETE":
        return "delete", True
    return "other", False


def audit_request_target(target: str) -> tuple[str, list[str]]:
    """Preserve the action path but never persist possibly-secret query values."""
    parsed = urlsplit(target)
    query_keys = sorted({part.partition("=")[0] for part in parsed.query.split("&") if part})
    return parsed.path or "/", query_keys


def build_audit_event(
    *, method: str, target: str, upstream, body: bytes | None, content_type: str,
    source: str, provider: str, client: str, status: int, duration_ms: int,
    response_bytes: int = 0, attempts: int = 1, error: str = "", websocket: bool = False,
) -> dict:
    path, query_keys = audit_request_target(target)
    action, mutating = audit_action(method, path, body)
    request = {
        "method": method,
        "path": path,
        "query_keys": query_keys,
        "action": action,
        "mutating": mutating,
        "body": audit_body(body, content_type),
    }
    return {
        "schema": AUDIT_SCHEMA,
        "timestamp": datetime.now(UTC).isoformat().replace("+00:00", "Z"),
        "source": source,
        "client": client,
        "upstream": {"scheme": upstream.scheme, "host": upstream.hostname, "port": upstream.port},
        "provider": provider or None,
        "request": request,
        "response": {
            "status": status,
            "bytes": response_bytes,
            "duration_ms": duration_ms,
            "attempts": attempts,
            "websocket": websocket,
            "error": error or None,
        },
    }


def write_audit_event(event: dict) -> None:
    """Append a host-only JSONL record without ever exposing it to the guest."""
    if not AUDIT_ENABLED:
        return
    directory = os.path.dirname(AUDIT_PATH)
    os.makedirs(directory, mode=0o700, exist_ok=True)
    encoded = (json.dumps(event, ensure_ascii=False, separators=(",", ":")) + "\n").encode("utf-8")
    with _AUDIT_LOCK:
        descriptor = os.open(AUDIT_PATH, os.O_WRONLY | os.O_APPEND | os.O_CREAT, 0o600)
        try:
            os.fchmod(descriptor, 0o600)
            with os.fdopen(descriptor, "wb") as audit_file:
                audit_file.write(encoded)
            descriptor = -1
        finally:
            if descriptor >= 0:
                os.close(descriptor)


def read_audit_events() -> list[dict]:
    """Read valid JSONL entries, skipping a partial final line after a crash."""
    try:
        events = []
        with open(AUDIT_PATH, encoding="utf-8") as audit_file:
            for line in audit_file:
                if not line.strip():
                    continue
                try:
                    events.append(json.loads(line))
                except json.JSONDecodeError:
                    # An abrupt host shutdown can leave a final partial line.
                    continue
        return events
    except FileNotFoundError:
        return []
    except (OSError, json.JSONDecodeError) as exc:
        raise RuntimeError(f"could not read proxy audit log: {exc}") from exc


def audit_status() -> dict:
    try:
        size = os.stat(AUDIT_PATH).st_size
    except FileNotFoundError:
        size = 0
    return {
        "enabled": AUDIT_ENABLED,
        "path": AUDIT_PATH,
        "max_body_bytes": AUDIT_MAX_BODY_BYTES,
        "bytes": size,
    }


def audit_html(events: list[dict]) -> str:
    """Render a self-contained, escaped report. Its contents are sensitive."""
    mutations = sum(bool(event.get("request", {}).get("mutating")) for event in events)
    rows = []
    for event in reversed(events):
        request = event.get("request", {})
        response = event.get("response", {})
        upstream = event.get("upstream", {})
        payload = json.dumps(request.get("body"), ensure_ascii=False, indent=2, sort_keys=True)
        rows.append(
            "<tr class=\"%s\"><td>%s</td><td>%s</td><td>%s</td><td>%s %s</td>"
            "<td>%s</td><td>%s</td><td><details><summary>payload</summary><pre>%s</pre></details></td></tr>"
            % (
                "mutation" if request.get("mutating") else "read",
                html.escape(str(event.get("timestamp", ""))),
                html.escape(str(event.get("provider") or event.get("source", ""))),
                html.escape(str(upstream.get("host", ""))),
                html.escape(str(request.get("method", ""))),
                html.escape(str(request.get("path", ""))),
                html.escape(str(request.get("action", ""))),
                html.escape(str(response.get("status", ""))),
                html.escape(payload),
            )
        )
    return """<!doctype html>
<meta charset=\"utf-8\"><title>Devbox proxy audit</title>
<style>body{font:14px system-ui;margin:2rem;background:#111;color:#eee}table{border-collapse:collapse;width:100%%}th,td{border:1px solid #555;padding:.5rem;text-align:left;vertical-align:top}.mutation{background:#3b1d1d}pre{white-space:pre-wrap;word-break:break-word;max-width:72rem}summary{cursor:pointer}</style>
<h1>Devbox proxy audit</h1><p>%d request(s); %d mutating request(s). This report can contain prompts, source snippets, and GitHub payloads. Keep it private.</p>
<table><thead><tr><th>Time</th><th>Provider</th><th>Host</th><th>Request</th><th>Action</th><th>Status</th><th>Captured request payload</th></tr></thead><tbody>%s</tbody></table>
""" % (len(events), mutations, "".join(rows))


def write_audit_html(path: str) -> str:
    destination = os.path.abspath(os.path.expanduser(path or os.path.join(STATE_DIR, "proxy-audit.html")))
    os.makedirs(os.path.dirname(destination), mode=0o700, exist_ok=True)
    descriptor = os.open(destination, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
    try:
        os.fchmod(descriptor, 0o600)
        with os.fdopen(descriptor, "wb") as report_file:
            report_file.write(audit_html(read_audit_events()).encode("utf-8"))
        descriptor = -1
    finally:
        if descriptor >= 0:
            os.close(descriptor)
    return destination


def resolve_source(source: str) -> str:
    if source.startswith("env:"):
        return os.environ.get(source[4:], "")
    if source.startswith("token-file:"):
        path, _, dotted = source[len("token-file:"):].partition("#")
        try:
            with open(os.path.expanduser(path)) as fh:
                data = json.load(fh)
        except Exception:
            return ""
        if dotted:
            for key in dotted.split("."):
                if isinstance(data, dict):
                    data = data.get(key, "")
                else:
                    return ""
        return data if isinstance(data, str) else ""
    if source.startswith("token-cmd:"):
        try:
            return subprocess.check_output(
                source[len("token-cmd:"):], shell=True, text=True
            ).strip()
        except Exception:
            return ""
    return ""


def read_json(path: str) -> dict:
    try:
        with open(path) as fh:
            data = json.load(fh)
    except (OSError, json.JSONDecodeError):
        return {}
    return data if isinstance(data, dict) else {}


def write_json_atomic(path: str, data: dict) -> None:
    """Replace a host credential file without ever creating a world-readable copy."""
    directory = os.path.dirname(path)
    fd, temporary = tempfile.mkstemp(prefix=".devbox-oauth-", dir=directory)
    try:
        with os.fdopen(fd, "w") as fh:
            json.dump(data, fh, indent=2)
            fh.write("\n")
        os.chmod(temporary, 0o600)
        os.replace(temporary, path)
    except Exception:
        try:
            os.unlink(temporary)
        except OSError:
            pass
        raise


def jwt_payload(token: str) -> dict:
    """Decode only the unsigned payload needed to find a JWT expiry/client ID."""
    try:
        import base64

        payload = token.split(".")[1]
        data = base64.urlsafe_b64decode(payload + "=" * (-len(payload) % 4))
        parsed = json.loads(data)
        return parsed if isinstance(parsed, dict) else {}
    except Exception:
        return {}


def token_expiring(expires_at: object) -> bool:
    """Return whether a Unix-seconds/milliseconds expiry is within refresh skew."""
    if not isinstance(expires_at, (int, float)):
        return False
    seconds = expires_at / 1000 if expires_at > 10_000_000_000 else expires_at
    return seconds <= time.time() + REFRESH_SKEW_SECONDS


def refresh_token(token_url: str, client_id: str, refresh: str, json_body: bool = False) -> dict:
    payload = {"grant_type": "refresh_token", "refresh_token": refresh, "client_id": client_id}
    body = json.dumps(payload).encode() if json_body else urlencode(payload).encode()
    endpoint = urlsplit(token_url)
    conn = http.client.HTTPSConnection(endpoint.hostname, endpoint.port or 443, timeout=30)
    try:
        conn.request(
            "POST",
            endpoint.path,
            body=body,
            headers={
                "Content-Type": "application/json" if json_body else "application/x-www-form-urlencoded",
                "Accept": "application/json",
            },
        )
        response = conn.getresponse()
        raw = response.read()
    finally:
        conn.close()
    if response.status < 200 or response.status >= 300:
        raise RuntimeError(f"token endpoint returned HTTP {response.status}")
    data = json.loads(raw)
    if not isinstance(data, dict) or not isinstance(data.get("access_token"), str):
        raise RuntimeError("token endpoint returned no access token")
    return data


def resolve_claude_oauth(force_refresh: bool = False) -> tuple[str, str]:
    with _REFRESH_LOCKS["anthropic"]:
        credentials = read_json(CLAUDE_CREDENTIALS_PATH)
        oauth = credentials.get("claudeAiOauth")
        if not isinstance(oauth, dict):
            return "", ""
        access = oauth.get("accessToken", "")
        refresh = oauth.get("refreshToken", "")
        if force_refresh or token_expiring(oauth.get("expiresAt")):
            if not isinstance(refresh, str) or not refresh:
                return "", ""
            try:
                refreshed = refresh_token(CLAUDE_TOKEN_URL, CLAUDE_CLIENT_ID, refresh)
                access = refreshed["access_token"]
                oauth["accessToken"] = access
                oauth["refreshToken"] = refreshed.get("refresh_token", refresh)
                if isinstance(refreshed.get("expires_in"), (int, float)):
                    oauth["expiresAt"] = int((time.time() + refreshed["expires_in"]) * 1000)
                credentials["claudeAiOauth"] = oauth
                write_json_atomic(CLAUDE_CREDENTIALS_PATH, credentials)
            except Exception as exc:
                sys.stderr.write(f"[devbox-ai-proxy] Claude OAuth refresh failed: {exc}\n")
                return "", ""
        return (access, "anthropic") if isinstance(access, str) and access else ("", "")


def resolve_codex_oauth(force_refresh: bool = False) -> tuple[str, str, str]:
    with _REFRESH_LOCKS["openai"]:
        credentials = read_json(CODEX_CREDENTIALS_PATH)
        tokens = credentials.get("tokens")
        if not isinstance(tokens, dict):
            return "", "", ""
        access = tokens.get("access_token", "")
        refresh = tokens.get("refresh_token", "")
        account = tokens.get("account_id", "")
        expires_at = jwt_payload(access).get("exp") if isinstance(access, str) else None
        if force_refresh or token_expiring(expires_at):
            audience = jwt_payload(tokens.get("id_token", "")).get("aud")
            client_id = audience[0] if isinstance(audience, list) and audience else audience
            if not isinstance(client_id, str) or not client_id or not isinstance(refresh, str) or not refresh:
                return "", "", ""
            try:
                refreshed = refresh_token(CODEX_TOKEN_URL, client_id, refresh)
                access = refreshed["access_token"]
                tokens["access_token"] = access
                tokens["refresh_token"] = refreshed.get("refresh_token", refresh)
                if isinstance(refreshed.get("id_token"), str):
                    tokens["id_token"] = refreshed["id_token"]
                credentials["tokens"] = tokens
                credentials["last_refresh"] = datetime.now(UTC).isoformat().replace("+00:00", "Z")
                write_json_atomic(CODEX_CREDENTIALS_PATH, credentials)
            except Exception as exc:
                sys.stderr.write(f"[devbox-ai-proxy] Codex OAuth refresh failed: {exc}\n")
                return "", "", ""
        if not isinstance(access, str) or not access:
            return "", "", ""
        return access, account if isinstance(account, str) else "", "openai"


def resolve_github_token() -> str:
    """Read the host GitHub CLI token without ever sending it to the guest."""
    for name in ("GH_TOKEN", "GITHUB_TOKEN"):
        token = os.environ.get(name, "")
        if token:
            return token

    # Ask the host CLI rather than reading its config/keyring directly. Remove
    # the environment fallbacks so a non-empty marker inherited by the proxy
    # cannot be mistaken for a real stored credential.
    environment = dict(os.environ)
    environment.pop("GH_TOKEN", None)
    environment.pop("GITHUB_TOKEN", None)
    try:
        completed = subprocess.run(
            ["gh", "auth", "token", "--hostname", "github.com"],
            check=False,
            capture_output=True,
            text=True,
            timeout=15,
            env=environment,
        )
    except (OSError, subprocess.SubprocessError):
        return ""
    return completed.stdout.strip() if completed.returncode == 0 else ""


def resolve_auth(auth: dict, force_refresh: bool = False):
    """Return headers and provider for one route auth block.

    The automatic routes prefer a host API key, then use a host OAuth login.
    OAuth request headers from the guest are deliberately replaced: the guest
    carries only a dummy key, while the proxy owns the real bearer credential.
    """
    source = auth.get("source", "")
    if source == "auto:anthropic":
        api_key = os.environ.get("ANTHROPIC_API_KEY", "")
        if api_key:
            return "x-api-key", "", api_key, {}, ("authorization",), ""
        oauth_token, provider = resolve_claude_oauth(force_refresh)
        if oauth_token:
            return (
                "authorization",
                "Bearer ",
                oauth_token,
                {"anthropic-beta": CLAUDE_OAUTH_BETA},
                ("x-api-key",),
                provider,
            )
        return "", "", "", {}, (), ""
    if source in ("auto:openai", "auto:codex"):
        api_key = os.environ.get("OPENAI_API_KEY", "")
        if api_key and source == "auto:openai":
            return "authorization", "Bearer ", api_key, {}, (), ""
        oauth_token, account_id, provider = resolve_codex_oauth(force_refresh)
        if oauth_token:
            extra = {"ChatGPT-Account-ID": account_id} if account_id else {}
            return "authorization", "Bearer ", oauth_token, extra, (), provider
        return "", "", "", {}, (), ""
    if source == "auto:github":
        token = resolve_github_token()
        if token:
            return "authorization", "Bearer ", token, {}, ("x-api-key",), "github"
        return "", "", "", {}, (), ""
    return (
        auth.get("header", ""),
        auth.get("prefix", ""),
        resolve_source(source),
        {},
        (),
        "",
    )


def maintain_oauth_sessions() -> None:
    """Refresh host OAuth sessions even while no devbox is sending requests."""
    while True:
        resolve_claude_oauth()
        resolve_codex_oauth()
        time.sleep(REFRESH_POLL_SECONDS)


def add_header_value(headers: dict, name: str, value: str) -> None:
    """Add a comma-delimited header value without discarding client betas."""
    existing_name = next((key for key in headers if key.lower() == name.lower()), name)
    existing = headers.get(existing_name, "")
    if not existing:
        headers[existing_name] = value
        return
    values = [part.strip() for part in existing.split(",")]
    if value not in values:
        headers[existing_name] = f"{existing},{value}"


def match_route(path: str):
    for route in ROUTES:
        if path.startswith(route.get("match", "")):
            return route
    return None


def github_connect_target(authority: str) -> tuple[str, str] | None:
    """Classify a CONNECT target as TLS-intercepted GitHub or a safe tunnel."""
    host, separator, port = authority.rpartition(":")
    if not separator or not host or port != "443":
        return None
    hostname = host.lower().rstrip(".")
    if hostname in GITHUB_MITM_HOSTS:
        return "mitm", hostname
    if hostname == "github.com" or hostname.endswith(".github.com") or hostname.endswith(".githubusercontent.com"):
        return "tunnel", hostname
    return None


def github_certificate_paths() -> tuple[str, str, str]:
    return (
        os.path.join(STATE_DIR, "gh-proxy-ca.pem"),
        os.path.join(STATE_DIR, "gh-proxy-leaf.pem"),
        os.path.join(STATE_DIR, "gh-proxy-leaf-key.pem"),
    )


def ensure_github_certificates() -> tuple[str, str, str]:
    """Create a local CA and GitHub leaf certificate once, with strict modes."""
    with _GITHUB_CERT_LOCK:
        ca_path, cert_path, key_path = github_certificate_paths()
        if all(os.path.isfile(path) for path in (ca_path, cert_path, key_path)):
            return ca_path, cert_path, key_path

        os.makedirs(STATE_DIR, mode=0o700, exist_ok=True)
        with tempfile.TemporaryDirectory(prefix=".devbox-gh-ca-", dir=STATE_DIR) as directory:
            ca_key = os.path.join(directory, "ca-key.pem")
            ca_cert = os.path.join(directory, "ca.pem")
            leaf_key = os.path.join(directory, "leaf-key.pem")
            leaf_csr = os.path.join(directory, "leaf.csr")
            leaf_cert = os.path.join(directory, "leaf.pem")
            ca_config = os.path.join(directory, "ca.cnf")
            leaf_config = os.path.join(directory, "leaf.cnf")
            with open(ca_config, "w", encoding="utf-8") as config:
                config.write("""[req]\ndistinguished_name = dn\nx509_extensions = v3_ca\nprompt = no\n[dn]\nCN = Devbox GitHub Proxy CA\n[v3_ca]\nbasicConstraints = critical, CA:true\nkeyUsage = critical, keyCertSign, cRLSign\nsubjectKeyIdentifier = hash\n""")
            with open(leaf_config, "w", encoding="utf-8") as config:
                config.write("""[req]\ndistinguished_name = dn\nreq_extensions = v3_req\nprompt = no\n[dn]\nCN = api.github.com\n[v3_req]\nbasicConstraints = critical, CA:false\nkeyUsage = critical, digitalSignature, keyEncipherment\nextendedKeyUsage = serverAuth\nsubjectAltName = @alt_names\n[alt_names]\nDNS.1 = api.github.com\nDNS.2 = uploads.github.com\n""")
            commands = (
                ["openssl", "req", "-x509", "-newkey", "rsa:2048", "-nodes", "-days", "3650", "-keyout", ca_key, "-out", ca_cert, "-config", ca_config],
                ["openssl", "req", "-new", "-newkey", "rsa:2048", "-nodes", "-keyout", leaf_key, "-out", leaf_csr, "-config", leaf_config],
                ["openssl", "x509", "-req", "-in", leaf_csr, "-CA", ca_cert, "-CAkey", ca_key, "-CAcreateserial", "-out", leaf_cert, "-days", "825", "-extfile", leaf_config, "-extensions", "v3_req"],
            )
            try:
                for command in commands:
                    subprocess.run(command, check=True, stdout=subprocess.DEVNULL, stderr=subprocess.PIPE)
            except FileNotFoundError as exc:
                raise RuntimeError("GitHub CLI proxy needs openssl on the host") from exc
            except subprocess.CalledProcessError as exc:
                detail = exc.stderr.decode("utf-8", "replace").strip()
                raise RuntimeError(f"could not create GitHub CLI proxy certificate: {detail}") from exc

            for source, destination, mode in (
                (ca_cert, ca_path, 0o644),
                (leaf_cert, cert_path, 0o644),
                (leaf_key, key_path, 0o600),
            ):
                os.chmod(source, mode)
                os.replace(source, destination)
        return ca_path, cert_path, key_path


def github_proxy_key_path() -> str:
    return os.path.join(STATE_DIR, "gh-proxy-capability-key")


def github_proxy_key() -> bytes:
    """Load or create the host-only key that signs short-lived guest grants."""
    with _GITHUB_CAPABILITY_LOCK:
        path = github_proxy_key_path()
        try:
            with open(path, "rb") as key_file:
                key = key_file.read()
            if len(key) >= 32:
                return key
        except OSError:
            pass

        os.makedirs(STATE_DIR, mode=0o700, exist_ok=True)
        key = secrets.token_bytes(32)
        descriptor, temporary = tempfile.mkstemp(prefix=".devbox-gh-capability-", dir=STATE_DIR)
        try:
            with os.fdopen(descriptor, "wb") as key_file:
                key_file.write(key)
            os.chmod(temporary, 0o600)
            os.replace(temporary, path)
        except Exception:
            try:
                os.unlink(temporary)
            except OSError:
                pass
            raise
        return key


def _base64url(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).decode("ascii").rstrip("=")


def _base64url_decode(value: str) -> bytes:
    return base64.urlsafe_b64decode(value + "=" * (-len(value) % 4))


def issue_github_proxy_token() -> str:
    """Issue a VM-only, time-limited proxy capability; never a GitHub token."""
    payload = json.dumps(
        {"aud": "devbox-gh", "exp": int(time.time()) + GITHUB_PROXY_TOKEN_TTL_SECONDS},
        separators=(",", ":"),
    ).encode("utf-8")
    encoded = _base64url(payload)
    signature = hmac.new(github_proxy_key(), encoded.encode("ascii"), "sha256").digest()
    return f"{encoded}.{_base64url(signature)}"


def valid_github_proxy_token(token: str) -> bool:
    try:
        encoded, signature = token.split(".", 1)
        expected = hmac.new(github_proxy_key(), encoded.encode("ascii"), "sha256").digest()
        if not hmac.compare_digest(_base64url_decode(signature), expected):
            return False
        payload = json.loads(_base64url_decode(encoded))
        return payload.get("aud") == "devbox-gh" and int(payload.get("exp", 0)) >= int(time.time())
    except (ValueError, TypeError, UnicodeError, json.JSONDecodeError, OSError):
        return False


def github_proxy_authorized(headers) -> bool:
    """Validate the short-lived Basic-proxy credential supplied by the wrapper."""
    authorization = headers.get("Proxy-Authorization", "")
    if not authorization.startswith("Basic "):
        return False
    try:
        decoded = base64.b64decode(authorization[6:], validate=True).decode("utf-8")
        username, separator, password = decoded.partition(":")
    except (ValueError, UnicodeError):
        return False
    return bool(separator) and not password and valid_github_proxy_token(username)


def traffic_proxy_key_path() -> str:
    return os.path.join(STATE_DIR, "traffic-proxy-capability-key")


def traffic_proxy_key() -> bytes:
    """Load or create the host-only key for generic traffic-audit grants."""
    with _TRAFFIC_CAPABILITY_LOCK:
        path = traffic_proxy_key_path()
        try:
            with open(path, "rb") as key_file:
                key = key_file.read()
            if len(key) >= 32:
                return key
        except OSError:
            pass
        os.makedirs(STATE_DIR, mode=0o700, exist_ok=True)
        key = secrets.token_bytes(32)
        descriptor, temporary = tempfile.mkstemp(prefix=".devbox-traffic-capability-", dir=STATE_DIR)
        try:
            with os.fdopen(descriptor, "wb") as key_file:
                key_file.write(key)
            os.chmod(temporary, 0o600)
            os.replace(temporary, path)
        except Exception:
            try:
                os.unlink(temporary)
            except OSError:
                pass
            raise
        return key


def issue_traffic_proxy_token() -> str:
    """Issue a VM-only generic HTTP(S) CONNECT capability, never a host token."""
    payload = json.dumps(
        {"aud": "devbox-traffic", "exp": int(time.time()) + TRAFFIC_PROXY_TOKEN_TTL_SECONDS},
        separators=(",", ":"),
    ).encode("utf-8")
    encoded = _base64url(payload)
    signature = hmac.new(traffic_proxy_key(), encoded.encode("ascii"), "sha256").digest()
    return f"{encoded}.{_base64url(signature)}"


def valid_traffic_proxy_token(token: str) -> bool:
    try:
        encoded, signature = token.split(".", 1)
        expected = hmac.new(traffic_proxy_key(), encoded.encode("ascii"), "sha256").digest()
        if not hmac.compare_digest(_base64url_decode(signature), expected):
            return False
        payload = json.loads(_base64url_decode(encoded))
        return payload.get("aud") == "devbox-traffic" and int(payload.get("exp", 0)) >= int(time.time())
    except (ValueError, TypeError, UnicodeError, json.JSONDecodeError, OSError):
        return False


def traffic_proxy_authorized(headers) -> bool:
    """Validate a time-limited generic CONNECT capability from a Devbox."""
    authorization = headers.get("Proxy-Authorization", "")
    if not authorization.startswith("Basic "):
        return False
    try:
        decoded = base64.b64decode(authorization[6:], validate=True).decode("utf-8")
        username, separator, password = decoded.partition(":")
    except (ValueError, UnicodeError):
        return False
    return bool(separator) and not password and valid_traffic_proxy_token(username)


def traffic_connect_target(authority: str) -> tuple[str, int] | None:
    """Allow the capability only to make web CONNECT tunnels on ports 80/443."""
    try:
        parsed = urlsplit("//" + authority)
        host, port = parsed.hostname, parsed.port
    except ValueError:
        return None
    if not host or parsed.username or parsed.password or port not in (80, 443):
        return None
    return host, port


def traffic_http_target(target: str) -> tuple[str, int, str] | None:
    """Parse an ordinary HTTP proxy request, limited to port 80.

    HTTPS clients use CONNECT. Plain HTTP proxy clients use an absolute-form
    request target instead, so accepting this form avoids an unnecessary
    compatibility hole while retaining the same capability and target checks.
    """
    try:
        parsed = urlsplit(target)
        host, port = parsed.hostname, parsed.port or 80
    except ValueError:
        return None
    if (
        parsed.scheme != "http" or not host or parsed.username or parsed.password
        or port != 80 or parsed.fragment
    ):
        return None
    path = parsed.path or "/"
    if parsed.query:
        path += "?" + parsed.query
    return host, port, path


def open_traffic_connection(host: str, port: int) -> socket.socket:
    """Connect only to an address that cannot pivot through the host proxy.

    Resolve once and connect to the selected numeric address.  This prevents a
    hostname from resolving publicly during validation and privately during a
    later connection (DNS rebinding), while keeping the original hostname for
    the client's TLS SNI inside a CONNECT tunnel.
    """
    errors: list[OSError] = []
    try:
        addresses = socket.getaddrinfo(host, port, type=socket.SOCK_STREAM)
    except OSError as exc:
        raise OSError(f"could not resolve traffic destination: {exc}") from exc
    for family, socktype, protocol, _, sockaddr in addresses:
        try:
            address = ipaddress.ip_address(sockaddr[0])
        except ValueError:
            continue
        # Generic guest traffic must not turn the host proxy into access to its
        # loopback, LAN, or link-local services.  `is_global` rejects all such
        # ranges and other special-use addresses.
        if not address.is_global:
            continue
        connection = socket.socket(family, socktype, protocol)
        connection.settimeout(30)
        try:
            connection.connect(sockaddr)
            return connection
        except OSError as exc:
            errors.append(exc)
            connection.close()
    if errors:
        raise OSError(f"could not connect to public traffic destination: {errors[-1]}")
    raise OSError("traffic destination has no public IP address")


def build_connect_audit_event(
    *, client: str, host: str, port: int, status: int, duration_ms: int,
    request_bytes: int = 0, response_bytes: int = 0, error: str = "",
) -> dict:
    return {
        "schema": AUDIT_SCHEMA,
        "timestamp": datetime.now(UTC).isoformat().replace("+00:00", "Z"),
        "source": "traffic-connect",
        "client": client,
        "upstream": {"scheme": "https" if port == 443 else "http", "host": host, "port": port},
        "provider": None,
        "request": {
            "method": "CONNECT",
            "path": "/",
            "query_keys": [],
            "action": "opaque-connect",
            "mutating": False,
            "body": None,
        },
        "response": {
            "status": status,
            "bytes": response_bytes,
            "request_bytes": request_bytes,
            "duration_ms": duration_ms,
            "attempts": 1,
            "websocket": False,
            "error": error or None,
        },
    }


class Handler(BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"
    server_version = "devbox-ai-proxy"

    def handle(self):
        # A CLI can close just after a successful CONNECT/TLS handshake. The
        # stdlib request loop otherwise reports that ordinary disconnect as a
        # server traceback, which is noisy and can leave the wrapped socket open.
        try:
            super().handle()
        except (BrokenPipeError, ConnectionResetError, ssl.SSLError, OSError):
            self.close_connection = True

    def finish(self):
        try:
            super().finish()
        finally:
            connection = getattr(self, "connection", None)
            if connection is not None and connection is not self.request:
                try:
                    connection.close()
                except OSError:
                    pass

    def log_message(self, fmt, *args):  # to stderr, quiet-ish
        sys.stderr.write("[devbox-ai-proxy] %s %s\n" % (self.command, self.path))

    def _open_websocket(self, upstream, headers):
        """Open a WebSocket upstream, returning its socket and raw response.

        The proxy is deliberately frame-agnostic after the HTTP Upgrade: it
        only terminates the local HTTP connection, injects host auth into the
        handshake, and relays WebSocket bytes in both directions.
        """
        raw = socket.create_connection(
            (upstream.hostname, upstream.port or (443 if upstream.scheme == "https" else 80)),
            timeout=30,
        )
        conn = raw
        try:
            if upstream.scheme == "https":
                conn = ssl.create_default_context().wrap_socket(raw, server_hostname=upstream.hostname)
            request = [f"{self.command} {self.path} HTTP/1.1"]
            request.extend(f"{key}: {value}" for key, value in headers.items())
            conn.sendall(("\r\n".join(request) + "\r\n\r\n").encode("iso-8859-1"))

            response = bytearray()
            while b"\r\n\r\n" not in response:
                chunk = conn.recv(65536)
                if not chunk:
                    raise RuntimeError("upstream closed during WebSocket handshake")
                response.extend(chunk)
                if len(response) > 65536:
                    raise RuntimeError("WebSocket handshake headers exceed 64 KiB")
            status_line = bytes(response).split(b"\r\n", 1)[0].decode("iso-8859-1")
            parts = status_line.split(" ", 2)
            if len(parts) < 2 or not parts[1].isdigit():
                raise RuntimeError(f"invalid WebSocket response: {status_line!r}")
            return conn, int(parts[1]), bytes(response)
        except Exception:
            conn.close()
            raise

    def _relay_socket(self, upstream):
        sockets = (self.connection, upstream)
        request_bytes = response_bytes = 0
        try:
            while True:
                readable, _, _ = select.select(sockets, (), (), 600)
                if not readable:
                    continue
                for source in readable:
                    data = source.recv(65536)
                    if not data:
                        return request_bytes, response_bytes
                    if source is self.connection:
                        request_bytes += len(data)
                        upstream.sendall(data)
                    else:
                        response_bytes += len(data)
                        self.connection.sendall(data)
        except (BrokenPipeError, ConnectionResetError, OSError):
            pass
        finally:
            upstream.close()
            self.close_connection = True
        return request_bytes, response_bytes

    def _connect(self):
        """Handle capability-scoped generic web tunnels and GitHub `gh` tunnels."""
        traffic_target = traffic_connect_target(self.path)
        if traffic_target and traffic_proxy_authorized(self.headers):
            hostname, port = traffic_target
            started = time.monotonic()
            try:
                upstream = open_traffic_connection(hostname, port)
            except OSError as exc:
                self.send_error(502, "traffic CONNECT error: %s" % exc)
                try:
                    write_audit_event(build_connect_audit_event(
                        client=self.client_address[0] if self.client_address else "",
                        host=hostname,
                        port=port,
                        status=502,
                        duration_ms=round((time.monotonic() - started) * 1000),
                        error="connect-error",
                    ))
                except Exception as audit_exc:
                    sys.stderr.write(f"[devbox-ai-proxy] audit write failed: {audit_exc}\n")
                return
            self.send_response(200, "Connection Established")
            self.end_headers()
            request_bytes, response_bytes = self._relay_socket(upstream)
            try:
                write_audit_event(build_connect_audit_event(
                    client=self.client_address[0] if self.client_address else "",
                    host=hostname,
                    port=port,
                    status=200,
                    duration_ms=round((time.monotonic() - started) * 1000),
                    request_bytes=request_bytes,
                    response_bytes=response_bytes,
                ))
            except Exception as audit_exc:
                sys.stderr.write(f"[devbox-ai-proxy] audit write failed: {audit_exc}\n")
            return
        target = github_connect_target(self.path)
        if target is None:
            self.send_error(403, "CONNECT is limited to GitHub HTTPS hosts")
            return
        if not github_proxy_authorized(self.headers):
            self.send_response(407, "Devbox GitHub proxy authentication required")
            self.send_header("Proxy-Authenticate", 'Basic realm="devbox-gh"')
            self.send_header("Connection", "close")
            self.end_headers()
            self.close_connection = True
            return
        mode, hostname = target

        if mode == "tunnel":
            try:
                upstream = socket.create_connection((hostname, 443), timeout=30)
            except OSError as exc:
                self.send_error(502, "GitHub tunnel error: %s" % exc)
                return
            self.send_response(200, "Connection Established")
            self.end_headers()
            self._relay_socket(upstream)
            return

        try:
            _, certificate, private_key = ensure_github_certificates()
            context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
            context.load_cert_chain(certificate, private_key)
            self.send_response(200, "Connection Established")
            self.end_headers()
            self.wfile.flush()
            connection = context.wrap_socket(self.connection, server_side=True)
        except Exception as exc:
            self.send_error(502, "GitHub TLS proxy setup failed: %s" % exc)
            return

        # BaseHTTPRequestHandler keeps one instance for the full TCP connection.
        # Replacing its streams here means the next request loop receives the
        # decrypted API request and can send it through the normal auth path.
        self.connection = connection
        self.rfile = connection.makefile("rb", self.rbufsize)
        self.wfile = connection.makefile("wb", self.wbufsize)
        self._github_connect_host = hostname
        self.close_connection = False

    def _proxy(self):
        # Health/identity endpoint so callers can distinguish this proxy from
        # any other service that happens to hold the port.
        if self.path.startswith("/_devbox"):
            body = b"devbox-ai-proxy ok\n"
            self.send_response(200)
            self.send_header("Content-Type", "text/plain")
            self.send_header("Content-Length", str(len(body)))
            self.send_header("X-Devbox-Proxy", "1")
            self.end_headers()
            try:
                self.wfile.write(body)
            except (BrokenPipeError, ConnectionResetError):
                pass
            self.close_connection = True
            return
        traffic_target = traffic_http_target(self.path)
        if traffic_target is not None:
            self._traffic_http_proxy(*traffic_target)
            return
        github_host = getattr(self, "_github_connect_host", "")
        route = (
            {"upstream": f"https://{github_host}", "auth": {"source": "auto:github"}}
            if github_host
            else match_route(self.path)
        )
        if route is None:
            self.send_error(404, "no matching route")
            return
        up = urlsplit(route["upstream"])

        length = int(self.headers.get("Content-Length", 0) or 0)
        body = self.rfile.read(length) if length else None
        audit_started = time.monotonic()
        audit_source = "github-connect" if github_host else "auth-proxy"
        client = self.client_address[0] if self.client_address else ""

        def audit_outcome(
            status: int, provider: str = "", error: str = "", response_bytes: int = 0,
            attempts: int = 1, websocket: bool = False,
        ) -> None:
            try:
                write_audit_event(build_audit_event(
                    method=self.command,
                    target=self.path,
                    upstream=up,
                    body=body,
                    content_type=self.headers.get("Content-Type", ""),
                    source=audit_source,
                    provider=provider,
                    client=client,
                    status=status,
                    duration_ms=round((time.monotonic() - audit_started) * 1000),
                    response_bytes=response_bytes,
                    attempts=attempts,
                    error=error,
                    websocket=websocket,
                ))
            except Exception as exc:
                sys.stderr.write(f"[devbox-ai-proxy] audit write failed: {exc}\n")

        strip = {h.lower() for h in (route.get("strip_headers") or [])}
        incoming_headers = {
            k: v for k, v in self.headers.items()
            if k.lower() not in DROP and k.lower() not in strip
        }
        websocket_headers = {
            k: v for k, v in self.headers.items() if k.lower() not in strip
        }
        auth = route.get("auth")
        conn_cls = http.client.HTTPSConnection if up.scheme == "https" else http.client.HTTPConnection

        def request_headers(force_refresh: bool = False, websocket: bool = False):
            headers = dict(websocket_headers if websocket else incoming_headers)
            provider = ""
            if auth:
                hname, prefix, value, extra_headers, remove_headers, provider = resolve_auth(
                    auth, force_refresh
                )
                if not hname or not value:
                    return None, ""
                remove = {hname.lower(), *(name.lower() for name in remove_headers)}
                headers = {k: v for k, v in headers.items() if k.lower() not in remove}
                headers[hname] = prefix + value
                for key, extra_value in extra_headers.items():
                    add_header_value(headers, key, extra_value)
            for key, header_value in (route.get("set_headers") or {}).items():
                headers[key] = header_value
            headers["Host"] = up.netloc
            return headers, provider

        is_websocket = self.headers.get("Upgrade", "").lower() == "websocket"
        if is_websocket:
            attempts = 1
            try:
                headers, provider = request_headers(websocket=True)
                if headers is None:
                    self.send_error(503, "authentication source is unavailable")
                    audit_outcome(503, error="authentication-unavailable", websocket=True)
                    return
                conn, status, response = self._open_websocket(up, headers)
                if status in (401, 403) and provider:
                    conn.close()
                    headers, _ = request_headers(force_refresh=True, websocket=True)
                    if headers is None:
                        self.send_error(503, "OAuth refresh failed")
                        audit_outcome(503, provider, "oauth-refresh-failed", attempts=2, websocket=True)
                        return
                    conn, status, response = self._open_websocket(up, headers)
                    attempts = 2
            except Exception as exc:
                self.send_error(502, "WebSocket upstream error: %s" % exc)
                audit_outcome(502, error="websocket-upstream-error", attempts=attempts, websocket=True)
                return
            try:
                self.connection.sendall(response)
                if status == 101:
                    audit_outcome(status, provider, response_bytes=len(response), attempts=attempts, websocket=True)
                    self._relay_socket(conn)
                    return
            except (BrokenPipeError, ConnectionResetError, OSError):
                pass
            finally:
                if status != 101:
                    conn.close()
            audit_outcome(status, provider, response_bytes=len(response), attempts=attempts, websocket=True)
            self.close_connection = True
            return

        headers, provider = request_headers()
        if headers is None:
            self.send_error(503, "authentication source is unavailable")
            audit_outcome(503, error="authentication-unavailable")
            return

        def upstream_request(request_headers):
            conn = conn_cls(
                up.hostname, up.port or (443 if up.scheme == "https" else 80), timeout=600
            )
            try:
                conn.request(self.command, self.path, body=body, headers=request_headers)
                return conn, conn.getresponse()
            except Exception:
                conn.close()
                raise

        try:
            conn, resp = upstream_request(headers)
            attempts = 1
            # OAuth access tokens can be revoked between the preflight and this
            # request. Refresh once and replay only the failed request.
            if resp.status in (401, 403) and provider:
                resp.read()
                conn.close()
                headers, _ = request_headers(force_refresh=True)
                if headers is None:
                    self.send_error(503, "OAuth refresh failed")
                    audit_outcome(503, provider, "oauth-refresh-failed", attempts=2)
                    return
                conn, resp = upstream_request(headers)
                attempts = 2
        except Exception as exc:  # upstream unreachable / TLS / etc.
            self.send_error(502, "upstream error: %s" % exc)
            audit_outcome(502, provider, "upstream-error")
            return

        # Stream back with Connection: close (no re-chunking; works for SSE).
        self.send_response(resp.status, resp.reason)
        for k, v in resp.getheaders():
            if k.lower() in DROP:
                continue
            self.send_header(k, v)
        self.send_header("Connection", "close")
        self.end_headers()
        response_bytes = 0
        try:
            while True:
                chunk = resp.read(65536)
                if not chunk:
                    break
                response_bytes += len(chunk)
                self.wfile.write(chunk)
                self.wfile.flush()
        except (BrokenPipeError, ConnectionResetError):
            pass
        finally:
            conn.close()
            audit_outcome(resp.status, provider, response_bytes=response_bytes, attempts=attempts)
        self.close_connection = True

    def _traffic_http_proxy(self, hostname: str, port: int, path: str) -> None:
        """Forward plain HTTP through the generic capability-scoped proxy."""
        if not traffic_proxy_authorized(self.headers):
            self.send_response(407, "Devbox traffic proxy authentication required")
            self.send_header("Proxy-Authenticate", 'Basic realm="devbox-traffic"')
            self.send_header("Connection", "close")
            self.end_headers()
            self.close_connection = True
            return
        length = int(self.headers.get("Content-Length", 0) or 0)
        body = self.rfile.read(length) if length else None
        started = time.monotonic()
        client = self.client_address[0] if self.client_address else ""
        upstream_url = urlsplit(f"http://{hostname}:{port}")

        def audit_outcome(status: int, error: str = "", response_bytes: int = 0) -> None:
            try:
                write_audit_event(build_audit_event(
                    method=self.command,
                    target=self.path,
                    upstream=upstream_url,
                    body=body,
                    content_type=self.headers.get("Content-Type", ""),
                    source="traffic-http",
                    provider="",
                    client=client,
                    status=status,
                    duration_ms=round((time.monotonic() - started) * 1000),
                    response_bytes=response_bytes,
                    error=error,
                ))
            except Exception as audit_exc:
                sys.stderr.write(f"[devbox-ai-proxy] audit write failed: {audit_exc}\n")

        try:
            upstream_socket = open_traffic_connection(hostname, port)
            connection = http.client.HTTPConnection(hostname, port, timeout=600)
            connection.sock = upstream_socket
            connection.putrequest(self.command, path, skip_host=True, skip_accept_encoding=True)
            for header, value in self.headers.items():
                if header.lower() not in DROP and header.lower() != "proxy-connection":
                    connection.putheader(header, value)
            connection.putheader("Host", hostname)
            if body is not None:
                connection.putheader("Content-Length", str(len(body)))
            connection.endheaders(body)
            response = connection.getresponse()
        except Exception as exc:
            self.send_error(502, "traffic HTTP error: %s" % exc)
            audit_outcome(502, "upstream-error")
            return

        self.send_response(response.status, response.reason)
        for header, value in response.getheaders():
            if header.lower() not in DROP:
                self.send_header(header, value)
        self.send_header("Connection", "close")
        self.end_headers()
        response_bytes = 0
        try:
            while True:
                chunk = response.read(65536)
                if not chunk:
                    break
                response_bytes += len(chunk)
                self.wfile.write(chunk)
                self.wfile.flush()
        except (BrokenPipeError, ConnectionResetError):
            pass
        finally:
            connection.close()
            audit_outcome(response.status, response_bytes=response_bytes)
        self.close_connection = True

    do_GET = do_POST = do_PUT = do_DELETE = do_PATCH = do_OPTIONS = _proxy
    do_CONNECT = _connect


def main():
    args = sys.argv[1:]
    if args == ["--init-gh-ca"]:
        ca_path, _, _ = ensure_github_certificates()
        print(ca_path)
        return
    if args == ["--new-gh-proxy-token"]:
        print(issue_github_proxy_token())
        return
    if args == ["--new-traffic-proxy-token"]:
        print(issue_traffic_proxy_token())
        return
    if args == ["--audit-status"]:
        print(json.dumps(audit_status(), sort_keys=True))
        return
    if args[:1] == ["--audit-show"]:
        if len(args) > 2:
            raise SystemExit("usage: devbox-ai-proxy --audit-show [LIMIT]")
        try:
            limit = int(args[1]) if len(args) == 2 else 50
        except ValueError as exc:
            raise SystemExit("audit LIMIT must be a non-negative integer") from exc
        if limit < 0:
            raise SystemExit("audit LIMIT must be a non-negative integer")
        for event in read_audit_events()[-limit:]:
            print(json.dumps(event, ensure_ascii=False, sort_keys=True))
        return
    if args[:1] == ["--audit-export"]:
        if len(args) > 2:
            raise SystemExit("usage: devbox-ai-proxy --audit-export [FILE]")
        print(write_audit_html(args[1] if len(args) == 2 else ""))
        return
    srv = ThreadingHTTPServer((BIND_HOST, BIND_PORT), Handler)
    sys.stderr.write(
        "[devbox-ai-proxy] listening on %s:%d  (config: %s, %d route(s))\n"
        % (_HOST, BIND_PORT, CONFIG_PATH, len(ROUTES))
    )
    threading.Thread(
        target=maintain_oauth_sessions,
        name="devbox-oauth-refresh",
        daemon=True,
    ).start()
    sys.stderr.write(
        "[devbox-ai-proxy] host OAuth refresh enabled (checks every %ss)\n"
        % REFRESH_POLL_SECONDS
    )
    try:
        srv.serve_forever()
    except KeyboardInterrupt:
        sys.stderr.write("\n[devbox-ai-proxy] shutting down\n")


if __name__ == "__main__":
    main()
