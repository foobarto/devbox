#!/usr/bin/env python3
"""devbox-ai-proxy — zero-dependency host-side AI proxy.

Keeps real credentials on the *host* so disposable devboxes never hold them.
For each route it injects auth from one of:

  * a static API key         -> "env:OPENAI_API_KEY"
  * a token read *fresh* from a file on every request (OAuth access tokens that
    the host keeps refreshed) -> "token-file:~/.claude/.credentials.json#claudeAiOauth.accessToken"
  * the output of a command  -> "token-cmd:some-command"
  * automatic Anthropic auth -> prefer ANTHROPIC_API_KEY, then host Claude OAuth

Responses are streamed (SSE-friendly). Python standard library only — no pip.

Config: JSON at $DEVBOX_PROXY_CONFIG (defaults to proxy.config.example.json next
to this file). See that file for the shape.
"""
import http.client
import json
import os
import select
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

# hop-by-hop + length/host headers we never forward verbatim
DROP = {
    "connection", "keep-alive", "proxy-authenticate", "proxy-authorization",
    "te", "trailers", "transfer-encoding", "upgrade", "content-length", "host",
}


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


class Handler(BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"
    server_version = "devbox-ai-proxy"

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

    def _relay_websocket(self, upstream):
        sockets = (self.connection, upstream)
        try:
            while True:
                readable, _, _ = select.select(sockets, (), (), 600)
                if not readable:
                    continue
                for source in readable:
                    data = source.recv(65536)
                    if not data:
                        return
                    (upstream if source is self.connection else self.connection).sendall(data)
        except (BrokenPipeError, ConnectionResetError, OSError):
            pass
        finally:
            upstream.close()
            self.close_connection = True

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
        route = match_route(self.path)
        if route is None:
            self.send_error(404, "no matching route")
            return
        up = urlsplit(route["upstream"])

        length = int(self.headers.get("Content-Length", 0) or 0)
        body = self.rfile.read(length) if length else None

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
            try:
                headers, provider = request_headers(websocket=True)
                if headers is None:
                    self.send_error(503, "authentication source is unavailable")
                    return
                conn, status, response = self._open_websocket(up, headers)
                if status in (401, 403) and provider:
                    conn.close()
                    headers, _ = request_headers(force_refresh=True, websocket=True)
                    if headers is None:
                        self.send_error(503, "OAuth refresh failed")
                        return
                    conn, status, response = self._open_websocket(up, headers)
            except Exception as exc:
                self.send_error(502, "WebSocket upstream error: %s" % exc)
                return
            try:
                self.connection.sendall(response)
                if status == 101:
                    self._relay_websocket(conn)
                    return
            except (BrokenPipeError, ConnectionResetError, OSError):
                pass
            finally:
                if status != 101:
                    conn.close()
            self.close_connection = True
            return

        headers, provider = request_headers()
        if headers is None:
            self.send_error(503, "authentication source is unavailable")
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
            # OAuth access tokens can be revoked between the preflight and this
            # request. Refresh once and replay only the failed request.
            if resp.status in (401, 403) and provider:
                resp.read()
                conn.close()
                headers, _ = request_headers(force_refresh=True)
                if headers is None:
                    self.send_error(503, "OAuth refresh failed")
                    return
                conn, resp = upstream_request(headers)
        except Exception as exc:  # upstream unreachable / TLS / etc.
            self.send_error(502, "upstream error: %s" % exc)
            return

        # Stream back with Connection: close (no re-chunking; works for SSE).
        self.send_response(resp.status, resp.reason)
        for k, v in resp.getheaders():
            if k.lower() in DROP:
                continue
            self.send_header(k, v)
        self.send_header("Connection", "close")
        self.end_headers()
        try:
            while True:
                chunk = resp.read(65536)
                if not chunk:
                    break
                self.wfile.write(chunk)
                self.wfile.flush()
        except (BrokenPipeError, ConnectionResetError):
            pass
        finally:
            conn.close()
        self.close_connection = True

    do_GET = do_POST = do_PUT = do_DELETE = do_PATCH = do_OPTIONS = _proxy


def main():
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
