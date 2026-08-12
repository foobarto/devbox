"""Unit tests for host-side proxy auth selection (no network or VM)."""
import importlib.util
import json
import os
import socket
import ssl
import subprocess
import sys
import tempfile
import threading
from base64 import b64encode
from base64 import urlsafe_b64encode
from pathlib import Path
from unittest import TestCase, main
from unittest.mock import Mock, patch


MODULE = Path(__file__).parents[1] / "proxy" / "devbox-ai-proxy.py"
GH_WRAPPER = Path(__file__).parents[1] / "proxy" / "gh-wrapper.py"
SPEC = importlib.util.spec_from_file_location("devbox_ai_proxy", MODULE)
proxy = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(proxy)


class AutoAnthropicAuthTests(TestCase):
    def test_prefers_configured_api_key(self):
        with patch.dict(os.environ, {"ANTHROPIC_API_KEY": "host-key"}, clear=False), \
             patch.object(proxy, "resolve_claude_oauth") as oauth:
            self.assertEqual(
                proxy.resolve_auth({"source": "auto:anthropic"}),
                ("x-api-key", "", "host-key", {}, ("authorization",), ""),
            )
            oauth.assert_not_called()

    def test_uses_host_claude_oauth_when_no_api_key_exists(self):
        with patch.dict(os.environ, {"ANTHROPIC_API_KEY": ""}, clear=False), \
             patch.object(proxy, "resolve_claude_oauth", return_value=("oauth-token", "anthropic")) as oauth:
            self.assertEqual(
                proxy.resolve_auth({"source": "auto:anthropic"}),
                (
                    "authorization",
                    "Bearer ",
                    "oauth-token",
                    {"anthropic-beta": proxy.CLAUDE_OAUTH_BETA},
                    ("x-api-key",),
                    "anthropic",
                ),
            )
            oauth.assert_called_once_with(False)

    def test_reports_missing_auth_instead_of_forwarding_an_empty_key(self):
        with patch.dict(os.environ, {"ANTHROPIC_API_KEY": ""}, clear=False), \
             patch.object(proxy, "resolve_claude_oauth", return_value=("", "")):
            self.assertEqual(
                proxy.resolve_auth({"source": "auto:anthropic"}),
                ("", "", "", {}, (), ""),
            )

    def test_uses_host_codex_oauth_and_account_id_when_no_api_key_exists(self):
        with patch.dict(os.environ, {"OPENAI_API_KEY": ""}, clear=False), \
             patch.object(proxy, "resolve_codex_oauth", return_value=("oauth-token", "account-id", "openai")):
            self.assertEqual(
                proxy.resolve_auth({"source": "auto:openai"}),
                (
                    "authorization",
                    "Bearer ",
                    "oauth-token",
                    {"ChatGPT-Account-ID": "account-id"},
                    (),
                    "openai",
                ),
            )

    def test_codex_backend_uses_oauth_even_when_a_platform_key_is_configured(self):
        with patch.dict(os.environ, {"OPENAI_API_KEY": "host-key"}, clear=False), \
             patch.object(proxy, "resolve_codex_oauth", return_value=("oauth-token", "account-id", "openai")):
            self.assertEqual(
                proxy.resolve_auth({"source": "auto:codex"}),
                (
                    "authorization",
                    "Bearer ",
                    "oauth-token",
                    {"ChatGPT-Account-ID": "account-id"},
                    (),
                    "openai",
                ),
            )

    def test_oauth_beta_is_added_without_removing_client_betas(self):
        headers = {"Anthropic-Beta": "feature-a,feature-b"}
        proxy.add_header_value(headers, "anthropic-beta", "oauth-beta")
        self.assertEqual(headers, {"Anthropic-Beta": "feature-a,feature-b,oauth-beta"})

    def test_claude_refresh_rotates_host_credentials_atomically(self):
        with tempfile.TemporaryDirectory() as directory:
            credentials_path = Path(directory) / "credentials.json"
            credentials_path.write_text(json.dumps({"claudeAiOauth": {
                "accessToken": "old-access", "refreshToken": "old-refresh", "expiresAt": 0,
            }}))
            with patch.object(proxy, "CLAUDE_CREDENTIALS_PATH", str(credentials_path)), \
                 patch.object(proxy, "refresh_token", return_value={
                     "access_token": "new-access", "refresh_token": "new-refresh", "expires_in": 3600,
                 }) as refresh:
                self.assertEqual(proxy.resolve_claude_oauth(), ("new-access", "anthropic"))
            refresh.assert_called_once_with(
                proxy.CLAUDE_TOKEN_URL,
                proxy.CLAUDE_CLIENT_ID,
                "old-refresh",
            )
            data = json.loads(credentials_path.read_text())
            self.assertEqual(data["claudeAiOauth"]["accessToken"], "new-access")
            self.assertEqual(data["claudeAiOauth"]["refreshToken"], "new-refresh")
            self.assertGreater(data["claudeAiOauth"]["expiresAt"], 0)

    def test_codex_refresh_rotates_host_credentials_atomically(self):
        with tempfile.TemporaryDirectory() as directory:
            credentials_path = Path(directory) / "auth.json"
            id_token = ".".join((
                urlsafe_b64encode(b"{}").decode().rstrip("="),
                urlsafe_b64encode(b'{"aud":"client"}').decode().rstrip("="),
                "signature",
            ))
            credentials_path.write_text(json.dumps({
                "auth_mode": "chatgpt",
                "tokens": {
                    "access_token": "old-access",
                    "refresh_token": "old-refresh",
                    "id_token": id_token,
                    "account_id": "account-id",
                },
            }))
            with patch.object(proxy, "CODEX_CREDENTIALS_PATH", str(credentials_path)), \
                 patch.object(proxy, "refresh_token", return_value={
                     "access_token": "new-access", "refresh_token": "new-refresh",
                 }):
                self.assertEqual(
                    proxy.resolve_codex_oauth(force_refresh=True),
                    ("new-access", "account-id", "openai"),
                )
            data = json.loads(credentials_path.read_text())
            self.assertEqual(data["tokens"]["access_token"], "new-access")
            self.assertEqual(data["tokens"]["refresh_token"], "new-refresh")
            self.assertIn("last_refresh", data)


class GitHubCliProxyTests(TestCase):
    def test_prefers_an_explicit_host_github_token(self):
        with patch.dict(os.environ, {"GH_TOKEN": "host-gh-token"}, clear=False), \
             patch.object(proxy.subprocess, "run") as run:
            self.assertEqual(proxy.resolve_github_token(), "host-gh-token")
        run.assert_not_called()

    def test_reads_the_host_gh_login_without_leaking_its_token(self):
        result = Mock(returncode=0, stdout="host-gh-token\n")
        with patch.dict(os.environ, {"GH_TOKEN": "", "GITHUB_TOKEN": ""}, clear=False), \
             patch.object(proxy.subprocess, "run", return_value=result) as run:
            self.assertEqual(proxy.resolve_github_token(), "host-gh-token")
        self.assertEqual(run.call_args.args[0], ["gh", "auth", "token", "--hostname", "github.com"])
        self.assertNotIn("GH_TOKEN", run.call_args.kwargs["env"])
        self.assertNotIn("GITHUB_TOKEN", run.call_args.kwargs["env"])

    def test_github_auth_replaces_the_guest_routing_marker(self):
        with patch.object(proxy, "resolve_github_token", return_value="host-gh-token"):
            self.assertEqual(
                proxy.resolve_auth({"source": "auto:github"}),
                ("authorization", "Bearer ", "host-gh-token", {}, ("x-api-key",), "github"),
            )

    def test_connect_allows_only_github_tls_hosts(self):
        self.assertEqual(proxy.github_connect_target("api.github.com:443"), ("mitm", "api.github.com"))
        self.assertEqual(proxy.github_connect_target("uploads.github.com:443"), ("mitm", "uploads.github.com"))
        self.assertEqual(proxy.github_connect_target("objects.githubusercontent.com:443"), ("tunnel", "objects.githubusercontent.com"))
        self.assertIsNone(proxy.github_connect_target("api.github.com:80"))
        self.assertIsNone(proxy.github_connect_target("example.com:443"))

    def test_generated_github_leaf_is_signed_by_its_local_ca(self):
        with tempfile.TemporaryDirectory() as directory, \
             patch.object(proxy, "STATE_DIR", directory):
            ca_path, certificate, private_key = proxy.ensure_github_certificates()
            self.assertTrue(Path(ca_path).is_file())
            self.assertTrue(Path(certificate).is_file())
            self.assertEqual(Path(private_key).stat().st_mode & 0o777, 0o600)
            verified = proxy.subprocess.run(
                ["openssl", "verify", "-CAfile", ca_path, certificate],
                check=False,
                capture_output=True,
                text=True,
            )
        self.assertEqual(verified.returncode, 0, verified.stderr)

    def test_connect_upgrades_to_a_locally_trusted_github_tls_session(self):
        with tempfile.TemporaryDirectory() as directory, \
             patch.object(proxy, "STATE_DIR", directory), \
             patch.object(proxy, "resolve_github_token", return_value=""), \
             patch.object(proxy.Handler, "log_message"):
            ca_path, _, _ = proxy.ensure_github_certificates()
            capability = proxy.issue_github_proxy_token()
            server = proxy.ThreadingHTTPServer(("127.0.0.1", 0), proxy.Handler)
            thread = threading.Thread(target=server.serve_forever, daemon=True)
            thread.start()
            try:
                raw = socket.create_connection(server.server_address, timeout=5)
                authorization = b64encode(f"{capability}:".encode()).decode()
                raw.sendall(
                    b"CONNECT api.github.com:443 HTTP/1.1\r\n"
                    b"Host: api.github.com:443\r\n"
                    + f"Proxy-Authorization: Basic {authorization}\r\n\r\n".encode()
                )
                response = bytearray()
                while b"\r\n\r\n" not in response:
                    response.extend(raw.recv(4096))
                self.assertIn(b" 200 ", bytes(response).split(b"\r\n", 1)[0])
                context = ssl.create_default_context(cafile=ca_path)
                client = context.wrap_socket(raw, server_hostname="api.github.com")
                self.assertEqual(client.version()[:3], "TLS")
                client.sendall(b"GET / HTTP/1.1\r\nHost: api.github.com\r\nConnection: close\r\n\r\n")
                self.assertIn(b" 503 ", client.recv(4096).split(b"\r\n", 1)[0])
                client.close()
            finally:
                server.shutdown()
                server.server_close()
                thread.join(timeout=5)

    def test_connect_rejects_an_expired_capability(self):
        with tempfile.TemporaryDirectory() as directory, \
             patch.object(proxy, "STATE_DIR", directory), \
             patch.object(proxy, "GITHUB_PROXY_TOKEN_TTL_SECONDS", 60):
            capability = proxy.issue_github_proxy_token()
            encoded = b64encode(f"{capability}:".encode()).decode()
            self.assertTrue(proxy.valid_github_proxy_token(capability))
            headers = {"Proxy-Authorization": f"Basic {encoded}"}
            self.assertTrue(proxy.github_proxy_authorized(headers))
            with patch.object(proxy.time, "time", return_value=proxy.time.time() + 61):
                self.assertFalse(proxy.github_proxy_authorized(headers))


class GitHubCliWrapperTests(TestCase):
    def test_wrapper_routes_only_gh_through_the_credential_proxy(self):
        with tempfile.TemporaryDirectory() as directory:
            fake_gh = Path(directory) / "gh"
            fake_gh.write_text(
                f"#!{sys.executable}\n"
                "import json, os\n"
                "print(json.dumps({key: os.environ.get(key) for key in "
                "('GH_TOKEN', 'GITHUB_TOKEN', 'HTTPS_PROXY', 'SSL_CERT_DIR')}))\n"
            )
            fake_gh.chmod(0o755)
            environment = {
                "PATH": directory,
                "DEVBOX_GH_PROXY_URL": "http://capability@host.lima.internal:4141",
                "DEVBOX_GH_PROXY_CERT_DIR": "/guest/certs",
                "SSL_CERT_DIR": "/existing/certs",
            }
            result = subprocess.run(
                [sys.executable, str(GH_WRAPPER), "api", "/user"],
                check=False,
                capture_output=True,
                text=True,
                env=environment,
            )
        self.assertEqual(result.returncode, 0, result.stderr)
        routed = json.loads(result.stdout)
        self.assertEqual(routed["GH_TOKEN"], "devbox-proxy")
        self.assertEqual(routed["GITHUB_TOKEN"], "devbox-proxy")
        self.assertEqual(routed["HTTPS_PROXY"], "http://capability@host.lima.internal:4141")
        self.assertEqual(routed["SSL_CERT_DIR"], "/guest/certs:/existing/certs")

    def test_wrapper_refuses_guest_auth_mutation(self):
        result = subprocess.run(
            [sys.executable, str(GH_WRAPPER), "auth", "login"],
            check=False,
            capture_output=True,
            text=True,
            env={"PATH": os.environ.get("PATH", "")},
        )
        self.assertEqual(result.returncode, 2)
        self.assertIn("host GitHub CLI login", result.stderr)


if __name__ == "__main__":
    main()
