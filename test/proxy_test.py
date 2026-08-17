"""Unit tests for host-side proxy auth selection (no network or VM)."""
import importlib.util
import http.client
import json
import os
import socket
import ssl
import subprocess
import sys
import tempfile
import threading
from base64 import b64encode
from contextlib import contextmanager
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

    def test_codex_refresh_is_delegated_to_codex_managed_auth(self):
        with tempfile.TemporaryDirectory() as directory:
            credentials_path = Path(directory) / "auth.json"
            credentials_path.write_text(json.dumps({
                "auth_mode": "chatgpt",
                "tokens": {
                    "access_token": "old-access",
                    "refresh_token": "old-refresh",
                    "account_id": "account-id",
                },
            }))

            def managed_refresh():
                data = json.loads(credentials_path.read_text())
                data["tokens"]["access_token"] = "new-access"
                data["tokens"]["refresh_token"] = "new-refresh"
                credentials_path.write_text(json.dumps(data))

            with patch.object(proxy, "CODEX_CREDENTIALS_PATH", str(credentials_path)), \
                 patch.object(proxy, "CODEX_REFRESH_LOCK_PATH", str(Path(directory) / "refresh.lock")), \
                 patch.object(proxy, "request_codex_managed_refresh", side_effect=managed_refresh) as refresh, \
                 patch.object(proxy, "refresh_token") as direct_refresh:
                self.assertEqual(
                    proxy.resolve_codex_oauth(
                        force_refresh=True, rejected_access="old-access"
                    ),
                    ("new-access", "account-id", "openai"),
                )
            refresh.assert_called_once_with()
            direct_refresh.assert_not_called()
            data = json.loads(credentials_path.read_text())
            self.assertEqual(data["tokens"]["access_token"], "new-access")
            self.assertEqual(data["tokens"]["refresh_token"], "new-refresh")

    def test_codex_refresh_adopts_token_rotated_by_another_proxy(self):
        with tempfile.TemporaryDirectory() as directory:
            credentials_path = Path(directory) / "auth.json"
            credentials_path.write_text(json.dumps({
                "auth_mode": "chatgpt",
                "tokens": {
                    "access_token": "rejected-access",
                    "refresh_token": "old-refresh",
                    "account_id": "account-id",
                },
            }))

            @contextmanager
            def competing_proxy_refresh():
                data = json.loads(credentials_path.read_text())
                data["tokens"]["access_token"] = "other-proxy-access"
                data["tokens"]["refresh_token"] = "other-proxy-refresh"
                credentials_path.write_text(json.dumps(data))
                yield

            with patch.object(proxy, "CODEX_CREDENTIALS_PATH", str(credentials_path)), \
                 patch.object(proxy, "codex_refresh_lock", competing_proxy_refresh), \
                 patch.object(proxy, "request_codex_managed_refresh") as refresh:
                self.assertEqual(
                    proxy.resolve_codex_oauth(
                        force_refresh=True, rejected_access="rejected-access"
                    ),
                    ("other-proxy-access", "account-id", "openai"),
                )
            refresh.assert_not_called()

    def test_codex_refresh_lock_excludes_a_second_proxy_process(self):
        contender = (
            "import fcntl, os, sys; "
            "fd = os.open(sys.argv[1], os.O_CREAT | os.O_RDWR, 0o600); "
            "fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)"
        )
        with tempfile.TemporaryDirectory() as directory:
            lock_path = str(Path(directory) / "refresh.lock")
            with patch.object(proxy, "CODEX_REFRESH_LOCK_PATH", lock_path):
                with proxy.codex_refresh_lock():
                    blocked = subprocess.run(
                        [sys.executable, "-c", contender, lock_path],
                        check=False,
                        capture_output=True,
                        text=True,
                    )
                acquired = subprocess.run(
                    [sys.executable, "-c", contender, lock_path],
                    check=False,
                    capture_output=True,
                    text=True,
                )
                lock_mode = Path(lock_path).stat().st_mode & 0o777
        self.assertNotEqual(blocked.returncode, 0)
        self.assertEqual(acquired.returncode, 0, acquired.stderr)
        self.assertEqual(lock_mode, 0o600)


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

    def test_daemon_renews_registered_running_box_without_project_resolution(self):
        with tempfile.TemporaryDirectory() as directory:
            registrations = Path(directory) / "gh-proxy-boxes"
            registrations.mkdir()
            (registrations / "devbox-existing-1234.url").write_text(
                "http://host.lima.internal:4141\n"
            )
            history = {}
            with patch.object(proxy, "STATE_DIR", directory), \
                 patch.object(proxy, "BIND_PORT", 4141), \
                 patch.object(proxy, "GITHUB_PROXY_RENEW_SECONDS", 100), \
                 patch.object(proxy, "running_lima_instances", return_value={"devbox-existing-1234"}), \
                 patch.object(proxy, "deliver_github_proxy_capability") as deliver:
                first = proxy.refresh_registered_github_proxy_boxes(history, now=1000)
                second = proxy.refresh_registered_github_proxy_boxes(history, now=1050)
                third = proxy.refresh_registered_github_proxy_boxes(history, now=1101)

        self.assertEqual(first, {"registered": 1, "running": 1, "renewed": 1, "failed": 0})
        self.assertEqual(second["renewed"], 0)
        self.assertEqual(third["renewed"], 1)
        self.assertEqual(deliver.call_count, 2)
        deliver.assert_called_with("devbox-existing-1234", "http://host.lima.internal:4141")

    def test_daemon_does_not_start_a_stopped_registered_box(self):
        with tempfile.TemporaryDirectory() as directory:
            registrations = Path(directory) / "gh-proxy-boxes"
            registrations.mkdir()
            (registrations / "devbox-stopped.url").write_text(
                "http://host.lima.internal:4141\n"
            )
            with patch.object(proxy, "STATE_DIR", directory), \
                 patch.object(proxy, "BIND_PORT", 4141), \
                 patch.object(proxy, "running_lima_instances", return_value=set()), \
                 patch.object(proxy, "deliver_github_proxy_capability") as deliver:
                summary = proxy.refresh_registered_github_proxy_boxes(force=True)

        self.assertEqual(summary, {"registered": 1, "running": 0, "renewed": 0, "failed": 0})
        deliver.assert_not_called()

    def test_capability_delivery_keeps_token_out_of_process_arguments(self):
        completed = Mock(returncode=0, stdout="", stderr="")
        with patch.object(proxy, "issue_github_proxy_token", return_value="part.one"), \
             patch.object(proxy.subprocess, "run", return_value=completed) as run:
            proxy.deliver_github_proxy_capability(
                "devbox-existing-1234",
                "http://host.lima.internal:4141",
            )

        arguments = run.call_args.args[0]
        self.assertNotIn("part.one", " ".join(arguments))
        self.assertEqual(
            run.call_args.kwargs["input"],
            "http://part.one@host.lima.internal:4141\n",
        )

    def test_running_lima_instances_accepts_ndjson(self):
        completed = Mock(
            returncode=0,
            stdout=(
                '{"name":"devbox-running","status":"Running"}\n'
                '{"name":"devbox-stopped","status":"Stopped"}\n'
            ),
            stderr="",
        )
        with patch.object(proxy.subprocess, "run", return_value=completed):
            self.assertEqual(proxy.running_lima_instances(), {"devbox-running"})


class GitHubCliWrapperTests(TestCase):
    def test_wrapper_prefers_its_private_real_binary(self):
        with tempfile.TemporaryDirectory() as directory:
            managed = Path(directory) / "gh-proxy"
            wrapper = managed / "bin" / "gh"
            real_gh = managed / "libexec" / "gh-real"
            wrapper.parent.mkdir(parents=True)
            real_gh.parent.mkdir(parents=True)
            wrapper.write_text(GH_WRAPPER.read_text())
            wrapper.chmod(0o755)
            real_gh.write_text(
                f"#!{sys.executable}\n"
                "import json, os\n"
                "print(json.dumps({'argv': __import__('sys').argv[1:], "
                "'token': os.environ.get('GH_TOKEN'), "
                "'proxy': os.environ.get('HTTPS_PROXY')}))\n"
            )
            real_gh.chmod(0o755)
            result = subprocess.run(
                [sys.executable, str(wrapper), "api", "/rate_limit"],
                check=False,
                capture_output=True,
                text=True,
                env={
                    "PATH": "",
                    "DEVBOX_GH_PROXY_URL": "http://capability@host.lima.internal:4141",
                    "DEVBOX_GH_PROXY_CERT_DIR": "/guest/certs",
                },
            )

        self.assertEqual(result.returncode, 0, result.stderr)
        routed = json.loads(result.stdout)
        self.assertEqual(routed["argv"], ["api", "/rate_limit"])
        self.assertEqual(routed["token"], "devbox-proxy")
        self.assertEqual(routed["proxy"], "http://capability@host.lima.internal:4141")

    def test_wrapper_reads_a_renewed_proxy_url_from_its_state_file(self):
        with tempfile.TemporaryDirectory() as directory:
            fake_gh = Path(directory) / "gh"
            fake_gh.write_text(
                f"#!{sys.executable}\n"
                "import json, os\n"
                "print(json.dumps({key: os.environ.get(key) for key in "
                "('HTTPS_PROXY', 'HTTP_PROXY', 'ALL_PROXY')}))\n"
            )
            fake_gh.chmod(0o755)
            proxy_url_file = Path(directory) / "proxy-url"
            proxy_url_file.write_text("http://renewed-capability@host.lima.internal:4141\n")
            environment = {
                "PATH": directory,
                "DEVBOX_GH_PROXY_URL": "http://stale-capability@host.lima.internal:4141",
                "DEVBOX_GH_PROXY_URL_FILE": str(proxy_url_file),
                "DEVBOX_GH_PROXY_CERT_DIR": "/guest/certs",
            }
            result = subprocess.run(
                [sys.executable, str(GH_WRAPPER)],
                capture_output=True,
                text=True,
                env=environment,
            )
        self.assertEqual(result.returncode, 0, result.stderr)
        routed = json.loads(result.stdout)
        self.assertEqual(
            routed,
            {
                "HTTPS_PROXY": "http://renewed-capability@host.lima.internal:4141",
                "HTTP_PROXY": "http://renewed-capability@host.lima.internal:4141",
                "ALL_PROXY": "http://renewed-capability@host.lima.internal:4141",
            },
        )

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


class ProxyAuditTests(TestCase):
    def test_audit_body_keeps_prompt_content_but_redacts_known_credential_fields(self):
        body = json.dumps({
            "model": "test-model",
            "messages": [{"role": "user", "content": "review this change"}],
            "api_key": "must-not-be-recorded",
        }).encode()
        with patch.object(proxy, "AUDIT_MAX_BODY_BYTES", 4096):
            captured = proxy.audit_body(body, "application/json")
        self.assertEqual(captured["bytes"], len(body))
        self.assertFalse(captured["truncated"])
        self.assertEqual(captured["json"]["messages"][0]["content"], "review this change")
        self.assertEqual(captured["json"]["api_key"], "[redacted]")

    def test_audit_classifies_github_graphql_mutations_as_state_changes(self):
        mutation = json.dumps({"query": "mutation { closeIssue(input: {}) { issue { id } } }"}).encode()
        query = json.dumps({"query": "query { viewer { login } }"}).encode()
        self.assertEqual(proxy.audit_action("POST", "/graphql", mutation), ("graphql-mutation", True))
        self.assertEqual(proxy.audit_action("POST", "/graphql", query), ("graphql-query", False))
        self.assertEqual(proxy.audit_action("DELETE", "/repos/o/r/issues/1", None), ("delete", True))

    def test_audit_log_is_owner_only_and_html_escapes_captured_prompt_content(self):
        with tempfile.TemporaryDirectory() as directory:
            audit_path = Path(directory) / "proxy-audit.jsonl"
            report_path = Path(directory) / "report.html"
            upstream = proxy.urlsplit("https://api.example.test")
            event = proxy.build_audit_event(
                method="POST",
                target="/v1/messages?api_key=not-logged",
                upstream=upstream,
                body=b'{"prompt":"<script>alert(1)</script>"}',
                content_type="application/json",
                source="auth-proxy",
                provider="test",
                client="192.0.2.10",
                status=200,
                duration_ms=12,
            )
            with patch.object(proxy, "AUDIT_PATH", str(audit_path)), \
                 patch.object(proxy, "AUDIT_ENABLED", True):
                proxy.write_audit_event(event)
                self.assertEqual(proxy.read_audit_events(), [event])
                output = proxy.write_audit_html(str(report_path))
            self.assertEqual(output, str(report_path))
            self.assertEqual(audit_path.stat().st_mode & 0o777, 0o600)
            self.assertEqual(report_path.stat().st_mode & 0o777, 0o600)
            rendered = report_path.read_text()
            self.assertIn("&lt;script&gt;alert(1)&lt;/script&gt;", rendered)
            self.assertNotIn("api_key=not-logged", rendered)

    def test_forwarded_request_emits_a_detailed_action_audit_event(self):
        class UpstreamHandler(proxy.BaseHTTPRequestHandler):
            def do_POST(self):
                self.server.request_body = self.rfile.read(int(self.headers["Content-Length"]))
                self.send_response(201)
                self.send_header("Content-Length", "2")
                self.end_headers()
                self.wfile.write(b"ok")

            def log_message(self, *_):
                pass

        with tempfile.TemporaryDirectory() as directory:
            audit_path = Path(directory) / "proxy-audit.jsonl"
            upstream = proxy.ThreadingHTTPServer(("127.0.0.1", 0), UpstreamHandler)
            upstream_thread = threading.Thread(target=upstream.serve_forever, daemon=True)
            upstream_thread.start()
            route = {
                "match": "/v1/messages",
                "upstream": f"http://127.0.0.1:{upstream.server_address[1]}",
            }
            server = proxy.ThreadingHTTPServer(("127.0.0.1", 0), proxy.Handler)
            server_thread = threading.Thread(target=server.serve_forever, daemon=True)
            server_thread.start()
            body = json.dumps({"prompt": "audit this request", "token": "not-logged"}).encode()
            try:
                with patch.object(proxy, "ROUTES", [route]), \
                     patch.object(proxy, "AUDIT_PATH", str(audit_path)), \
                     patch.object(proxy, "AUDIT_ENABLED", True), \
                     patch.object(proxy.Handler, "log_message"):
                    connection = http.client.HTTPConnection(*server.server_address, timeout=5)
                    connection.request("POST", "/v1/messages?credential=hidden", body=body,
                                       headers={"Content-Type": "application/json"})
                    response = connection.getresponse()
                    self.assertEqual(response.status, 201)
                    self.assertEqual(response.read(), b"ok")
                    connection.close()
                    events = proxy.read_audit_events()
            finally:
                server.shutdown()
                server.server_close()
                server_thread.join(timeout=5)
                upstream.shutdown()
                upstream.server_close()
                upstream_thread.join(timeout=5)
            self.assertEqual(upstream.request_body, body)
            self.assertEqual(len(events), 1)
            event = events[0]
            self.assertEqual(event["request"]["action"], "create-or-action")
            self.assertTrue(event["request"]["mutating"])
            self.assertEqual(event["request"]["query_keys"], ["credential"])
            self.assertEqual(event["request"]["body"]["json"]["prompt"], "audit this request")
            self.assertEqual(event["request"]["body"]["json"]["token"], "[redacted]")
            self.assertEqual(event["response"]["status"], 201)
            self.assertEqual(event["response"]["bytes"], 2)


class TrafficProxyTests(TestCase):
    def test_traffic_capability_is_separate_from_github_and_limited_to_web_ports(self):
        with tempfile.TemporaryDirectory() as directory, patch.object(proxy, "STATE_DIR", directory):
            token = proxy.issue_traffic_proxy_token()
            header = {"Proxy-Authorization": "Basic " + b64encode((token + ":").encode()).decode()}
            self.assertTrue(proxy.traffic_proxy_authorized(header))
            self.assertFalse(proxy.github_proxy_authorized(header))
        self.assertEqual(proxy.traffic_connect_target("example.com:443"), ("example.com", 443))
        self.assertEqual(proxy.traffic_connect_target("example.com:80"), ("example.com", 80))
        self.assertIsNone(proxy.traffic_connect_target("example.com:22"))
        self.assertEqual(
            proxy.traffic_http_target("http://example.com/path?visible=yes"),
            ("example.com", 80, "/path?visible=yes"),
        )
        self.assertIsNone(proxy.traffic_http_target("https://example.com/path"))

    def test_traffic_proxy_refuses_private_or_loopback_destinations_before_connecting(self):
        for address in ("127.0.0.1", "10.0.0.1", "169.254.1.1", "::1"):
            with self.subTest(address=address), patch.object(
                proxy.socket,
                "getaddrinfo",
                return_value=[(socket.AF_INET6 if ":" in address else socket.AF_INET,
                               socket.SOCK_STREAM, 6, "", (address, 443, 0, 0)
                               if ":" in address else (address, 443))],
            ):
                with self.assertRaisesRegex(OSError, "no public IP address"):
                    proxy.open_traffic_connection("destination.test", 443)

    def test_connect_audit_remains_metadata_only(self):
        event = proxy.build_connect_audit_event(
            client="192.0.2.10", host="example.com", port=443, status=200,
            duration_ms=12, request_bytes=10, response_bytes=20,
        )
        self.assertEqual(event["source"], "traffic-connect")
        self.assertEqual(event["request"]["action"], "opaque-connect")
        self.assertIsNone(event["request"]["body"])
        self.assertEqual(event["response"]["request_bytes"], 10)
        self.assertEqual(event["response"]["bytes"], 20)

    def test_plain_http_proxy_forwards_and_audits_the_actual_request(self):
        class UpstreamHandler(proxy.BaseHTTPRequestHandler):
            def do_POST(self):
                self.server.request_path = self.path
                self.server.request_body = self.rfile.read(int(self.headers["Content-Length"]))
                self.server.proxy_authorization = self.headers.get("Proxy-Authorization")
                self.send_response(202)
                self.send_header("Content-Length", "2")
                self.end_headers()
                self.wfile.write(b"ok")

            def log_message(self, *_):
                pass

        with tempfile.TemporaryDirectory() as directory:
            audit_path = Path(directory) / "proxy-audit.jsonl"
            upstream = proxy.ThreadingHTTPServer(("127.0.0.1", 0), UpstreamHandler)
            upstream_thread = threading.Thread(target=upstream.serve_forever, daemon=True)
            upstream_thread.start()
            server = proxy.ThreadingHTTPServer(("127.0.0.1", 0), proxy.Handler)
            server_thread = threading.Thread(target=server.serve_forever, daemon=True)
            server_thread.start()
            body = b'{"operation":"update"}'
            try:
                with patch.object(proxy, "traffic_proxy_authorized", return_value=True), \
                     patch.object(proxy, "open_traffic_connection", side_effect=lambda *_: socket.create_connection(upstream.server_address)), \
                     patch.object(proxy, "AUDIT_PATH", str(audit_path)), \
                     patch.object(proxy, "AUDIT_ENABLED", True), \
                     patch.object(proxy.Handler, "log_message"):
                    connection = http.client.HTTPConnection(*server.server_address, timeout=5)
                    connection.request(
                        "POST", "http://example.test/action?secret=not-logged", body=body,
                        headers={"Content-Type": "application/json", "Proxy-Authorization": "Basic ignored"},
                    )
                    response = connection.getresponse()
                    self.assertEqual(response.status, 202)
                    self.assertEqual(response.read(), b"ok")
                    connection.close()
                    events = proxy.read_audit_events()
            finally:
                server.shutdown()
                server.server_close()
                server_thread.join(timeout=5)
                upstream.shutdown()
                upstream.server_close()
                upstream_thread.join(timeout=5)
            self.assertEqual(upstream.request_path, "/action?secret=not-logged")
            self.assertEqual(upstream.request_body, body)
            self.assertIsNone(upstream.proxy_authorization)
            self.assertEqual(events[0]["source"], "traffic-http")
            self.assertEqual(events[0]["request"]["query_keys"], ["secret"])
            self.assertEqual(events[0]["response"]["status"], 202)


if __name__ == "__main__":
    main()
