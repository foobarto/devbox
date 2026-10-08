"""Exercise the guest catalog refresh through its actual shell transport."""

import json
import os
from pathlib import Path
import subprocess
import tempfile
import threading
import tomllib
import unittest
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer


DEVBOX = Path(__file__).resolve().parents[1] / "bin" / "devbox"
CATALOG = {"models": [{"slug": "gpt-daybreak-blue-latest",
                       "display_name": "Daybreak Blue", "description": "Test model",
                       "supported_reasoning_levels": [{"effort": "low", "description": "Fast"}],
                       "default_reasoning_level": "low", "shell_type": "unified_exec",
                       "visibility": "list", "supported_in_api": True, "priority": 1,
                       "base_instructions": "Test instructions", "support_verbosity": False,
                       "default_verbosity": "low", "apply_patch_tool_type": "freeform",
                       "truncation_policy": {"mode": "tokens", "limit": 10000},
                       "input_modalities": ["text"], "experimental_supported_tools": [],
                       "context_window": 272000, "effective_context_window_percent": 95}]}


class CatalogTests(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary.cleanup)
        self.home = Path(self.temporary.name)
        self.profile = self.home / ".devbox" / "codex-proxy"
        self.catalog = self.profile / "models.json"
        self.config = self.profile / "config.toml"
        binary = self.home / "bin" / "codex"
        binary.parent.mkdir()
        binary.write_text('''#!/usr/bin/env python3
import json,sys
if sys.argv[1:] == ["--version"]:
    print("codex-cli 0.160.0")
else:
    path = json.loads(next(a.split("=", 1)[1] for a in sys.argv
                           if a.startswith("model_catalog_json=")))
    data = json.load(open(path))
    if any("supported_reasoning_levels" not in model for model in data["models"]):
        sys.exit(1)
''')
        binary.chmod(0o700)
        self.status = 200
        self.body = json.dumps(CATALOG).encode()
        self.requests = []
        self.slow = threading.Event()
        test = self

        class Handler(BaseHTTPRequestHandler):
            def do_GET(self):
                test.requests.append((self.path, self.headers.get("Authorization")))
                if test.status == -1:
                    self.connection.sendall(b"broken status line\r\n\r\n")
                    self.close_connection = True
                    return
                self.send_response(200 if test.status == -2 else test.status)
                if test.status == 302:
                    self.send_header("Location", test.base_url + "/redirected")
                self.end_headers()
                try:
                    if test.status == -2:
                        # Keep the socket active past its per-read timeout.
                        for _ in range(150):
                            if test.slow.wait(0.2):
                                return
                            self.wfile.write(b" ")
                            self.wfile.flush()
                        return
                    self.wfile.write(test.body)
                except (BrokenPipeError, ConnectionResetError):
                    pass

            def log_message(self, *_args):
                pass

        self.server = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
        self.base_url = f"http://127.0.0.1:{self.server.server_port}"
        thread = threading.Thread(target=self.server.serve_forever, daemon=True)
        thread.start()
        self.addCleanup(self.server.server_close)
        self.addCleanup(self.server.shutdown)
        self.addCleanup(self.slow.set)

    def refresh(self):
        result = subprocess.run(
            ["bash", "-c", 'source "$1"; limactl() { shift 3; "$@"; }; '
             'refresh_codex_proxy_config box "$2" "$3"', "bash", str(DEVBOX),
             self.base_url + "/backend-api/codex", "dbx-ai.box.testcapability"],
            env=dict(os.environ, HOME=str(self.home),
                     PATH=str(self.home / "bin") + os.pathsep + os.environ["PATH"],
                     # An unrelated environment proxy must never see the capability.
                     HTTP_PROXY="http://127.0.0.1:1", http_proxy="http://127.0.0.1:1",
                     NO_PROXY="", no_proxy=""),
            capture_output=True, text=True, timeout=25)
        self.assertNotIn("dbx-ai.box.testcapability", result.stdout + result.stderr)
        return result

    def test_account_catalog_and_permissions(self):
        self.assertEqual(self.refresh().returncode, 0)
        self.assertEqual(json.loads(self.catalog.read_text()), CATALOG)
        config = tomllib.loads(self.config.read_text())
        self.assertEqual(config["model_catalog_json"], str(self.catalog))
        self.assertEqual(config["openai_base_url"], self.base_url + "/backend-api/codex")
        self.assertEqual(self.requests, [
            ("/backend-api/codex/models?client_version=0.160.0",
             "Bearer dbx-ai.box.testcapability")])
        for path in (self.home / ".devbox", self.profile):
            self.assertEqual(path.stat().st_mode & 0o777, 0o700)
        for path in (self.catalog, self.config):
            self.assertEqual(path.stat().st_mode & 0o777, 0o600)

    def test_failures_keep_previous_catalog(self):
        self.assertEqual(self.refresh().returncode, 0)
        original = self.catalog.read_bytes()
        for status, body in ((503, b"unavailable"), (200, b"invalid JSON"),
                             (200, b'{"models": []}'),
                             (200, b'{"models": [{"slug": "x"}]}'),
                             (200, b'{"models": [{"slug": "x", "display_name": "X"}]}'),
                             (200, b" " * (4 * 1024 * 1024 + 1))):
            with self.subTest(status=status, bytes=len(body)):
                self.status, self.body = status, body
                result = self.refresh()
                self.assertEqual(result.returncode, 0, result.stderr)
                self.assertIn("could not refresh", result.stderr)
                self.assertEqual(self.catalog.read_bytes(), original)
                self.assertEqual(tomllib.loads(self.config.read_text())["model_catalog_json"],
                                 str(self.catalog))

    def test_malformed_http_uses_safe_fallback(self):
        self.status = -1
        result = self.refresh()
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertIn("could not refresh", result.stderr)
        self.assertNotIn("Traceback", result.stderr)
        self.assertFalse(self.catalog.exists())

    def test_slow_response_hits_overall_deadline(self):
        self.status = -2
        result = self.refresh()
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertIn("could not refresh", result.stderr)
        self.assertFalse(self.catalog.exists())

    def test_first_failure_uses_bundled_catalog(self):
        self.status = 404
        result = self.refresh()
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertNotIn("model_catalog_json", tomllib.loads(self.config.read_text()))
        self.assertFalse(self.catalog.exists())

    def test_redirect_is_not_followed(self):
        self.status = 302
        result = self.refresh()
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(len(self.requests), 1)
        self.assertFalse(self.catalog.exists())

    def test_symlinks_are_refused_before_network_or_writes(self):
        target = self.home / "target"
        target.mkdir()
        for path in (self.home / ".devbox", self.profile, self.catalog, self.config):
            with self.subTest(path=path.name):
                path.parent.mkdir(parents=True, exist_ok=True)
                path.symlink_to(target)
                result = self.refresh()
                self.assertNotEqual(result.returncode, 0)
                self.assertIn("refusing a symlink", result.stderr)
                self.assertEqual(self.requests, [])
                self.assertEqual(list(target.iterdir()), [])
                path.unlink()


if __name__ == "__main__":
    unittest.main()
