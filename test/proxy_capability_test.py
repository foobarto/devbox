"""Live capability checks using throwaway state and local mocks."""
import hmac
import io
import json
import tempfile
import threading
from base64 import b64encode
from contextlib import redirect_stdout
from pathlib import Path
from unittest import TestCase, main
from unittest.mock import patch

from proxy_test import proxy


class LiveCapabilityTests(TestCase):
    def setUp(self):
        self.directory = tempfile.TemporaryDirectory(prefix="devbox-capability-test-")
        self.addCleanup(self.directory.cleanup)
        self.state = patch.object(proxy, "STATE_DIR", self.directory.name)
        self.state.start()
        self.addCleanup(self.state.stop)
        self.port = patch.object(proxy, "BIND_PORT", 4141)
        self.port.start()
        self.addCleanup(self.port.stop)

    def issue(self, kind, name):
        proxy.register_proxy_box(kind, name, "http://host.lima.internal:4141")
        return proxy._issue_registered_proxy_token(kind, name, None)

    def test_revoke_rejects_all_copies_and_preserves_other_box(self):
        for kind in ("github", "traffic"):
            with self.subTest(kind=kind):
                first = self.issue(kind, "devbox-a")
                second = self.issue(kind, "devbox-b")
                self.assertTrue(proxy._valid_registered_proxy_token(kind, first))
                proxy.revoke_proxy_box(kind, "devbox-a")
                self.assertFalse(proxy._valid_registered_proxy_token(kind, first))
                self.assertTrue(proxy._valid_registered_proxy_token(kind, second))
                replacement = self.issue(kind, "devbox-a")
                self.assertFalse(proxy._valid_registered_proxy_token(kind, first))
                self.assertTrue(proxy._valid_registered_proxy_token(kind, replacement))

    def test_expiry_audience_identity_and_permissions(self):
        for kind in ("github", "traffic"):
            with self.subTest(kind=kind), patch.object(proxy.time, "time", return_value=1000):
                token = self.issue(kind, "devbox-a")
                headers = {"Proxy-Authorization": "Basic " + b64encode((token + ":").encode()).decode()}
                get_box = proxy.github_request_box if kind == "github" else proxy.traffic_request_box
                self.assertEqual(get_box(headers), "devbox-a")
                other = "traffic" if kind == "github" else "github"
                self.assertFalse(proxy._valid_registered_proxy_token(other, token))
                registration = Path(proxy.proxy_registration_path(kind, "devbox-a"))
                self.assertEqual(registration.stat().st_mode & 0o777, 0o600)
                self.assertEqual(registration.parent.stat().st_mode & 0o777, 0o700)
                with patch.object(proxy.time, "time", return_value=1000 + 8 * 60 * 60):
                    self.assertFalse(proxy._valid_registered_proxy_token(kind, token))
                registration.chmod(0o644)
                self.assertFalse(proxy._valid_registered_proxy_token(kind, token))

    def test_reenter_preserves_generation_but_changed_endpoint_rotates_it(self):
        token = self.issue("github", "devbox-a")
        proxy.register_proxy_box("github", "devbox-a", "http://host.lima.internal:4141")
        self.assertTrue(proxy.valid_github_proxy_token(token))
        proxy.register_proxy_box("github", "devbox-a", "http://different.invalid:4141")
        self.assertFalse(proxy.valid_github_proxy_token(token))

    def test_legacy_stateless_tokens_rejected_with_correct_signature(self):
        for kind, audience in (("github", "devbox-gh"), ("traffic", "devbox-traffic")):
            with self.subTest(kind=kind):
                self.issue(kind, "devbox-a")
                encoded = proxy._base64url(json.dumps({"aud": audience, "exp": 2**40}).encode())
                key = proxy.github_proxy_key() if kind == "github" else proxy.traffic_proxy_key()
                signature = hmac.new(key, encoded.encode(), "sha256").digest()
                self.assertFalse(proxy._valid_registered_proxy_token(kind, encoded + "." + proxy._base64url(signature)))

    def test_issuance_cannot_create_missing_grant(self):
        for kind in ("github", "traffic"):
            with self.subTest(kind=kind), self.assertRaises(ValueError):
                proxy._issue_registered_proxy_token(kind, "devbox-a", None)
        self.assertFalse(Path(proxy.proxy_registration_path("github", "devbox-a")).exists())

    def test_registration_rejects_nonbare_endpoints_and_invalid_box_names(self):
        for endpoint in ("http://host:4141\n", "http://user@host:4141", "http://host:4141/path"):
            with self.subTest(endpoint=endpoint), self.assertRaises(ValueError):
                proxy.register_proxy_box("github", "devbox-a", endpoint)
        with self.assertRaises(ValueError):
            proxy.register_proxy_box("github", "../invalid", "http://host:4141")

    def test_custom_port_cli_registers_and_issues_but_daemon_scope_matches_listener(self):
        for kind in ("github", "traffic"):
            with self.subTest(kind=kind):
                proxy.register_proxy_box(kind, "devbox-custom", "http://host.lima.internal:5151")
                token = proxy._issue_registered_proxy_token(kind, "devbox-custom", None)
                self.assertFalse(proxy._valid_registered_proxy_token(kind, token))
                self.assertNotIn("devbox-custom", proxy._registered_proxy_boxes(kind))
                with patch.object(proxy, "BIND_PORT", 5151):
                    self.assertTrue(proxy._valid_registered_proxy_token(kind, token))
                    self.assertIn("devbox-custom", proxy._registered_proxy_boxes(kind))
                proxy.revoke_proxy_box(kind, "devbox-custom")
                with patch.object(proxy, "BIND_PORT", 5151):
                    self.assertFalse(proxy._valid_registered_proxy_token(kind, token))

    def test_custom_port_registration_and_issuance_through_actual_cli_dispatch(self):
        for kind, label in (("github", "gh"), ("traffic", "traffic")):
            with self.subTest(kind=kind):
                arguments = ["devbox-ai-proxy", "--register-" + label + "-proxy-box",
                             "devbox-custom-cli", "http://host.lima.internal:5151"]
                with patch.object(proxy.sys, "argv", arguments):
                    proxy.main()
                output = io.StringIO()
                with patch.object(proxy.sys, "argv", ["devbox-ai-proxy", "--new-" + label + "-proxy-token",
                                                    "devbox-custom-cli"]), redirect_stdout(output):
                    proxy.main()
                token = output.getvalue().strip()
                self.assertFalse(proxy._valid_registered_proxy_token(kind, token))
                with patch.object(proxy, "BIND_PORT", 5151):
                    self.assertTrue(proxy._valid_registered_proxy_token(kind, token))

    def test_stale_generation_cannot_renew_a_recreated_grant(self):
        for kind in ("github", "traffic"):
            self.issue(kind, "devbox-a")
            generation = proxy._proxy_registration(kind, "devbox-a")[1]
            proxy.revoke_proxy_box(kind, "devbox-a")
            self.issue(kind, "devbox-a")
            with self.assertRaises(ValueError):
                proxy._issue_registered_proxy_token(kind, "devbox-a", generation)

    def test_legacy_cli_without_box_name_fails_instead_of_starting_server(self):
        with patch.object(proxy.sys, "argv", ["devbox-ai-proxy", "--new-gh-proxy-token"]), \
             patch.object(proxy, "ThreadingHTTPServer") as server:
            with self.assertRaises(SystemExit):
                proxy.main()
        server.assert_not_called()

    def test_legacy_registrations_upgrade_once_and_removed_ones_stay_removed(self):
        for kind in ("github", "traffic"):
            registration = Path(proxy.proxy_registration_path(kind, "devbox-a"))
            registration.parent.mkdir(exist_ok=True)
            text = "http://host.lima.internal:4141\n" + ("grant=gh_proxy\n" if kind == "github" else "")
            registration.write_text(text)
            upgraded = proxy._registered_proxy_boxes(kind)
            self.assertEqual(proxy._registered_proxy_boxes(kind), upgraded)
            token = proxy._issue_registered_proxy_token(kind, "devbox-a", upgraded["devbox-a"][1])
            self.assertTrue(proxy._valid_registered_proxy_token(kind, token))
            proxy.revoke_proxy_box(kind, "devbox-a")
            self.assertEqual(proxy._registered_proxy_boxes(kind), {})
            self.assertFalse(proxy._valid_registered_proxy_token(kind, token))

    def test_renewal_after_waiting_revocation_cannot_resurrect_grant(self):
        for kind in ("github", "traffic"):
            self.issue(kind, "devbox-a")
            with proxy.proxy_registration_lock():
                revocation = threading.Thread(target=proxy.revoke_proxy_box, args=(kind, "devbox-a"))
                revocation.start()
                generation = proxy._proxy_registration(kind, "devbox-a")[1]
            revocation.join(timeout=5)
            self.assertFalse(revocation.is_alive())
            with self.assertRaises(ValueError):
                proxy._issue_registered_proxy_token(kind, "devbox-a", generation)
            self.assertIsNone(proxy._proxy_registration(kind, "devbox-a"))

    def test_late_renewal_delivery_is_revoked_after_regrant(self):
        issued = []
        self.issue("github", "devbox-a")

        def delivery(name, endpoint, *, expected_generation):
            issued.append(proxy.issue_github_proxy_token(name, expected_generation=expected_generation))
            proxy.revoke_proxy_box("github", name)
            proxy.register_proxy_box("github", name, endpoint)

        with patch.object(proxy, "running_lima_instances", return_value={"devbox-a"}), \
             patch.object(proxy, "ensure_github_certificates", side_effect=RuntimeError("test CA unavailable")), \
             patch.object(proxy, "deliver_github_proxy_capability", side_effect=delivery), \
             patch.object(proxy, "retract_github_proxy_capability") as retract, \
             patch.object(proxy.sys, "stderr"):
            summary = proxy.refresh_registered_github_proxy_boxes(force=True)
        self.assertEqual(summary["renewed"], 0)
        retract.assert_called_once_with("devbox-a")
        self.assertFalse(proxy.valid_github_proxy_token(issued[0]))
        self.assertTrue(proxy.valid_github_proxy_token(proxy.issue_github_proxy_token("devbox-a")))


if __name__ == "__main__":
    main()
