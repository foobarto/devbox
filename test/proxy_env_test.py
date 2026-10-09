"""Focused tests for safe host-side API-key loading."""

import importlib.util
import os
import stat
import sys
import tempfile
from pathlib import Path
from unittest import TestCase, main
from unittest.mock import patch


ROOT = Path(__file__).parents[1]
MODULE = ROOT / "proxy" / "devbox-ai-proxy.py"
_STATE = tempfile.TemporaryDirectory(prefix="devbox-proxy-env-test-")
with patch.dict(os.environ, {
    "DEVBOX_PROXY_STATE_DIR": _STATE.name,
    "DEVBOX_PROXY_AUDIT_PATH": str(Path(_STATE.name) / "audit.jsonl"),
    "DEVBOX_PROXY_CONFIG": str(MODULE.parent / "proxy.config.example.json"),
}):
    SPEC = importlib.util.spec_from_file_location("devbox_proxy_env", MODULE)
    proxy = importlib.util.module_from_spec(SPEC)
    SPEC.loader.exec_module(proxy)


class ApiKeyParserTests(TestCase):
    def test_parses_static_assignment_forms_and_common_key_characters(self):
        parsed = proxy.parse_api_key_assignments(
            """
            # provider credentials
            export ANTHROPIC_API_KEY="key with spaces"
            OPENAI_API_KEY=sk-a+/=_-.#fragment
            HASH_VALUE=#literal
            CONCATENATED="quoted"#suffix
            LITERAL='costs$5;still-data'
            ESCAPED="literal\\$value"
            EMPTY=
            """
        )
        self.assertEqual(parsed["ANTHROPIC_API_KEY"], "key with spaces")
        self.assertEqual(parsed["OPENAI_API_KEY"], "sk-a+/=_-.#fragment")
        self.assertEqual(parsed["HASH_VALUE"], "#literal")
        self.assertEqual(parsed["CONCATENATED"], "quoted#suffix")
        self.assertEqual(parsed["LITERAL"], "costs$5;still-data")
        self.assertEqual(parsed["ESCAPED"], "literal$value")
        self.assertEqual(parsed["EMPTY"], "")

    def test_rejects_shell_programs_and_expansions(self):
        for value in (
            "$(touch marker)",
            "`touch marker`",
            "$HOME",
            "value;touch-marker",
            "value|command",
            '"$(touch marker)"',
        ):
            with self.subTest(value=value), self.assertRaises(proxy.UnsafeApiKeyFile):
                proxy.parse_api_key_assignments(f"KEY={value}\n")
        with self.assertRaises(proxy.UnsafeApiKeyFile):
            proxy.parse_api_key_assignments("touch marker\n")


class ApiKeyFileTests(TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory(prefix="devbox-api-keys-")
        self.directory = Path(self.temporary.name)
        self.path = self.directory / "api-keys.env"

    def tearDown(self):
        self.temporary.cleanup()

    def write_private(self, contents="export OPENAI_API_KEY=private-key\n"):
        self.path.write_text(contents, encoding="utf-8")
        self.path.chmod(0o600)

    def test_private_owner_file_loads_without_mutating_process_environment(self):
        self.write_private("PATH=/credential/not/process/control\nOPENAI_API_KEY=private-key\n")
        inherited_path = os.environ.get("PATH")
        credentials = proxy.load_api_key_file(str(self.path))
        self.assertEqual(credentials["OPENAI_API_KEY"], "private-key")
        self.assertEqual(credentials["PATH"], "/credential/not/process/control")
        self.assertEqual(os.environ.get("PATH"), inherited_path)

    def test_missing_file_is_allowed_for_oauth_only_startup(self):
        self.assertEqual(proxy.load_api_key_file(str(self.path)), {})

    def test_group_or_other_permissions_are_rejected(self):
        for mode in (0o640, 0o604, 0o660, 0o666):
            with self.subTest(mode=oct(mode)):
                self.write_private()
                self.path.chmod(mode)
                with self.assertRaisesRegex(proxy.UnsafeApiKeyFile, "chmod 600"):
                    proxy.load_api_key_file(str(self.path))

    def test_symlink_is_rejected_without_following_it(self):
        target = self.directory / "target.env"
        target.write_text("OPENAI_API_KEY=target-key\n", encoding="utf-8")
        target.chmod(0o600)
        self.path.symlink_to(target)
        with self.assertRaisesRegex(proxy.UnsafeApiKeyFile, "cannot safely open"):
            proxy.load_api_key_file(str(self.path))

    def test_non_regular_file_is_rejected_without_blocking(self):
        os.mkfifo(self.path, 0o600)
        with self.assertRaisesRegex(proxy.UnsafeApiKeyFile, "regular file"):
            proxy.load_api_key_file(str(self.path))

    def test_foreign_owner_is_rejected(self):
        self.write_private()
        actual_uid = os.getuid()
        with patch.object(proxy.os, "getuid", return_value=actual_uid + 1):
            with self.assertRaisesRegex(proxy.UnsafeApiKeyFile, "current user"):
                proxy.load_api_key_file(str(self.path))

    def test_shell_payload_is_rejected_and_not_executed(self):
        marker = self.directory / "executed"
        self.write_private(f"OPENAI_API_KEY=$(touch${{IFS}}{marker})\n")
        with self.assertRaisesRegex(proxy.UnsafeApiKeyFile, "shell syntax"):
            proxy.load_api_key_file(str(self.path))
        self.assertFalse(marker.exists())


class CredentialLifecycleTests(TestCase):
    def test_file_value_overrides_inherited_value_without_entering_environment(self):
        with patch.dict(os.environ, {"OPENAI_API_KEY": "inherited"}), \
             patch.object(proxy, "_STATIC_CREDENTIALS", {"OPENAI_API_KEY": "from-file"}):
            self.assertEqual(proxy.resolve_source("env:OPENAI_API_KEY"), "from-file")
            self.assertEqual(os.environ["OPENAI_API_KEY"], "inherited")

    def test_maintenance_command_does_not_read_api_key_file(self):
        with patch.object(proxy, "load_api_key_file", side_effect=AssertionError("must not load")), \
             patch.object(sys, "argv", [str(MODULE), "--audit-status"]), \
             patch("builtins.print"):
            proxy.main()

    def test_proxy_ensure_tightens_existing_config_directory(self):
        with tempfile.TemporaryDirectory(prefix="devbox-config-mode-") as root:
            config = Path(root) / "config"
            config.mkdir(mode=0o755)
            config.chmod(0o755)
            script = f'''
source "{ROOT / "bin" / "devbox"}"
set +e +u
CONFIG_DIR="{config}"
proxy_health() {{ return 1; }}
proxy_port_open() {{ return 1; }}
proxy_launcher() {{ printf /bin/true; }}
sleep() {{ :; }}
proxy_ensure http://host.lima.internal:4141 >/dev/null 2>&1
exit 0
'''
            import subprocess
            subprocess.run(["bash", "-c", script], check=True)
            self.assertEqual(stat.S_IMODE(config.stat().st_mode), 0o700)


if __name__ == "__main__":
    main()
