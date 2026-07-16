"""Unit tests for host-side proxy auth selection (no network or VM)."""
import importlib.util
import json
import os
import tempfile
from base64 import urlsafe_b64encode
from pathlib import Path
from unittest import TestCase, main
from unittest.mock import patch


MODULE = Path(__file__).parents[1] / "proxy" / "devbox-ai-proxy.py"
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


if __name__ == "__main__":
    main()
