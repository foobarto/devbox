# Changelog

## v1.0.3 - 2026-07-16

- Restore the disposable default for existing boxes: a normal invocation now
  destroys its Devbox on shell exit; only `--keep` retains it.

## v1.0.2 - 2026-07-16

- Configure signed Git commits through the host SSH agent whenever
  `--ssh-agent` is enabled; the guest receives only the selected public key.

## v1.0.1 - 2026-07-16

- Make `--ssh-agent` work for existing Devboxes: verify the host agent socket,
  update Lima's forwarding setting, and restart the box when necessary.

## v1.0.0 - 2026-07-16

- First stable release of disposable Lima development boxes with golden images.
- Add `.devbox.toml` project configuration with approval prompts for host access
  and a visible warning before a project startup command runs.
- Add a host-only AI proxy for Claude and Codex API-key or OAuth sessions,
  including proactive OAuth refresh and Codex WebSocket forwarding.
- Add `--no-auth` to explicitly remove Devbox-managed authentication from a
  kept box.
- Add repository-managed credential checks through a pre-commit hook.
