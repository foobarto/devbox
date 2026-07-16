# Changelog

## v1.0.5 - 2026-07-16

- Golden images skip Lima's unused rootless-containerd bootstrap, avoiding an
  unnecessary daemon and a provisioning hang on current Lima releases.
- Golden provisioning now pins GitHub SSH host keys using the Meta API, with a
  GitHub Docs fallback when the unauthenticated API quota is exhausted.
- devbox build now rejects and removes a golden that lacks all three GitHub
  host keys, rather than retaining an incomplete image.
- New boxes that request SSH-agent forwarding receive it in their clone
  configuration before first boot; existing boxes keep the safe repair path.
- Fix one-item manifest package lists and file-based --with-creds copies.
- Add an opt-in, destructive end-to-end suite covering manifests, consent,
  mounts/copies/packages/start commands, SSH signing, proxy OAuth, API keys,
  copied credentials, and --no-auth.
- Resolve the CLI's real path before loading `VERSION`, so Homebrew's linked
  executable reports the installed release version correctly.

## v1.0.4 - 2026-07-16

- Make the Homebrew package install the release version metadata and document
  stable installs by default; `--HEAD` remains available for development.

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
