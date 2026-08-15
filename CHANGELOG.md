# Changelog

## v1.2.1 - 2026-08-15

- Move GitHub proxy-capability renewal into the long-lived host proxy daemon so
  registered running boxes refresh every seven hours without an open Devbox
  terminal, guest restart, or `.devbox.toml`/image resolution. Add
  `devbox proxy refresh` for an immediate manifest-independent refresh.
- Route Homebrew's public `gh` path through the managed proxy wrapper under
  `--proxy`, keeping the real binary as a private wrapper dependency and
  restoring the normal Homebrew link under `--no-auth`.

## v1.2.0 - 2026-08-15

- Persist resumable Claude Code, Codex, OpenCode, Pi, and Stado session state
  in an owner-only, per-project host directory so default disposable clones can
  be deleted and later recreated without losing their agent conversations.
  Credentials and unrelated host histories remain outside the store.
- Add `--ephemeral-sessions` / `-e` for runs that should leave no resumable
  agent state, plus `devbox sessions path|clear` for inspecting and explicitly
  deleting the retained project state.
- Existing kept boxes gain the session mount on next entry and migrate known
  in-guest session paths without overwriting a pre-existing OpenCode database.

## v1.1.0 - 2026-08-07

- `gh` is now included in golden images. With `--proxy`, the real guest CLI uses
  a GitHub-only TLS proxy and the host's existing `gh auth login`; the VM keeps
  only a dummy routing marker and short-lived proxy capability, never the
  GitHub token.
- `.devbox.toml` gains an `[image]` table (`location`, `digest`, `provision`,
  `provision_user`) so a project can define its golden — base image and baked-in
  toolchain — without a separate Lima YAML. `image = "name"` remains valid
  shorthand.
- `.devbox.toml` gains `[resources]` (`cpus`, `memory`, `disk`), with matching
  `--cpus/-j`, `--memory/-M`, `--disk/-D` flags and machine-wide defaults in
  `~/.config/devbox/config.toml`. Precedence: CLI > manifest > global > built-in
  (4 CPUs, 6GiB, 100GiB).
- `cpus`/`memory` are applied per box at clone time, so changing them no longer
  requires rebuilding the golden. `disk` is grow-only — a smaller request is
  refused with a warning rather than failing inside Lima — and is a sparse
  ceiling, so it costs only what is written. The default rose from 50GiB.
- A golden's name now includes a hash of its image spec whenever the project
  customises it, so one project can never silently redefine the golden another
  project clones from. Stock images keep their existing names.
- Project provisioning runs after the golden boots rather than as a Lima
  `provision` entry: Lima fails any start whose boot scripts outrun its
  readiness wait, which `limactl start --timeout` does not extend. Provisioning
  output is now visible live instead of buried in the guest's cloud-init log.
- Fix DNS in `systemd-resolved` guests whose cloud-image networking drops the
  DHCP DNS option (including Kali): golden images use Lima's host-aware virtual
  resolver, preserving host VPN and split-DNS behavior.
- `devbox build` reads the project manifest from the working directory, and
  gains `--manifest F` and `--yes/-y` for non-interactive builds. Baking a
  repo-controlled script into a golden requires the same approval as running one.
- Fix: the bats suite disabled `errexit` in `setup`, which is the mechanism bats
  uses to detect a failed assertion — every test reported success regardless of
  what it asserted. The suite now fails when it should.
- Fix: `--with-agent-config` now copies an allowlisted config directory when
  that directory itself is a symlink (for example a versioned Claude hook
  vault), while still refusing to follow links found inside it.
- Fix: `--with-agent-config` no longer labels an empty allowlisted instruction
  file as a possible credential.

## v1.0.6 - 2026-07-16

- Add `--with-agent-config` to copy an allowlisted set of non-secret Claude,
  Codex, OpenCode, and Stado configuration, prompts, rules, and custom agents.
  Credential files, histories, caches, and Stado keys are excluded; files that
  look like credentials are skipped.
- Add `-a` as the safe developer-ready shortcut for `--with-agent-config`,
  `--proxy`, and `--ssh-agent`. It never enables `--with-creds`.
- Add single-letter forms for every long Devbox run/build/destroy flag.

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
