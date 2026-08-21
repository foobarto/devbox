# Changelog

## v1.3.3 - 2026-08-21

- Stop goldens and boxes from mounting the host home directory. A golden's
  `mounts: []` was silently overridden: Lima resolves an image template's
  `base:` chain at create time and an empty list reads as "unset", so a
  template-based golden re-inherited `template:_default`'s read-only `~` mount,
  which then cloned into every box and shadowed the writable project mount that
  lives under it. Goldens are now created with `--mount-none` and clones with
  `--mount-only`, so a box has exactly the mounts devbox asked for — and a
  clone drops an inherited `~` even from a golden built before this fix. Before
  handover, devbox now refuses a box whose project directory is not mounted
  writable instead of failing on the session's first write.
- Fix a `set -e` abort when a stopped, kept box gained or lost persistent
  session state: the mount helper's trailing `[[ … ]] && limactl start`
  returned non-zero on the not-running path, and as the final command of a
  `… || ensure_session_mount` list that aborted devbox before handover.
- Tests now check effective, resolved behavior rather than generated config
  text: the golden suite resolves Lima's template merge (`tmpl copy --fill`) and
  asserts on the config Lima actually boots, the mount/clone/verify paths are
  driven with a stubbed limactl and asserted on the commands issued, and the
  e2e suite boots a box to prove the project mount is writable, the host home is
  not mounted, and the toolchain resolves.

## v1.3.2 - 2026-08-21

- Fetch the Homebrew installer resiliently while provisioning a golden: retry
  the raw.githubusercontent.com download and fall back to the same file via the
  GitHub REST API, download-then-run instead of piping curl straight into bash,
  and say plainly when brew could not be installed so the `|| true` tool
  installs that follow cannot no-op silently. During the 2026-08-17 GitHub
  incident the raw-content tier answered 429 while the API tier served the
  same file.
- Reject a golden without Homebrew at verification instead of keeping it with a
  warning. brew installs gh, every AI CLI, and the project manifest's own user
  tooling, so a brew-less golden clones an empty toolchain into every later
  box. The relevant cloud-init log lines are surfaced before the instance is
  deleted, and an unreachable guest now fails verification instead of passing
  it.
- Run project provisioning manifests under `bash -e`, so a script that fails
  halfway fails the build instead of reporting whatever its last line returned.
- Delete a golden whose project provisioning failed rather than leaving it
  behind as a clone source for boxes quietly missing their toolchain.
- Run on macOS hosts. `#!/usr/bin/env bash` resolves to the bash 3.2 that macOS
  still ships as `/bin/bash` whenever `/bin` precedes a newer bash in PATH, and
  3.2 cannot parse this script: it mis-reads a heredoc nested inside command
  substitution and blames a line hundreds of lines past the real construct. An
  explicit version guard now names the requirement and the fix, and the two
  Python heredocs are read outside `$( )` so 3.2 parses the file end to end
  instead of tripping anything that reads past the guard, `bash -n` included.
- Replace the two GNU-only invocations on the host side. `stat -c %u` is rejected
  by BSD stat, so the session-root ownership check compared a real uid against an
  empty string and refused every directory with "session root is not owned by the
  current user"; and `chmod --`, which BSD chmod reads as a filename, aborted
  `prepare_session_dir` under errexit without printing anything. The portable
  helpers probe GNU before BSD — BSD stat rejects a GNU flag cleanly, while GNU
  stat reads `-f` as `--file-system` and pollutes the captured output before
  failing. The unit tests grew the same portability for their mode assertions,
  where BSD spells the permission bits `%Lp` and reserves `%a` for the access
  time.

## v1.3.1 - 2026-08-17

- Prevent host Codex and Devbox from racing the same one-time OAuth refresh
  token. The proxy now asks Codex's managed auth layer to refresh its own
  credential store, serializes all Devbox proxy refreshes with an owner-only
  host lock, and adopts a token already rotated by another process before
  retrying a rejected request.
- Document the longer first launch while a golden image is built, how to keep
  per-run startup work small, and that persistent agent sessions follow the
  canonical project path across golden rebuilds.

## v1.3.0 - 2026-08-16

- Pre-accept the AI CLIs' first-run prompts for the mounted directory on every
  run: Claude Code's onboarding, folder-trust, and custom-API-key dialogs, and
  Codex's folder-trust and sign-in prompts. Starting a Devbox for a folder is
  already the trust decision, and the VM is the boundary. Trust is seeded for
  that directory only — never `$HOME`, never `--mount` paths — answers already
  on record are kept, and a real Codex `auth.json` from `--with-creds` is never
  overwritten. A repository's own `.claude/settings.json` and hooks
  consequently run unprompted; see
  [agent capability security](docs/agent-capabilities-security.md).
- Fix `devbox build` deleting the golden it had just built. Verification
  required `pasta --splice-only`, which Ubuntu 24.04's passt predates with no
  backport available, so the default image could never produce a usable golden.
  bwrap and pasta are now probed separately, and bwrap failures name the
  command to reproduce them.
- Build the pinned upstream passt (`2026_07_28.f8df3f1`, verified against its
  commit) in goldens whose distro package is older than `--splice-only`, so
  Stado's proxy-only sandbox networking works on those images instead of being
  reported as missing.
- Install the bwrap AppArmor profile whenever the profile and parser exist,
  rather than testing `apparmor_restrict_unprivileged_userns` during
  provisioning. That sysctl is applied by the apparmor package's own units and
  races the package upgrade in the same apt run, which could leave a golden
  silently unable to sandbox.
- The e2e suite builds the golden before its timed sessions instead of folding a
  90-minute build into a capped one, and its per-session timeout is now 900s and
  overridable with `DEVBOX_E2E_SESSION_TIMEOUT`.

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
