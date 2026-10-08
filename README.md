# devbox

Disposable, CWD-mounted dev VMs on [Lima](https://lima-vm.io)/QEMU, preloaded
with an AI-CLI toolchain — **claude**, **codex**, **opencode**, **pi**, and
**stado** — plus the **Herdr** terminal agent multiplexer, **GitHub CLI**
(`gh`), and **Homebrew**.

Project site: [devbox.foobarto.me](https://devbox.foobarto.me/).

`cd` into a project, type `devbox`, and you're in a throwaway Linux VM with the
project mounted and the tools ready. Exit the shell and the VM is gone; the
project's resumable AI sessions remain in a narrow, owner-only host state
directory so the next clone can continue them.

```sh
cd ~/code/some-project
devbox                       # clone → mount CWD → shell in → delete on exit
```

## Why

- **Disposable.** Each box is deleted on exit by default. Toolchains, package
  installs, credentials, processes, and caches disappear; only the project and
  its deliberately persistent AI session records remain.
- **Isolated.** Real dev work in a VM boundary, not your host. Only the mounted
  folder is visible to the box.
- **Fast.** A one-time *golden* image carries the heavy toolchain; each run is a
  cheap clone, not a re-provision.
- **Deterministic.** A folder always maps to the same box name, so `--keep`
  boxes are easy to find and re-enter; different folders get different boxes.
- **Credential-safe.** Secrets can stay on the host behind a proxy; the box need
  never hold them (see [Auth](#auth)).

## Requirements

- [Lima](https://lima-vm.io) ≥ 2.0 (`limactl`) with a QEMU or VZ backend
- `python3` ≥ 3.11 (for the [proxy](proxy/README.md) and `.devbox.toml`; standard library only)
- `waypipe` on the host when using `devbox gui` or `devbox --gui` from a
  Wayland session

## Install

### Homebrew (recommended)

```sh
brew install foobarto/tap/devbox
```

Installs `devbox` and `devbox-ai-proxy` on your `PATH`. The current stable
GitHub release is
[`v2.0.0`](https://github.com/foobarto/devbox/releases/tag/v2.0.0); source
archives are available from that release. Config lives under `~/.config/devbox/`
(or `$XDG_CONFIG_HOME/devbox`).

Upgrade with `brew upgrade foobarto/tap/devbox`. For a development checkout of
the latest `main`, use `brew install --HEAD foobarto/tap/devbox` and upgrade it
with `brew upgrade --fetch-HEAD foobarto/tap/devbox`.

Check the installed version with `devbox --version` or
`devbox-ai-proxy --version`.

### From source

```sh
git clone https://github.com/foobarto/devbox.git "${XDG_DATA_HOME:-$HOME/.local/share}/devbox"
ln -s "${XDG_DATA_HOME:-$HOME/.local/share}/devbox/bin/devbox" ~/.local/bin/devbox
```

## Usage

```
devbox [DIR] [FLAGS]                         spin up / attach a box for DIR (default: $PWD)
devbox gui [DIR] [FLAGS] [-- APP [ARGS...]]  open a GUI-ready shell or run a guest Wayland app
devbox --gui|-G [DIR] [FLAGS] [-- APP ...]   same GUI behavior through the main command
devbox build [--image N] [--force]   build/refresh the golden image
devbox ls                            list devbox instances
devbox destroy NAME | --all | --goldens
devbox sessions [path|clear --yes] [DIR]
devbox policy [list|show NAME]       list grant policies or show what one grants
devbox proxy [start|stop|status|refresh|audit]
devbox --version
```

### Run flags

| flag | effect |
|---|---|
| `--policy NAME`, `-P NAME` | grant the box exactly what [grant policy](docs/policies.md) `NAME` contains (`none`, `agent`, `agent-github`, or a host-defined one), instead of the project's `[grants]`. A kept box is brought in line with it. |
| `--image NAME`, `-i NAME` | base image for this box's golden (default `ubuntu-24.04`). See [Images](#images). |
| `--cpus N`, `-j N` | CPUs for this box (default 4). |
| `--memory SIZE`, `-M SIZE` | memory for this box, e.g. `12GiB` (default `6GiB`). |
| `--disk SIZE`, `-D SIZE` | disk ceiling, e.g. `80GiB` (default `100GiB`). Sparse, so it costs only what is written; grow-only. |
| `--keep`, `-k` | don't auto-delete the box on exit. |
| `--ephemeral-sessions`, `-e` | keep AI session records on this box's disposable disk instead of attaching the project's persistent session store. |
| `--ssh-agent`, `-s` | forward the host SSH agent into the box (git/GitHub) and configure signed Git commits. Host **private keys never enter the VM** — only the agent socket and selected public key are used. |
| `--proxy[=URL]`, `-p[=URL]` | point the AI CLIs at a host-side credential proxy that adds the host's AI logins; credentials stay on the host. Default `http://host.lima.internal:4141`. Grants no GitHub access. |
| `--gh-proxy[=URL\|off]`, `-H[=URL\|off]` | let the guest's `gh` act as the host's GitHub login through the same proxy — a separate, GitHub-only grant. A kept box keeps it until `--gh-proxy=off` or `--no-auth`. |
| `--traffic-audit[=connect\|off]`, `-T` | explicitly route normal web tooling through an audited CONNECT proxy and block direct TCP/UDP 80/443. `off` removes it from a kept box. It is separate from `-a`. |
| `--no-auth`, `-n` | explicitly disable Devbox-managed proxy, API-key, and copied-credential auth; removes its proxy/key profiles from an existing box. |
| `--api-keys[=FILE]`, `-K[=FILE]` | inject API keys into the box from an env file (default `~/.config/devbox/api-keys.env`). |
| `--with-creds`, `-c` | copy host AI-tool credential files into the box (OAuth logins for claude/codex without a proxy). Best-effort. |
| `--with-agent-config`, `-g` | copy an allowlisted set of non-secret Claude, Codex, OpenCode, and Stado settings, prompts, rules, and custom agents. Auth, histories, caches, and key directories are excluded; suspected credentials are skipped. |
| `--gui`, `-G` | start a GUI-ready Devbox shell through Waypipe; after the optional `--`, run one guest GUI app instead. |
| `-a` | shortcut for `--with-agent-config --proxy --ssh-agent`, added to the run's grants; it never enables `--gh-proxy`, `--with-creds`, or GUI forwarding. `--policy agent` grants the same set but replaces the project's grants. |
| `--mount PATH[:ro\|:rw]`, `-m PATH[:ro\|:rw]` | mount an extra host path into the box at the same path (default `ro`). Repeatable; applied at box creation. |
| `--copy SRC[:DEST]`, `-C SRC[:DEST]` | copy an extra host file/dir into the box (`DEST` defaults to the basename in `$HOME`). Repeatable; works on new **and** existing boxes. |
| `--name NAME`, `-N NAME` | override the derived instance name. |

The per-grant flags — `--proxy`, `--gh-proxy`, `--ssh-agent`,
`--with-agent-config`, `--api-keys`, `--with-creds`, `--traffic-audit`, and
`--no-auth`, plus the `-a` bundle — are deprecated in favour of
[grant policies](#grant-policies). They still work and add to the run's grants.

### Grant policies

Everything a box may use from the host beyond its project mount is a grant:
the AI proxy, the GitHub proxy, the SSH agent, agent configuration, API keys,
copied credentials, mounts, copies, and audited egress. Declare them once in
the project's `.devbox.toml`, or pick a named policy:

```toml
policy = "agent"           # optional base: none, agent, agent-github, or ~/.config/devbox/policies/NAME.toml

[grants]
egress = "audit"
mounts = ["./fixtures:ro"]
```

```sh
devbox --policy none .     # this run gets nothing from the host, whatever the project asks
devbox policy show agent   # what a policy grants
```

The grants for a run come from `--policy`, else the project's manifest (built on
its own `policy` or the machine default), else a machine default
`policy = "NAME"` in `~/.config/devbox/config.toml`. A project cannot lift a
machine default's audited egress. While a policy is in effect, a kept box loses
any grant it no longer contains. See
[grant policies](docs/policies.md) for every grant and how it maps to the old
flags.

> **Agent boundaries:** a Devbox agent cannot read host files or credentials by
> default. The `ssh_agent` grant lets it use loaded SSH identities without
> extracting their private keys; `ai_proxy` and `github` primarily prevent
> credential exfiltration by keeping tokens on the host, while still letting it
> make permitted provider requests. Give these grants only to trusted code. See [agent capability
> security](docs/agent-capabilities-security.md).

### GUI apps on a Wayland host

`devbox gui` and `devbox --gui` start a GUI-ready Devbox shell whose Wayland
applications display in the host session through
[Waypipe](https://gitlab.freedesktop.org/mstoeckl/waypipe/) over Lima's
per-instance SSH connection. It does not mount the host Wayland socket into the
guest. Put an application after `--` when you want Devbox to run just that app.

```sh
devbox --gui .                         # launch GUI apps from the Devbox shell
devbox -G .                            # short form; -g remains --with-agent-config
devbox gui . -- weston-terminal        # run one app and return when it exits
devbox --gui . -a -- code .
devbox gui . -- firefox --new-instance
```

The host must be in an active Wayland session and have `waypipe` installed.
New goldens include the guest-side package; an older kept box installs it on its
first GUI launch. GUI apps use Waypipe's `--no-gpu` mode because Devbox does not
pass host DRM/render nodes into QEMU guests. This works with already-existing
Devboxes too: guest-side Waypipe is installed on demand. As with a normal
`devbox` run, the box is removed when the shell or app exits unless `--keep` is
supplied.

> **Security:** GUI forwarding gives guest applications access to the host
> Wayland session. Devbox uses Waypipe over SSH and does not mount the host
> Wayland socket or GPU nodes, but it is **not** an isolation boundary. Use
> `--gui` and `-G` only with projects and GUI applications you trust.
> See [GUI forwarding security](docs/gui-security.md) for the threat model and
> safe-use guidance.

Use `--policy agent` (or `policy = "agent"` in the manifest) for the usual
agent-config + AI-proxy + SSH-agent setup. GUI forwarding is not a grant: add
`--gui` or `-G` explicitly when you want it, e.g.
`devbox --gui --policy agent -m ~/data:ro -C ~/.netrc`. Build accepts `-i` and `-f` for
`--image` and `--force`; destroy accepts `-A` and `-G` for `--all` and
`--goldens`. Help and version are `-h` and `-V`.

## How it works

1. **`devbox build`** creates a persistent golden Lima instance
   (`devbox-golden-<image>`) from a base image, provisions the toolchain
   (Homebrew + the AI and GitHub CLIs + build basics), verifies it, and stops it.
   One golden per base image.
2. **`devbox [DIR]`** derives a deterministic instance name from `(image, DIR)`,
   then:
   - if that box exists, **attaches** to it;
   - else **clones** the golden (`limactl clone`, fast — a copy of the
     already-provisioned disk, no re-install), mounts `DIR` writable at the same
     path, and boots.
   - applies `DIR/.devbox.toml` if present (per-project setup — see
     [`examples/.devbox.toml`](examples/.devbox.toml)),
   - mounts the project's owner-only AI session state and links each agent's
     native transcript/index paths to it,
   - drops you into a shell in `DIR`,
   - on exit, **deletes** the clone — unless that invocation uses `--keep`.

Because the name is deterministic, re-running `devbox` in the same folder finds
the same box. That's what makes "one box per folder" and re-entering `--keep`
boxes work.

### Startup time

The first `devbox` run for an image takes longer because it must download the
base image and build, provision, and verify the golden image before it can make
the first clone. This is a one-time cost per golden; run `devbox build` ahead of
time when you do not want the first interactive launch to wait. Normal later
runs clone the completed golden and should be much faster.

Keep that fast path intact:

- Put slow, deterministic system setup in `[image].provision` and slow
  user-level setup in `[image].provision_user`. Those actions run while building
  the golden, not every time a box starts.
- Keep `start` small, idempotent, and safe to run on every entry. Avoid
  unconditional package upgrades, dependency downloads, source builds,
  database migrations, or other network-heavy work there.
- `packages` is convenient and skips packages already present in a kept box,
  but a new disposable clone still has to install packages that are absent from
  its golden. Bake large or slow package sets into the golden instead.
- Use `--keep` when retaining guest-only compiler caches, package stores, or
  services matters more than getting a fresh disposable clone. Do not use
  `devbox build --force` unless you actually need to replace a golden.
- On filesystems without reflink support, cloning copies more disk data. Keep
  goldens lean and avoid baking disposable caches or build outputs into them.

## AI session continuity

Resumable session state is persistent by default even when the VM is not.
Devbox gives each canonical project path a separate directory under
`${XDG_STATE_HOME:-~/.local/state}/devbox/sessions/`, mounts only that directory
read-write, and uses it for Claude Code, Codex (including the isolated
`--proxy` profile), OpenCode, Pi, and Stado session records. Existing kept
boxes gain the mount on their next entry and restart once if necessary.
The directory name is derived only from the canonical project path, not from
the selected image, golden, or disposable box, so rebuilding or replacing a
golden reattaches the same project's existing sessions.
Devbox refuses to attach the same store to two differently named boxes at once,
which avoids concurrent writers corrupting an agent's session database; destroy
the retained owner first or make the second box ephemeral.

Authentication remains separate: Claude/Codex/OpenCode auth files, provider
keys, and unrelated sessions already present on the host are not placed in the
session store. Session transcripts can still contain prompts, source snippets,
paths, and tool output, so treat the directory as sensitive state. It is mode
`0700` and is also a deliberate cross-lifecycle trust channel: instructions in
an old transcript are available again when you resume it.

Use each tool's native resume command after entering the same project. For
example, Claude Code supports `claude --continue` / `claude --resume`, and
Codex supports `codex resume --last` or its session picker. Inspect or remove
the exact project store from the host with:

```sh
devbox sessions path .
devbox sessions clear .          # confirms interactively; destroy a retained box first
devbox sessions clear --yes .    # explicit non-interactive removal
```

`devbox destroy` intentionally leaves sessions intact. Use
`--ephemeral-sessions` (`-e`) when a run should leave no resumable agent state;
on a kept box that already has the host mount, the flag unlinks the native
agent stores and restarts the box once to remove that mount completely.
Override the host root with `DEVBOX_SESSION_DIR` when needed.

## Images

`--image` accepts several forms:

```sh
devbox --image ubuntu-24.04                     # a Lima template name (default)
devbox --image debian-12
devbox --image fedora                           # dnf-based; base packages adapt
devbox --image archlinux                        # pacman-based
devbox --image template://ubuntu-25.04
devbox --image ~/vms/kali.yaml                  # a Lima config file
devbox --image ~/.local/share/lima-images/kali-2026.2-genericcloud-amd64.qcow2
```

Each distinct image gets its own golden. Base-package provisioning auto-detects
`apt` / `dnf` / `pacman`; Homebrew and the AI CLIs are distro-agnostic.

> **Kali:** Lima ships no Kali template, so pass a Kali cloud `.qcow2` (or a
> `.yaml` referencing one) via `--image`.

## Auth

Installed ≠ authenticated. These combinable [grants](docs/policies.md) — or
their deprecated flags — cover the usual setups:

| you want | grant (flag) | where secrets live |
|---|---|---|
| keys/tokens never enter the box | [`ai_proxy`](proxy/README.md) (`--proxy`) for AI, [`github`](proxy/README.md#github-cli) (`--gh-proxy`) for `gh` | host only |
| explicitly opt out of Devbox auth | `--policy none` (`--no-auth`) | no new credentials injected |
| API keys (opencode, stado, OpenAI/Codex platform keys) | `api_keys` (`--api-keys`) | copied into the box |
| Claude/Codex **subscription OAuth** without a proxy | `host_credentials` (`--with-creds`) | copied into the box |
| AI CLI settings, prompts, rules, and custom agents without auth | `agent_config` (`--with-agent-config`) | allowlisted non-secret files copied into the box |
| nothing | *(default)* | you log in interactively inside the box |

The proxy supports API keys plus Claude, Codex, and GitHub CLI logins. A host CLI login
works with `--proxy` out of the box; its access token is read fresh and never
enters the box. See
[`proxy/README.md`](proxy/README.md) for the full explanation. `--proxy` is the
recommended default for disposable boxes, and it auto-starts the host proxy
(once, shared across boxes) — no separate launch step. Manage it with
`devbox proxy [start|stop|status|refresh]`. `refresh` updates every registered,
running box directly and never reads a project's `.devbox.toml`.

Every authenticated proxy request is also written to a host-owned, owner-only
audit log. It captures AI prompts/queries and GitHub API request payloads (with
known credential fields redacted), then records the outcome and classifies
GitHub writes such as create, modify, delete, and GraphQL mutations. Inspect it
with `devbox proxy audit show`, or create a private self-contained report with
`devbox proxy audit export [FILE]`. These logs can contain source snippets and
prompt content; see [proxy audit logging](docs/proxy-audit.md) before enabling
`--proxy` for sensitive work.

### Agent first-run prompts

Every run pre-answers the first-run gates the AI CLIs would otherwise show:
Claude Code's onboarding, folder-trust, and custom-API-key dialogs, and Codex's
folder-trust and sign-in prompts. Deciding to start a Devbox for a folder is
already the decision to run an agent in it, and the VM is the boundary — so the
box comes up ready to work instead of asking the same question again.

Trust is seeded for the mounted project directory only: never `$HOME`, and never
the read-only paths added with `--mount`. An answer already on record is left
alone, and a real Codex `auth.json` copied in with `--with-creds` is never
overwritten. This also means a repository's own `.claude/settings.json` and
hooks run unprompted — see
[agent capability security](docs/agent-capabilities-security.md).

### Opt-in web egress audit

Grant `egress = "audit"` (or use the deprecated `--traffic-audit`) when you want
ordinary guest web tools to be auditable too, rather than only the built-in AI
and GitHub authentication routes:

```toml
[grants]
egress = "audit"                       # devbox --traffic-audit; renewed on each entry
```

On a kept box, a policy without it — or `--traffic-audit=off` — removes the
profile and the guest firewall rule.

It sets standard `HTTP(S)_PROXY`/`ALL_PROXY` variables with a short-lived
Devbox capability, then rejects direct TCP and UDP traffic to ports 80 and 443
inside the guest. `NO_PROXY` exempts only guest loopback and the Devbox proxy
host, so AI clients still reach the credential proxy directly. Proxy-aware HTTPS
traffic therefore uses CONNECT; its audit
record contains destination, timing, and byte counts, but not encrypted paths
or request bodies. Plain HTTP proxy requests can be recorded in detail because
they are not encrypted. Tools that ignore proxy variables, use certificate
pinning, or use non-web ports can fail or fall outside this coverage. The
generic proxy accepts only public destinations, so it cannot be used to reach
host loopback or private-network web services.

It is not part of the `agent` policy or `-a`. It is an egress
guard for normal guest applications, not a containment boundary against a
process that has guest root/sudo and can remove the guest firewall. See
[proxy audit logging](docs/proxy-audit.md) and [agent capability
security](docs/agent-capabilities-security.md) before granting it to untrusted
code.

`--proxy` and `--gh-proxy` are separate grants: proxying AI requests never lets
the box act as your GitHub account. For `gh`, log in once on the host with
`gh auth login`; `devbox --gh-proxy` gives
the guest CLI a dummy routing marker plus a short-lived Devbox proxy capability,
then injects the host token only inside a GitHub-only TLS proxy. The capability
is not a GitHub token, expires after eight hours, and is renewed every seven
hours by the long-lived host proxy daemon, independently of any `devbox` shell
or project manifest. It checks recorded box names once a minute, so a host
suspend or long idle is repaired promptly after resume without restarting the
guest. `devbox proxy refresh` forces the same update immediately.

To prevent an agent from accidentally bypassing the wrapper with Homebrew's
absolute path, `--gh-proxy` copies the real `gh` binary into the managed private
wrapper directory and replaces Homebrew's public `bin/gh` link with the wrapper;
`--gh-proxy=off` and `--no-auth` restore the normal Homebrew link. This is command-routing hygiene,
not containment against hostile same-user guest code, which can still locate
and execute files it is permitted to access.
GitHub Enterprise hosts are not proxied. Git/GitHub SSH auth is separate: use **`--ssh-agent`**. It also enables automatic
SSH-format Git commit signatures through the forwarded agent. Devbox copies the
first public key exposed by `ssh-add -L` and the host Git name/email, then sets
Git's signing defaults inside the VM; the private key remains in the host
agent. Override the guest Git settings normally if you prefer another signing
method. Newly built golden images fetch GitHub's published SSH host keys from
the GitHub Meta API and place them in `~/.ssh/known_hosts`, so GitHub SSH use
does not stop for a first-connection prompt.

While a policy is in effect, entering a kept box removes the proxy, API-key, and
audited-egress state the policy lacks, so `devbox --policy none` is the clean
opt-out for those; SSH-agent forwarding, copied files, and mounts stay until the
box is recreated. The deprecated
`--no-auth` likewise removes Devbox's AI/GitHub proxy and API-key profiles
before the shell opens, without changing other grants. It does not delete credentials created manually
inside the VM, and cannot be combined with `--proxy`, `--gh-proxy`, `--api-keys`,
or `--with-creds`. It can be
combined with `--with-agent-config`, which never intentionally copies auth.

## Per-project setup

Use a `.devbox.toml` manifest in the project root to select an image, size the
box, bake a toolchain into its golden, install Homebrew packages, and run a
startup command. An explicit CLI flag always wins over the manifest.

```toml
start = "test -d node_modules || npm ci"

[image]
location = "ubuntu-24.04"
provision = '''
apt-get install -y --no-install-recommends postgresql-client
'''
provision_user = '''
brew install node python@3.12
'''

[resources]
cpus = 8
memory = "12GiB"
disk = "120GiB"
```

`image = "ubuntu-24.04"` remains valid shorthand when you only need to pick a
base image. **In TOML, every key after a `[table]` header belongs to that
table** — so keep top-level keys above `[image]` and `[resources]`.

`[image].provision` and `.provision_user` are baked into the **golden** at build
time (root and user mode respectively), not re-run per box — that's where a
heavy distro toolchain belongs, so each new box is a cheap clone rather than a
re-install. Custom provisioning is part of the golden's identity, so one project
can never silently redefine the golden another project clones from; editing it
builds a new golden, and `devbox destroy --goldens` cleans up the old one.

`[resources].disk` is a **ceiling, not an allocation** — Lima's qcow2 is sparse,
so a 120GiB box that has written 4GiB occupies 4GiB on the host. It is grow-only;
a request smaller than the golden's is refused with a warning rather than
silently applied. `cpus` and `memory` are applied per-box at clone time, so
changing them never requires rebuilding the golden.

The manifest can also declare `keep`, a grant `policy`, and a `[grants]` table
(see [grant policies](#grant-policies)); the older top-level grant keys still
work but are deprecated. Because a project manifest is repository-controlled
input, Devbox groups every declaration
by type, gives each category a distinct icon, and prints multiline
provisioning and startup scripts as readable blocks. Relative host paths in
local images and in the manifest's `[grants]` resolve from the manifest's
directory, so their meaning does not change with the shell's working directory.

On the first use of a manifest, Devbox offers an optional AI summary and safety
check. Codex is the default; the picker also supports Claude, Agy, Copilot,
Cursor, OpenCode, and Pi, or the user can skip the AI review. The evaluator
receives the manifest inline as untrusted data, runs non-interactively from an
isolated empty working directory, and is told not to execute or follow anything
in it. Devbox selects each CLI's native plan/read-only or no-tool controls;
Codex additionally uses an ephemeral session with local configuration and
exec-policy rules ignored. Selecting a reviewer sends the manifest contents to
the service configured for that CLI; the selected host CLI must already be
installed and authenticated. The AI review is advisory: Devbox still requires
an explicit `y` before it uses the manifest.

After approval, Devbox stores only the manifest path, SHA-256 fingerprints of
its exact contents and normalized meaning (including effective defaults and
resolved host paths), the selected reviewer, review outcome, and approval time under
`${XDG_STATE_HOME:-~/.local/state}/devbox/manifest-approvals/`. Files are mode
`0600` in a mode-`0700` directory; nothing is written to the project. The
warning and prompts are skipped on later runs and return after any content or
resolved-path change. Older content-only approval records are ignored, causing
a one-time reapproval. Command-line flags remain explicit user choices and are
not included in that confirmation. See the complete annotated template:
[`examples/.devbox.toml`](examples/.devbox.toml).

The old executable `.devbox` hook is no longer run; Devbox emits a migration
warning when it finds one.

## Config

Configuration and generated golden metadata live under `~/.config/devbox/`
(override with `$DEVBOX_CONFIG_DIR`):

```
~/.config/devbox/
├── config.toml                  # machine-wide [resources] and default grant policy
├── policies/NAME.toml           # host-defined grant policies (see docs/policies.md)
├── devbox-golden-<image>.yaml   # generated golden configs
├── api-keys.env                 # for --api-keys / the proxy   (gitignored)
├── proxy.config.json            # proxy routes                 (gitignored)
└── proxy-env                    # optional AI-proxy env template (__PROXY_URL__, __PROXY_TOKEN__)
```

`config.toml` sets the defaults for every project on this machine — top-level
keys such as the default grant policy before any table:

```toml
policy = "agent"                 # machine-default grant policy (docs/policies.md)

[resources]
cpus = 8
memory = "12GiB"
disk = "150GiB"
```

Resource precedence is **CLI flags > `.devbox.toml` > `config.toml` > built-in
defaults** (4 CPUs, 6GiB, 100GiB).

Persistent AI transcripts are state rather than configuration, so they live
separately under `${XDG_STATE_HOME:-~/.local/state}/devbox/sessions/` (override
with `$DEVBOX_SESSION_DIR`). `devbox sessions path DIR` resolves the exact
per-project directory. Saved `.devbox.toml` approvals live beside that session
root under `devbox/manifest-approvals/`; deleting the matching JSON record makes
Devbox ask again on the next run.

## Tests

`make test` runs the bats suite for `bin/devbox` and the Python tests for the
proxy and the site. They start no VM: Lima is exercised through stubs or its
template resolver, and the tests that need `limactl` or PyYAML skip when either
is absent.

```sh
brew install bats-core     # once
make hooks                 # once per checkout; enables credential guard
make test
make lint                  # shellcheck, when installed
```

`make e2e` is the destructive integration suite: it creates real Lima boxes,
calls the host's Claude and Codex logins through the proxy, and copies
credentials into a disposable VM. Run it deliberately; see `test/e2e.sh`.

## Notes & limits

- `limactl clone` copies the golden disk. On a reflink-capable filesystem
  (btrfs/xfs) that's near-instant; elsewhere it's a full copy (still far cheaper
  than re-provisioning).
- Golden images configure `systemd-resolved` to use Lima's virtual host
  resolver. This keeps DNS working on cloud images such as Kali that accept a
  DHCP route but omit its DNS option, and it preserves host VPN/split-DNS
  resolution rather than substituting public resolvers.
- New goldens include Stado's Linux sandbox helpers: `bwrap` for process and
  filesystem isolation, plus `pasta` for proxy-only host-allowlist networking.
  On Ubuntu 24.04, Devbox enables AppArmor's dedicated, restricted bwrap
  profile; it does not disable Ubuntu's global user-namespace restriction, so
  standalone `unshare` remains intentionally unavailable.
- A box created before a `devbox build --force` keeps the *old* toolchain until
  you `destroy` and recreate it.
- `--ssh-agent` enables Lima's agent socket for a new or existing box. An
  existing box is restarted once if needed, so run `devbox --ssh-agent` from
  the project directory to enable it. Your host agent must already be running
  and have a valid `SSH_AUTH_SOCK`.
