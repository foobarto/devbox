# devbox

Disposable, CWD-mounted dev VMs on [Lima](https://lima-vm.io)/QEMU, preloaded
with an AI-CLI toolchain — **claude**, **codex**, **opencode**, **pi**, and
**stado** — plus the **Herdr** terminal agent multiplexer, **GitHub CLI**
(`gh`), and **Homebrew**.

Project site: [devbox.foobarto.me](https://devbox.foobarto.me/).

`cd` into a project, type `devbox`, and you're in a throwaway Linux VM with the
project mounted and the tools ready. Exit the shell and the VM is gone.

```sh
cd ~/code/some-project
devbox                       # clone → mount CWD → shell in → delete on exit
```

## Why

- **Disposable.** Each box is deleted on exit by default. Nothing to clean up,
  nothing accretes.
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
[`v1.0.6`](https://github.com/foobarto/devbox/releases/tag/v1.0.6); source
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
```

### Run flags

| flag | effect |
|---|---|
| `--image NAME`, `-i NAME` | base image for this box's golden (default `ubuntu-24.04`). See [Images](#images). |
| `--cpus N`, `-j N` | CPUs for this box (default 4). |
| `--memory SIZE`, `-M SIZE` | memory for this box, e.g. `12GiB` (default `6GiB`). |
| `--disk SIZE`, `-D SIZE` | disk ceiling, e.g. `80GiB` (default `100GiB`). Sparse, so it costs only what is written; grow-only. |
| `--keep`, `-k` | don't auto-delete the box on exit. |
| `--ssh-agent`, `-s` | forward the host SSH agent into the box (git/GitHub) and configure signed Git commits. Host **private keys never enter the VM** — only the agent socket and selected public key are used. |
| `--proxy[=URL]`, `-p[=URL]` | point the AI CLIs and `gh` at a host-side credential proxy; credentials stay on the host. Default `http://host.lima.internal:4141`. |
| `--traffic-audit[=connect\|off]`, `-T` | explicitly route normal web tooling through an audited CONNECT proxy and block direct TCP/UDP 80/443. `off` removes it from a kept box. It is separate from `-a`. |
| `--no-auth`, `-n` | explicitly disable Devbox-managed proxy, API-key, and copied-credential auth; removes its proxy/key profiles from an existing box. |
| `--api-keys[=FILE]`, `-K[=FILE]` | inject API keys into the box from an env file (default `~/.config/devbox/api-keys.env`). |
| `--with-creds`, `-c` | copy host AI-tool credential files into the box (OAuth logins for claude/codex without a proxy). Best-effort. |
| `--with-agent-config`, `-g` | copy an allowlisted set of non-secret Claude, Codex, OpenCode, and Stado settings, prompts, rules, and custom agents. Auth, histories, caches, and key directories are excluded; suspected credentials are skipped. |
| `--gui`, `-G` | start a GUI-ready Devbox shell through Waypipe; after the optional `--`, run one guest GUI app instead. |
| `-a` | shortcut for `--with-agent-config --proxy --ssh-agent`; it never enables `--with-creds` or GUI forwarding. |
| `--mount PATH[:ro\|:rw]`, `-m PATH[:ro\|:rw]` | mount an extra host path into the box at the same path (default `ro`). Repeatable; applied at box creation. |
| `--copy SRC[:DEST]`, `-C SRC[:DEST]` | copy an extra host file/dir into the box (`DEST` defaults to the basename in `$HOME`). Repeatable; works on new **and** existing boxes. |
| `--name NAME`, `-N NAME` | override the derived instance name. |

> **Agent boundaries:** a Devbox agent cannot read host files or credentials by
> default. `--ssh-agent` lets it use loaded SSH identities without extracting
> their private keys; `--proxy` primarily prevents credential exfiltration by
> keeping tokens on the host, while still letting it make permitted provider
> requests. Give either capability only to trusted code. See [agent capability
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

Use `-a` for the usual agent-config + proxy + SSH-agent setup. Add `--gui` or
`-G` explicitly when you also want GUI forwarding, e.g.
`devbox --gui -a -m ~/data:ro -C ~/.netrc`. Build accepts `-i` and `-f` for
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
   - drops you into a shell in `DIR`,
   - on exit, **deletes** the clone — unless that invocation uses `--keep`.

Because the name is deterministic, re-running `devbox` in the same folder finds
the same box. That's what makes "one box per folder" and re-entering `--keep`
boxes work.

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

Installed ≠ authenticated. Three combinable strategies, pick per your setup:

| you want | use | where secrets live |
|---|---|---|
| keys/tokens never enter the box | [`--proxy`](proxy/README.md) | host only |
| explicitly opt out of Devbox auth | `--no-auth` | no new credentials injected |
| API keys (opencode, stado, OpenAI/Codex platform keys) | `--api-keys` | copied into the box |
| Claude/Codex **subscription OAuth** without a proxy | `--with-creds` | copied into the box |
| AI CLI settings, prompts, rules, and custom agents without auth | `--with-agent-config` | allowlisted non-secret files copied into the box |
| nothing | *(default)* | you log in interactively inside the box |

The proxy supports API keys plus Claude, Codex, and GitHub CLI logins. A host CLI login
works with `--proxy` out of the box; its access token is read fresh and never
enters the box. See
[`proxy/README.md`](proxy/README.md) for the full explanation. `--proxy` is the
recommended default for disposable boxes, and it auto-starts the host proxy
(once, shared across boxes) — no separate launch step. Manage it with
`devbox proxy [start|stop|status]`.

Every authenticated proxy request is also written to a host-owned, owner-only
audit log. It captures AI prompts/queries and GitHub API request payloads (with
known credential fields redacted), then records the outcome and classifies
GitHub writes such as create, modify, delete, and GraphQL mutations. Inspect it
with `devbox proxy audit show`, or create a private self-contained report with
`devbox proxy audit export [FILE]`. These logs can contain source snippets and
prompt content; see [proxy audit logging](docs/proxy-audit.md) before enabling
`--proxy` for sensitive work.

### Opt-in web egress audit

Use `--traffic-audit` when you want ordinary guest web tools to be auditable
too, rather than only the built-in AI and GitHub authentication routes:

```sh
devbox --traffic-audit                 # equivalent to --traffic-audit=connect
devbox --keep --traffic-audit          # renew a kept box's short-lived capability
devbox --keep --traffic-audit=off      # remove its profile and guest firewall rule
```

It sets standard `HTTP(S)_PROXY`/`ALL_PROXY` variables with a short-lived
Devbox capability, then rejects direct TCP and UDP traffic to ports 80 and 443
inside the guest. Proxy-aware HTTPS traffic therefore uses CONNECT; its audit
record contains destination, timing, and byte counts, but not encrypted paths
or request bodies. Plain HTTP proxy requests can be recorded in detail because
they are not encrypted. Tools that ignore proxy variables, use certificate
pinning, or use non-web ports can fail or fall outside this coverage. The
generic proxy accepts only public destinations, so it cannot be used to reach
host loopback or private-network web services.

This is intentionally explicit and is not included in `-a`. It is an egress
guard for normal guest applications, not a containment boundary against a
process that has guest root/sudo and can remove the guest firewall. See
[proxy audit logging](docs/proxy-audit.md) and [agent capability
security](docs/agent-capabilities-security.md) before granting it to untrusted
code.

For `gh`, log in once on the host with `gh auth login`; `devbox --proxy` gives
the guest CLI a dummy routing marker plus a short-lived Devbox proxy capability,
then injects the host token only inside a GitHub-only TLS proxy. The capability
is not a GitHub token, expires after eight hours, and is renewed every seven
hours while the `devbox --proxy` session is active. The bare proxy endpoint is
remembered on the host so re-entering a kept box renews its capability too.
GitHub Enterprise hosts are not proxied. Git/GitHub SSH auth is separate: use **`--ssh-agent`**. It also enables automatic
SSH-format Git commit signatures through the forwarded agent. Devbox copies the
first public key exposed by `ssh-add -L` and the host Git name/email, then sets
Git's signing defaults inside the VM; the private key remains in the host
agent. Override the guest Git settings normally if you prefer another signing
method. Newly built golden images fetch GitHub's published SSH host keys from
the GitHub Meta API and place them in `~/.ssh/known_hosts`, so GitHub SSH use
does not stop for a first-connection prompt.

`--no-auth` is the explicit opt-out for a kept box that was previously started
with `--proxy` or `--api-keys`; it removes Devbox's profile snippets before the
shell opens. It does not delete credentials created manually inside the VM, and
cannot be combined with `--proxy`, `--api-keys`, or `--with-creds`. It can be
combined with `--with-agent-config`, which never intentionally copies auth.

## Per-project setup

Use a `.devbox.toml` manifest in the project root to select an image, size the
box, bake a toolchain into its golden, install Homebrew packages, and run a
startup command. An explicit CLI flag always wins over the manifest.

```toml
packages = ["node", "python@3.12"]
start = "npm install"

[image]
location = "ubuntu-24.04"
provision = '''
apt-get install -y --no-install-recommends postgresql-client
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

The manifest can also declare `ssh_agent`, `keep`, `proxy`, `api_keys`,
`with_creds`, `with_agent_config`, `mounts`, `copies`, and `no_auth`. Because a project manifest is
repository-controlled input, Devbox prints every requested host-affecting
capability and startup command, then requires an explicit `y` before creating
or attaching to a box. Command-line flags remain explicit user choices and are
not included in that confirmation. See the complete annotated template:
[`examples/.devbox.toml`](examples/.devbox.toml).

The old executable `.devbox` hook is no longer run; Devbox emits a migration
warning when it finds one.

## Config

Everything host-side lives under `~/.config/devbox/` (override with
`$DEVBOX_CONFIG_DIR`):

```
~/.config/devbox/
├── config.toml                  # machine-wide [resources] defaults
├── devbox-golden-<image>.yaml   # generated golden configs
├── api-keys.env                 # for --api-keys / the proxy   (gitignored)
├── proxy.config.json            # proxy routes                 (gitignored)
└── proxy-env                    # optional --proxy env template (uses __PROXY_URL__)
```

`config.toml` sets the defaults for every project on this machine:

```toml
[resources]
cpus = 8
memory = "12GiB"
disk = "150GiB"
```

Resource precedence is **CLI flags > `.devbox.toml` > `config.toml` > built-in
defaults** (4 CPUs, 6GiB, 100GiB).

## Tests

Unit tests cover the pure logic (name derivation, image-stanza + golden-YAML
generation, dispatch) and spin up no VM, so they're fast.

```sh
brew install bats-core     # once
make hooks                 # once per checkout; enables credential guard
make test                  # or: bats test/
```

The one `limactl validate` test skips automatically if `limactl` isn't
installed.

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
