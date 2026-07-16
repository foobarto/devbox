# devbox

Disposable, CWD-mounted dev VMs on [Lima](https://lima-vm.io)/QEMU, preloaded
with an AI-CLI toolchain — **claude**, **codex**, **opencode**, **stado** — plus
**Homebrew**.

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
- `python3` (only if you use the [proxy](proxy/README.md); standard library only)

## Install

### Homebrew (recommended)

```sh
brew install --HEAD foobarto/tap/devbox
```

Installs `devbox` and `devbox-ai-proxy` on your `PATH` and pulls in `lima`. The
source repo is private, so this is a `--HEAD` (git-over-SSH) install. Config
lives under `~/.config/devbox/` (or `$XDG_CONFIG_HOME/devbox`).

Upgrade with `brew upgrade --fetch-HEAD foobarto/tap/devbox`.

### From source

```sh
git clone git@github.com:foobarto/devbox.git "${XDG_DATA_HOME:-$HOME/.local/share}/devbox"
ln -s "${XDG_DATA_HOME:-$HOME/.local/share}/devbox/bin/devbox" ~/.local/bin/devbox
```

## Usage

```
devbox [DIR] [FLAGS]        spin up / attach a box for DIR (default: $PWD)
devbox build [--image N] [--force]   build/refresh the golden image
devbox ls                            list devbox instances
devbox destroy NAME | --all | --goldens
```

### Run flags

| flag | effect |
|---|---|
| `--image NAME` | base image for this box's golden (default `ubuntu-24.04`). See [Images](#images). |
| `--keep` | don't auto-delete the box on exit. |
| `--ssh-agent` | forward the host SSH agent into the box (git/GitHub). Host **private keys never enter the VM** — only the agent socket is forwarded. |
| `--proxy[=URL]` | point the AI CLIs at a host-side proxy; credentials stay on the host. Default `http://host.lima.internal:4141`. |
| `--api-keys[=FILE]` | inject API keys into the box from an env file (default `~/.config/devbox/api-keys.env`). |
| `--with-creds` | copy host AI-tool credential files into the box (OAuth logins for claude/codex without a proxy). Best-effort. |
| `--mount PATH[:ro\|:rw]` | mount an extra host path into the box at the same path (default `ro`). Repeatable; applied at box creation. |
| `--copy SRC[:DEST]` | copy an extra host file/dir into the box (`DEST` defaults to the basename in `$HOME`). Repeatable; works on new **and** existing boxes. |
| `--name NAME` | override the derived instance name. |

Flags combine, e.g. `devbox --ssh-agent --proxy --mount ~/data:ro --copy ~/.netrc`.

## How it works

1. **`devbox build`** creates a persistent golden Lima instance
   (`devbox-golden-<image>`) from a base image, provisions the toolchain
   (Homebrew + the four AI CLIs + build basics), verifies it, and stops it.
   One golden per base image.
2. **`devbox [DIR]`** derives a deterministic instance name from `(image, DIR)`,
   then:
   - if that box exists, **attaches** to it;
   - else **clones** the golden (`limactl clone`, fast — a copy of the
     already-provisioned disk, no re-install), mounts `DIR` writable at the same
     path, and boots.
   - runs `DIR/.devbox` if present (per-project setup — see
     [`examples/.devbox`](examples/.devbox)),
   - drops you into a shell in `DIR`,
   - on exit, **deletes** the clone — unless `--keep`, or the box pre-existed.

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
| API keys (opencode, stado, OpenAI/Codex platform keys) | `--api-keys` | copied into the box |
| Claude/Codex **subscription OAuth** without a proxy | `--with-creds` | copied into the box |
| nothing | *(default)* | you log in interactively inside the box |

The proxy supports **both** API keys and OAuth logins (refreshed on the host,
read fresh per request) — see [`proxy/README.md`](proxy/README.md) for the full
explanation. `--proxy` is the recommended default for disposable boxes, and it
**auto-starts the host proxy** (once, shared across boxes) — no separate launch
step. Manage it with `devbox proxy [start|stop|status]`.

Git/GitHub auth is separate: use **`--ssh-agent`**.

## Per-project setup

If the mounted directory contains a `.devbox` script, it runs inside the box
after boot (as you, in the project dir). Declare project-specific tooling there
on top of the minimal baseline. Template:
[`examples/.devbox`](examples/.devbox).

## Config

Everything host-side lives under `~/.config/devbox/` (override with
`$DEVBOX_CONFIG_DIR`):

```
~/.config/devbox/
├── devbox-golden-<image>.yaml   # generated golden configs
├── api-keys.env                 # for --api-keys / the proxy   (gitignored)
├── proxy.config.json            # proxy routes                 (gitignored)
└── proxy-env                    # optional --proxy env template (uses __PROXY_URL__)
```

## Tests

Unit tests cover the pure logic (name derivation, image-stanza + golden-YAML
generation, dispatch) and spin up no VM, so they're fast.

```sh
brew install bats-core     # once
make test                  # or: bats test/
```

The one `limactl validate` test skips automatically if `limactl` isn't
installed.

## Notes & limits

- `limactl clone` copies the golden disk. On a reflink-capable filesystem
  (btrfs/xfs) that's near-instant; elsewhere it's a full copy (still far cheaper
  than re-provisioning).
- A box created before a `devbox build --force` keeps the *old* toolchain until
  you `destroy` and recreate it.
- `--ssh-agent` applies at box creation; to toggle it on an existing box,
  destroy and recreate.
