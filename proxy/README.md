# devbox credential proxy

A tiny host-side reverse proxy that lets disposable devboxes use AI and GitHub CLIs
**without ever holding a real credential**. Real keys/tokens stay on the host;
the proxy injects them and forwards to the provider.

- `devbox-ai-proxy.py` — the proxy. Python **standard library only**, no pip.
  Streams HTTP responses (SSE-safe), tunnels Codex WebSockets, and provides a
  GitHub-only TLS CONNECT proxy for `gh`.
- `gh-wrapper.py` — guest-side `gh` launcher that points only GitHub CLI traffic
  at that CONNECT proxy.
- `proxy.config.example.json` — route table (which path → which upstream →
  which auth source).
- `api-keys.env.example` — host-side API keys.
- `run.sh` — launcher.

## Why a proxy at all

The alternatives put secrets *inside* the throwaway VM:

| strategy | flag | secret location |
|---|---|---|
| **proxy** | `devbox --proxy` | host only — VM sees a dummy token |
| API keys in VM | `devbox --api-keys` | copied into the VM |
| OAuth creds in VM | `devbox --with-creds` | copied into the VM |

For a *disposable* box, keeping secrets on the host is the safer default: a
leaky or compromised box can't exfiltrate what it never had.

## Authentication (works out of the box)

For Claude, Codex, and GitHub CLI, `devbox --proxy` needs no proxy configuration
file when the corresponding host CLI is already logged in. Each default route
chooses, in order:

| provider | API-key preference | OAuth credential |
|---|---|---|
| Claude | `ANTHROPIC_API_KEY` | `~/.claude/.credentials.json` |
| Codex | `OPENAI_API_KEY` | `~/.codex/auth.json` |
| GitHub CLI (`gh`) | `GH_TOKEN` / `GITHUB_TOKEN` | host `gh auth login` |

The proxy reads access tokens fresh on every request. Its background check runs
every minute, refreshes Claude and Codex OAuth sessions shortly before expiry,
and retries a request once after a 401 or 403. It uses OAuth refresh grants
rather than sending empty model prompts, so it does not consume model usage
just to keep a session alive.
The VM never receives an access or refresh token; the repository also has a
pre-commit guard against embedding one in production scripts.

For Codex subscriptions, `devbox --proxy` gives the guest an isolated,
non-secret Codex profile that points its ChatGPT backend and WebSocket traffic
to the host proxy. The guest only receives the literal routing marker
`devbox-proxy`; the host replaces it with the refreshed OAuth header.

For OpenAI/Codex platform keys and the other API-key providers, configure
`api-keys.env` as before. An explicit `proxy.config.json` still takes full
control of every AI route and auth source.

## GitHub CLI

`gh` has no public-API base-URL setting, so the guest runs the normal `gh`
binary through a GitHub-only HTTPS CONNECT proxy. On the first use, Devbox
creates a local CA under `~/.config/devbox/`, copies only its public certificate
into the guest, and injects the host token after TLS termination for
`api.github.com` and `uploads.github.com`. The guest holds only the literal
`devbox-proxy` routing marker plus a short-lived Devbox proxy capability, never
the real GitHub token. The capability authenticates only the local proxy and
expires after eight hours. While the host-side `devbox --proxy` session remains
open, Devbox renews that capability every seven hours and atomically updates the
guest wrapper state. Devbox remembers only the bare proxy endpoint on the host,
so re-entering a kept box renews its capability even when `--proxy` is omitted.
GitHub-owned download hosts are tunnelled without TLS interception.

Log in on the host first:

```sh
gh auth login
devbox --proxy
```

The guest wrapper refuses `gh auth login`, `logout`, and token-changing auth
commands so a disposable box cannot alter the host account. `gh auth status`
is safe and reports the dummy environment-token login. This automatic path is
for GitHub.com; GitHub Enterprise hosts remain direct guest configuration.

### Repairing an existing box

For a kept box where `gh` is installed but reports that it needs `gh auth
login`, refresh the Devbox-managed proxy setup without deleting the box:

```sh
cd /path/to/project
devbox --keep --proxy
```

The command refreshes the guest wrapper and proxy profile, then opens the box.
Use `gh api /rate_limit --jq .rate.remaining` there as a credential-safe smoke
check. Do not run `gh auth login` in the guest; log in on the host instead.
For a session that was closed or suspended past the capability lifetime, the
same command issues a fresh capability before opening the guest. Subsequent
bare re-entry to that kept box does the same, using the host-owned remembered
endpoint; use `--no-auth` to remove the proxy configuration and remembered
endpoint.

If the box says `gh` is missing, it predates the golden-image installation.
First check that its project work is committed or otherwise safe, then rebuild
the golden and recreate only that box:

```sh
devbox build --force
devbox ls                         # identify the kept box name
devbox destroy <box-name>
devbox --keep --proxy
```

## Quick start

To use static API keys or custom routes, configure them once:

```sh
mkdir -p ~/.config/devbox
cp proxy/api-keys.env.example       ~/.config/devbox/api-keys.env      # fill in
cp proxy/proxy.config.example.json  ~/.config/devbox/proxy.config.json # optional route overrides
```

Then just use `--proxy` — **devbox auto-starts the host proxy** (once, shared
across boxes) if it isn't already running:

```sh
devbox --proxy          # starts the proxy on the host, wires the box's env to it
```

Manage the shared proxy directly if you want:

```sh
devbox proxy status     # RUNNING / not running / port held by another service
devbox proxy start      # start it without a box
devbox proxy stop       # stop it
```

The guest reaches the host at `host.lima.internal`, so the default proxy URL is
`http://host.lima.internal:4141` (a devbox-specific port chosen to avoid common
collisions — `4000` is often taken). If the port is already held by a
non-devbox service, devbox refuses to start rather than clobber it; set
`DEVBOX_PROXY_URL` to a free port. Because the guest reaches the host over
Lima's user-network gateway, the proxy binds `0.0.0.0` by default — restrict
with a firewall if you want it tighter, or set `"listen"` to a specific
interface. Logs go to `~/.config/devbox/proxy.log`.

## Heavier off-the-shelf alternatives

If you outgrow this, swap `run.sh` for a full gateway and keep `devbox --proxy`
pointed at it:

- **LiteLLM Proxy** — mature, multi-provider, virtual keys, Anthropic + OpenAI
  compatible endpoints. Great for the API-key case.
- **mitmproxy** with a small addon — good when you need per-request scripting
  (e.g. dynamic OAuth token injection) with a batteries-included TLS stack.

Both are Python, `pip`/`pipx`-installable — no Node.
