# devbox AI proxy

A tiny host-side reverse proxy that lets disposable devboxes use AI CLIs
**without ever holding a real credential**. Real keys/tokens stay on the host;
the proxy injects them and forwards to the provider.

- `devbox-ai-proxy.py` — the proxy. Python **standard library only**, no pip.
  Streams HTTP responses (SSE-safe) and tunnels Codex WebSockets.
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

For Claude and Codex, `devbox --proxy` needs no proxy configuration file when
the host CLI is already logged in. Each default route chooses, in order:

| provider | API-key preference | OAuth credential |
|---|---|---|
| Claude | `ANTHROPIC_API_KEY` | `~/.claude/.credentials.json` |
| Codex | `OPENAI_API_KEY` | `~/.codex/auth.json` |

The proxy reads access tokens fresh on every request. Its background check runs
every minute, refreshes a session shortly before expiry, and retries a request
once after a 401 or 403. It uses OAuth refresh grants rather than sending empty
model prompts, so it does not consume model usage just to keep a session alive.
The VM never receives an access or refresh token; the repository also has a
pre-commit guard against embedding one in production scripts.

For Codex subscriptions, `devbox --proxy` gives the guest an isolated,
non-secret Codex profile that points its ChatGPT backend and WebSocket traffic
to the host proxy. The guest only receives the literal routing marker
`devbox-proxy`; the host replaces it with the refreshed OAuth header.

For OpenAI/Codex platform keys and the other API-key providers, configure
`api-keys.env` as before. An explicit `proxy.config.json` still takes full
control of every route and auth source.

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
