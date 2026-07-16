# devbox AI proxy

A tiny host-side reverse proxy that lets disposable devboxes use AI CLIs
**without ever holding a real credential**. Real keys/tokens stay on the host;
the proxy injects them and forwards to the provider.

- `devbox-ai-proxy.py` — the proxy. Python **standard library only**, no pip.
  Streams responses (SSE-safe), a few dozen lines.
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

## The two auth modes (both supported)

**1. API keys — static.** `auth.source: "env:OPENAI_API_KEY"`. The proxy reads
the key from its own environment (via `api-keys.env`) and injects it. Best for
opencode, stado, OpenAI/Codex-with-a-platform-key, and any provider you use with
a plain API key.

**2. OAuth subscription logins — dynamic.** Claude Code / Codex logged in with a
subscription don't use a static key; they use an OAuth **access token** that
expires (~hourly) and is refreshed. The trick that makes the proxy work "out of
the box":

> **Refresh happens on the host, not in the VM.** The proxy reads the *current*
> access token from the host's credential file **on every request**
> (`auth.source: "token-file:~/.claude/.credentials.json#claudeAiOauth.accessToken"`).
> As long as the host keeps that file fresh — which it does whenever you use the
> tool on the host — the VM always gets a valid token, and never sees the
> refresh token at all.

Caveat: if the host sits fully idle past token expiry, the file can hold a
stale token until the next host-side use refreshes it. For always-on setups run
the tool (or a small refresher) on the host periodically. The `anthropic-beta`
OAuth header value can also change over time — tune it in the config if
Anthropic updates it.

## Quick start

```sh
mkdir -p ~/.config/devbox
cp proxy/api-keys.env.example       ~/.config/devbox/api-keys.env      # fill in
cp proxy/proxy.config.example.json  ~/.config/devbox/proxy.config.json # edit routes
proxy/run.sh                                                           # leave running
```

Then in any project:

```sh
devbox --proxy          # VM's ANTHROPIC_BASE_URL / OPENAI_BASE_URL → the proxy
```

The guest reaches the host at `host.lima.internal`, so the default proxy URL is
`http://host.lima.internal:4000`. Because the guest reaches the host over Lima's
user-network gateway, the proxy binds `0.0.0.0` by default. It's your machine —
restrict with a firewall if you want it tighter, or set `"listen"` to a specific
interface.

## Heavier off-the-shelf alternatives

If you outgrow this, swap `run.sh` for a full gateway and keep `devbox --proxy`
pointed at it:

- **LiteLLM Proxy** — mature, multi-provider, virtual keys, Anthropic + OpenAI
  compatible endpoints. Great for the API-key case.
- **mitmproxy** with a small addon — good when you need per-request scripting
  (e.g. dynamic OAuth token injection) with a batteries-included TLS stack.

Both are Python, `pip`/`pipx`-installable — no Node.
