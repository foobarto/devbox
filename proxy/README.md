# devbox credential proxy

A tiny host-side reverse proxy that lets disposable devboxes use AI and GitHub CLIs
**without ever holding a real credential**. Real keys/tokens stay on the host;
the proxy injects them and forwards to the provider.

> **Security boundary:** the primary purpose of `--proxy` is preventing token
> extraction from a Devbox: real credentials remain on the host. An in-VM agent
> can still make the proxy's permitted provider requests as the host account.
> Restrict the proxy listener to trusted guests/networks and give the flag only
> to trusted code. See
> [agent capability security](../docs/agent-capabilities-security.md).

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

| strategy | grant (flag) | secret location |
|---|---|---|
| **proxy** | `ai_proxy` / `github` (`--proxy` / `--gh-proxy`) | host only — VM sees a revocable per-box capability |
| API keys in VM | `api_keys` (`--api-keys`) | copied into the VM |
| OAuth creds in VM | `host_credentials` (`--with-creds`) | copied into the VM |

For a *disposable* box, keeping secrets on the host is the safer default: a
leaky or compromised box can't exfiltrate what it never had.

## Authentication (works out of the box)

For Claude and Codex (`devbox --proxy`) and GitHub CLI (`devbox --gh-proxy`, a
separate grant), no proxy configuration file is needed when the corresponding
host CLI is already logged in. Each default route
chooses, in order:

| provider | API-key preference | OAuth credential |
|---|---|---|
| Claude | `ANTHROPIC_API_KEY` | `~/.claude/.credentials.json` |
| Codex | `OPENAI_API_KEY` | `~/.codex/auth.json` |
| GitHub CLI (`gh`) | `GH_TOKEN` / `GITHUB_TOKEN` | host `gh auth login` |

The proxy reads access tokens fresh on every request. Its background check runs
every minute, refreshes Claude and Codex OAuth sessions shortly before expiry,
and retries a request once after a 401. Because a guest can provoke that 401,
such a forced refresh is skipped when the host has already replaced the
rejected token, runs under an owner-only host lock shared by every Devbox
proxy, and happens at most once a minute per provider; when the refreshed token
is rejected too, the next forced refresh waits 15 minutes. A 403 never
refreshes; it is retried once only when the host has already replaced the
token. Claude refreshes through its OAuth
grant; Codex refreshes through the host CLI's managed-auth `account/read`
interface, so the proxy never independently consumes Codex's one-time refresh
token. Refreshing does not send empty model prompts or consume model usage.
The VM never receives an access or refresh token; the repository also has a
pre-commit guard against embedding one in production scripts.

GitHub and traffic capabilities are bound to a box, audience, expiry, and
host-owned registration generation. Every request validates that live record;
revocation invalidates copied tokens, and recreating a grant never revives its
previous tokens. Older stateless tokens are rejected after upgrading the proxy.

The listener admits at most 256 concurrent connections. Every guest reaches the
proxy from 127.0.0.1, so the per-source cap defaults to the same value; fairness
between boxes is enforced after authentication, with 32 concurrent requests and
64 concurrent CONNECT tunnels per box. Before authentication, a guest can still
occupy connection slots, so a compromised guest can degrade the shared proxy for
other boxes; headers must arrive within 15 seconds, which limits how long it can
hold each one. Headers have a 15-second deadline; request bodies have a
300-second deadline and a 256 MiB limit. Aggregate body reservations are capped
at 768 MiB globally and 256 MiB per box (or across anonymous clients when
client authentication is disabled). Chunked uploads are charged incrementally
as bounded pieces are read. Streams and tunnels close after ten idle minutes or
eight hours. These defaults can be adjusted through `limits` in the example
configuration; the per-box body cap must remain below the global cap.

## Detailed audit log

By default, every request that reaches an authenticated AI or GitHub route is
recorded on the host with mode `0600`: AI routes in
`~/.config/devbox/proxy-audit-ai.jsonl`, GitHub and audited web traffic in
`~/.config/devbox/proxy-audit.jsonl`.
This is intentionally a detailed action log, not only access metadata: it
captures AI prompts and queries, GitHub REST/GraphQL request payloads, request
method/path, classification (`read`, `create-or-action`, `modify`, `delete`, or
GraphQL mutation), final status, duration, and response byte count. It never
records request headers, response bodies, host tokens, or known token/password
fields embedded in JSON bodies. Query values are omitted; only query parameter
names are retained.

The default capture cap is 1 MiB per request body. Larger or binary uploads
record byte count and SHA-256 plus a bounded text preview when possible. The
log can therefore contain prompts, source snippets, issue text, and other
sensitive work data. Do not commit, upload, or share it casually.

```sh
devbox proxy audit status             # path, size, and capture settings
devbox proxy audit show               # newest 50 JSONL entries
devbox proxy audit show 200           # newest 200 entries
devbox proxy audit export             # ~/.config/devbox/proxy-audit.html (mode 0600)
devbox proxy audit export ~/audit.html
```

The HTML report escapes captured content and highlights mutating operations.
Disable collection before starting the proxy with either
`DEVBOX_PROXY_AUDIT=0`, or this host-local `proxy.config.json` section:

```json
"audit": { "enabled": false }
```

See [proxy audit logging](../docs/proxy-audit.md) for the data model, retention
guidance, and the boundary between authentication auditing and optional traffic
capture.

## Opt-in CONNECT web egress audit

The `egress = "audit"` grant (deprecated flag `--traffic-audit`, `-T`) is
separate from the AI and GitHub grants and from the `agent` policy. It issues a
different eight-hour capability for generic public web traffic, sets the guest's
standard `HTTP(S)_PROXY` and `ALL_PROXY` variables (with `NO_PROXY` exempting
only guest loopback and this proxy's host, so AI clients still reach the
credential proxy directly), and blocks direct guest TCP/UDP ports 80 and 443
with nftables. Normal proxy-aware tools
therefore use this host proxy or fail visibly instead of bypassing its log.
The firewall survives guest restarts through a root-owned boot policy required
before supported systemd network services. Guests without that boot interface
are refused for audited egress.

HTTPS CONNECT records are intentionally metadata-only: destination host/port,
time, status, and byte counts. TLS remains end-to-end, so request paths and
bodies are unavailable. Plain HTTP proxy requests are visible and produce a
detailed audit record. The generic capability cannot reach loopback, private,
or link-local targets, preventing the proxy from becoming a route to host/LAN
web services.

`egress = "inspect"` (`--traffic-audit=inspect`) additionally installs a
Devbox CA in the guest. The proxy then terminates the box's TLS, records each
decrypted request, and forwards it only if the classifier configured under
`inspect` in `proxy.config.json` answers `allow`. Any failure blocks the
request. See [inspecting egress proxy](../docs/inspect-proxy.md).

This is a guest egress guard, not a hostile-root containment system: a process
with guest sudo/root can remove its nftables table, and non-web ports are not
covered. Remove it from a kept box with `devbox --traffic-audit=off`. See the
[detailed audit guide](../docs/proxy-audit.md) for limitations and data handling.

For Codex subscriptions, `devbox --proxy` gives the guest an isolated,
non-secret Codex profile that points its ChatGPT backend and WebSocket traffic
to the host proxy. As its API key the guest only receives the box's proxy
capability; the host replaces it with the refreshed OAuth header. Devbox fetches
the account's model definitions through that proxy into the isolated profile on
each entry and loads them with `model_catalog_json`. This lets the model picker show
account-specific models that are absent from the CLI's bundled catalog. A failed
refresh retains the previous catalog, or uses bundled models on first entry.
Restart an already-running Codex process to load a refreshed catalog. Only Codex's
own API, `chatgpt.com/backend-api/codex/`, is routed: the rest of
`chatgpt.com/backend-api` (conversation history, account, billing, and cloud
tasks) never receives the host login. Request paths with dot segments or encoded
separators are refused, so no route can be escaped through its prefix. A
`proxy.config.json` copied from an older example still routes all of
`/backend-api/`; change its `match` to `/backend-api/codex/`.
The host must have a current `codex` CLI on `PATH`. All Devbox proxy processes
also serialize refresh requests through an owner-only host lock and re-read
`auth.json` after taking it, so custom-port or concurrently started proxies
adopt a token another proxy already rotated instead of refreshing it again.

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
expires after eight hours. The long-lived proxy daemon scans host-owned box
registrations on every request to enforce revocation. Its background renewal scans
registrations once a minute and renews due capabilities every seven hours.
Renewal uses the recorded Lima box name directly: it does not depend on a
`devbox` terminal remaining open, re-read `.devbox.toml`, start a stopped box,
or restart a running guest. The wrapper reads the atomically replaced
capability file for every invocation. The CA's private key is discarded after it signs
the GitHub leaf, so it cannot issue certificates for other hosts. When the CA or
leaf nears expiry or no longer passes strict X.509 checks, the proxy replaces
both and delivers the new CA certificate to running boxes with their next
renewal check.
GitHub-owned download hosts are tunnelled without TLS interception.

The `github` grant (`--gh-proxy`) is separate: `ai_proxy`, the `agent` policy,
and `-a` never include it, so a box can use the host's AI logins while staying
sealed off from the host's GitHub identity. A kept box loses the grant when
entered under a policy without `github`, or with `--gh-proxy=off` or
`--no-auth`.

`--gh-proxy` also moves the usable Homebrew `gh` binary into the wrapper's managed
private directory and replaces Homebrew's public `bin/gh` link with the wrapper.
That prevents ordinary child-process and absolute-Homebrew-path mistakes. The
real binary must remain executable by the same guest user for the wrapper to run
it, so this is not a security boundary against deliberately hostile guest code.
`--gh-proxy=off` and `--no-auth` restore Homebrew's normal link.

Log in on the host first:

```sh
gh auth login
devbox --gh-proxy
```

The guest wrapper refuses `gh auth login`, `logout`, and token-changing auth
commands so a disposable box cannot alter the host account. `gh auth status`
is safe and reports the dummy environment-token login. This automatic path is
for GitHub.com; GitHub Enterprise hosts remain direct guest configuration.

### Repairing an existing box

For an immediate refresh of every registered running box, without resolving a
project manifest or opening/restarting a guest, run:

```sh
devbox proxy refresh
```

Use `gh api /rate_limit --jq .rate.remaining` in the existing guest as a
credential-safe smoke check. Do not run `gh auth login` in the guest; log in on
the host instead. Re-entering a kept box still repairs the wrapper/profile and
records it for daemon renewal, but is no longer needed for routine refreshes.
After upgrading from a proxy version without daemon renewal, the first new
`devbox --proxy`/`--gh-proxy`, `devbox proxy start`, or `devbox proxy refresh` restarts only
the host proxy process once; it does not restart any guest.

If the box says `gh` is missing, it predates the golden-image installation.
First check that its project work is committed or otherwise safe, then rebuild
the golden and recreate only that box:

```sh
devbox build --force
devbox ls                         # identify the kept box name
devbox destroy <box-name>
devbox --keep --policy agent-github     # or [grants] github = true
```

## Quick start

To use static API keys or custom routes, configure them once:

```sh
install -d -m 700 "$HOME/.config/devbox"
install -m 600 proxy/api-keys.env.example      "$HOME/.config/devbox/api-keys.env"      # fill in
install -m 600 proxy/proxy.config.example.json "$HOME/.config/devbox/proxy.config.json" # optional route overrides
```

The API-key file is parsed as data, not sourced as a shell script. Use one
`NAME=value` or `export NAME=value` assignment per line; literal unquoted,
single-quoted, and double-quoted values are supported. The proxy refuses links,
non-regular files, files owned by another user, and files with any group/other
permissions. If upgrading an older setup, run
`chmod 700 ~/.config/devbox && chmod 600 ~/.config/devbox/api-keys.env`.
Shell syntax such as `$(op read …)` is not evaluated; export such values in the
environment that starts devbox instead, which the proxy reads as a fallback.
Settings other than credentials (for example `DEVBOX_PROXY_AUDIT`) belong in
that environment or in `proxy.config.json`, not in this file.

Then grant `ai_proxy` — for example with `--policy agent` or `ai_proxy = true`
in `[grants]` — and **devbox auto-starts the host proxy** (once, shared across
boxes) if it isn't already running:

```sh
devbox --policy agent   # starts the proxy on the host, wires the box's env to it
```

Manage the shared proxy directly if you want:

```sh
devbox proxy status     # RUNNING / not running / port held by another service
devbox proxy start      # start it without a box
devbox proxy refresh    # renew every registered running box; no guest restart
devbox proxy stop       # stop it
```

The guest reaches the host at `host.lima.internal`, so the default proxy URL is
`http://host.lima.internal:4141` (a devbox-specific port chosen to avoid common
collisions — `4000` is often taken). If the port is already held by a
non-devbox service, devbox refuses to start rather than clobber it; set
`DEVBOX_PROXY_URL` to a free port. Because the guest reaches the host over
Lima's user-mode network, which delivers `host.lima.internal` (192.168.5.2)
connections on the host's loopback interface, the proxy listens on
`127.0.0.1` by default and nothing beyond this machine can reach it. Logs go to
`~/.config/devbox/proxy.log`.

### Per-box capability on AI routes

`devbox --proxy` sets the guest's `ANTHROPIC_API_KEY` and `OPENAI_API_KEY` to a
per-box capability, `dbx-ai.<box>.<secret>`, rather than a shared marker. The
proxy adds host AI credentials only when a request's `x-api-key` or bearer
`Authorization` header carries a registered capability, then removes it before
forwarding. The secret lives only in the owner-only host file
`~/.config/devbox/ai-proxy-boxes/<box>.key`; re-entering a kept box reuses it,
and destroying the box or `--no-auth` deletes it, revoking the capability
immediately. Audit records name the box.

A custom `~/.config/devbox/proxy-env` template receives the capability through
the `__PROXY_TOKEN__` placeholder, alongside `__PROXY_URL__`. An existing
`proxy.config.json` copied from an older example may still say
`"listen": "0.0.0.0:4141"`; change it to `127.0.0.1:4141`. Setting
`"ai_client_auth": "none"` accepts any client that reaches the listener, and the
proxy warns at startup when either setting widens access.

Two combinations change with this: an `api-keys.env` passed with `--api-keys`
that sets `ANTHROPIC_API_KEY` or `OPENAI_API_KEY` overrides the capability in
the guest, so the proxy refuses those AI requests (Devbox warns); and a
`DEVBOX_PROXY_URL` naming a host address other than `host.lima.internal` needs a
matching `"listen"` address. A gateway that authenticates guest-supplied keys
(LiteLLM and similar) should keep its own keys in a `proxy-env` template rather
than the box capability.

## Heavier off-the-shelf alternatives

If you outgrow this, swap `run.sh` for a full gateway and keep `devbox --proxy`
pointed at it:

- **LiteLLM Proxy** — mature, multi-provider, virtual keys, Anthropic + OpenAI
  compatible endpoints. Great for the API-key case.
- **mitmproxy** with a small addon — good when you need per-request scripting
  (e.g. dynamic OAuth token injection) with a batteries-included TLS stack.

Both are Python, `pip`/`pipx`-installable — no Node.
