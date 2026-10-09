# Inspecting egress proxy

`egress = "audit"` (`--traffic-audit=connect`) records where a box connected,
but HTTPS stays encrypted end to end, so the proxy never sees what was sent.
`egress = "inspect"` (`--traffic-audit=inspect`) goes further:
- the host proxy terminates the box's HTTPS with a Devbox CA. The CA is
  created on the host and trusted only by inspected guests, and its key never
  leaves the host;
- it records every decrypted request;
- it asks a small, configurable model whether the request may leave the
  machine.

A request leaves only if every existing check passes *and* the model answers
`allow`.

## Principles

1. **The model can only restrict.** Inspection runs after the deterministic
   checks: capability, generation, port, per-box budgets, and a check that the
   destination resolves to a public address (so the content of requests the
   proxy would refuse anyway never reaches the model). The address is checked
   again when the proxy connects. The verdict can block a request those checks
   allowed, but never allow one they refused. A prompt injection that fools the
   classifier therefore gains at most what `audit` mode already permits.
2. **Fail closed.** Each of these blocks the request with `403` and records the
   reason in the audit log:
   - no CA;
   - no classifier configuration or API key;
   - a timeout, or a full queue;
   - an HTTP error or a redirect from the classifier;
   - an answer that is not a JSON `allow`/`block` verdict;
   - a body above the inspection limit, or a content encoding that cannot be
     decoded.

   There is no "allow on error" setting. If inspection is unavailable when a
   tunnel opens, the CONNECT itself is refused with `503`.
3. **The host decides the mode.** Whether a box is inspected is set by a
   host-side registration (`~/.config/devbox/traffic-inspect-boxes/NAME`),
   written by the launcher. Neither the guest's capability nor its headers
   decide it, so a guest cannot downgrade itself to an opaque tunnel. While a
   box is registered, the proxy refuses opaque tunnels for it and closes the
   ones already open. An unreadable or unexpected entry at that path also
   counts as "inspect".
4. **Restriction composes upward.** The order is `open` < `audit` < `inspect`.
   A project manifest may raise a machine default of `audit` to `inspect`, but
   cannot lower an `inspect` default.
5. **No new dependencies.** The proxy remains standard-library Python plus the
   host's `openssl` command, as the GitHub proxy already is.

## What changes in the guest

Inspection builds on everything `audit` mode already does:
- the nftables boot policy that blocks direct web egress;
- `HTTP(S)_PROXY` set to a short-lived per-box capability.

In addition:

- **The inspection CA is installed.** It goes into the system trust store, via
  `update-ca-certificates` or `update-ca-trust`, and is also stored at
  `/usr/local/share/devbox/inspect-ca.pem`.
- **A login profile is added** for runtimes that ignore the system store.
  `/etc/profile.d/zz-devbox-31-traffic-inspect.sh` sets:
  - `NODE_EXTRA_CA_CERTS` (Node, Bun);
  - `DENO_CERT`;
  - `SSL_CERT_FILE`, `REQUESTS_CA_BUNDLE`, `CURL_CA_BUNDLE` and `PIP_CERT`.
- **Some clients will fail to connect.** This includes clients with pinned
  certificates or a private trust store, such as some Java and statically
  linked Rust builds. It also includes clients that do not use the proxy
  variables: Python's `urllib` sends no proxy credentials when the password is
  empty, although `requests` and pip work. Such clients fail at the firewall or
  the proxy. That is the fail-closed outcome, not a bypass.
- **The CA private key stays on the host.** Leaving inspect mode removes the CA
  from the trust store and deletes the profile.

The registration is written before the guest trusts the CA, and before its
profile receives a fresh traffic capability. It is revoked only after the CA has
been removed again. A mode change therefore never leaves a window in which
traffic is uninspected. A bare `--traffic-audit` (`-T`) keeps an inspected box
inspected; only an explicit `--traffic-audit=connect` or `=off` lowers it.

## Proxy flow

```
guest CONNECT host:443 (traffic capability)
  ├─ deterministic checks, as in audit mode        → refuse: 403 / 407 / 503
  ├─ box not registered for inspection             → opaque tunnel (audit mode),
  │                                                   closed if inspection is later required
  └─ registered: inspection unavailable            → 503
                 otherwise 200, TLS handshake with a leaf for `host` (ALPN http/1.1)
                 └─ for each HTTP/1.1 request on the decrypted stream:
                      read body (bounded); Upgrade/WebSocket → 403
                      classify; write the opening audit event (required)
                      block → 403 with the reason
                      allow → open a fresh, verified TLS connection to the
                              CONNECT host's public address; stream the response back
                      write the completed audit event with the verdict
```

- **Fixed destination.** The upstream is always the CONNECT authority, resolved
  once to a public address. A different `Host` header is passed to the
  classifier as a signal; it never changes where the request goes. A nested
  CONNECT inside an inspected session is refused.
- **Upstream TLS.** It is verified against the host's system trust store, with
  SNI set to the CONNECT host.
- **Plain HTTP.** Port 80 traffic (absolute-form requests, or a CONNECT to
  `:80`) takes the same inspection path, without TLS.
- **Leaf certificates.**
  - One EC P-256 leaf key is created alongside the CA.
  - Each hostname gets its own 30-day certificate, signed on first use and
    cached in memory for a day.
  - Hostnames are validated as DNS names or IP literals before they reach
    `openssl`.
- **No HTTP/2.** Only HTTP/1.1 is offered over ALPN, so clients do not switch
  to HTTP/2 framing that this inspector would not read.

## Classifier

Configure it in the `inspect` section of `proxy.config.json`, then restart the
proxy (`devbox proxy stop`; it restarts on the next run):

```json
"inspect": {
  "provider": "anthropic",
  "model": "claude-haiku-4-5",
  "api_key_env": "ANTHROPIC_API_KEY",
  "base_url": "https://api.anthropic.com",
  "timeout_seconds": 20,
  "max_concurrency": 4,
  "max_body_bytes": 65536,
  "cache_seconds": 300,
  "instructions": "",
  "skip": []
}
```

- **`provider`**: `anthropic` for the Messages API, or `openai` for any
  Chat Completions-compatible endpoint (OpenAI, OpenRouter, a local Ollama at
  `http://127.0.0.1:11434/v1`). `openai` requires `model`.
- **Model choice**: the defaults aim at the cheapest current models; any model
  name the endpoint accepts works. `request_options` is merged into the request
  body for provider-specific tuning.
- **`api_key_env`**: names a key that the proxy reads on the host, from its
  environment or from `api-keys.env`, never from the guest. Set it to `""` for
  an endpoint that needs no key.
- **Endpoint security**: classifier calls go directly from the host, are not
  inspected themselves, and do not follow redirects. `base_url` must be
  `https`, or `http` on localhost.
- **`instructions`**: optional, trusted operator text appended to the system
  prompt — for example, what the box is meant to be working on.
- **`skip`**: optional rules for requests that are audited but not sent to the
  classifier, such as downloads from a package registry. For example:

  ```json
  "skip": [{"hosts": ["registry.npmjs.org", "*.pypi.org"], "methods": ["GET", "HEAD"]}]
  ```

  How rules match:
  - `methods` defaults to `GET` and `HEAD`.
  - `*.example.org` matches subdomains only.
  - A rule matches only requests with no body, unless it sets `max_body_bytes`.
  - Nothing in the guest or in a project manifest can add a rule.

`devbox` checks readiness before enabling inspection, and refuses with the
reason if the classifier is not ready. The check is
`devbox-ai-proxy --inspect-status`, and it runs with the launching shell's
environment. The running proxy daemon reads the key from its own environment,
taken when it started, or from `api-keys.env`. If the daemon lacks the key, every
inspected CONNECT fails with `503`, and the host proxy log says why.

A blocked request gets `403` with an `audit_request_id`, but not the
classifier's reason: the reason stays in the host audit log, so a manipulated
agent cannot use it to rephrase until something passes.

### What the classifier sees

The classifier receives one JSON document per request, labelled as untrusted
data and delimited so the request cannot close its own delimiter:
- **Request line**: the method, and the URL with the full query string.
- **Headers**: names and full values, except a fixed list of credential
  headers.
  - `Authorization`, `X-Api-Key`, `Api-Key`, `X-Goog-Api-Key`, `X-Auth-Token`,
    `Private-Token`, `X-Amz-Security-Token`, `X-Vault-Token` and
    `X-Registry-Auth` are replaced by their scheme and length.
  - `Cookie` is reduced to its cookie names and value lengths.
  - A credential value over 4,096 characters blocks the request instead.
- **Body**: the whole body as text. A gzip or deflate body is decoded first. A
  binary body is described by its length and a 512-byte hex prefix. A body
  larger than `max_body_bytes` blocks the request without a call.
- **`Host` header**: included only when it differs from the CONNECT
  destination.

Nothing is truncated. A URL or header value over 16,384 characters blocks the
request without a call. So does a body with:
- more than one content encoding;
- data outside its single gzip or deflate stream.

The classifier must answer with a JSON object,
`{"verdict": "allow"|"block", "reason": "..."}`. Any other answer blocks the
request.

The default system prompt tells the model to block requests that:
- send secrets, credentials, private keys or configuration to destinations with
  no evident need for them;
- upload source code or bulk data to destinations that are not evident
  development services;
- hide data in paths, query strings, headers or subdomain labels;
- perform destructive or account-changing actions unrelated to development;
- address the classifier itself.

Ordinary development traffic is allowed.

Verdicts are cached, keyed by a hash of the classifier input, for
`cache_seconds`. Retries and identical polling requests therefore cost one
classifier call; classifier errors are not cached.

## Data handling and cost

- **Data sent out.** Inspect mode sends request contents, bodies included, to
  the configured model provider. To avoid sending traffic to a third party,
  point `base_url` at a local model.
- **Audit log.** Each decrypted request is recorded with source
  `traffic-inspect`, using the audit's usual redaction rules plus an
  `inspection` object holding the verdict, reason, model, latency, and the
  cache, skip and error state ([proxy audit](proxy-audit.md)).
- **Latency and cost.** Every request that is neither skipped nor cached waits
  for a model call.
- **GitHub grant.** On an inspected box, `github` (`--gh-proxy`) API calls are
  classified like other traffic. The opaque tunnels that the gh grant otherwise
  opens to `github.com` and `*.githubusercontent.com` are refused, so `gh`
  commands that need them fail. Git over HTTPS uses the inspected web path.
- **AI agents in the box.** Pair inspection with the `ai_proxy` grant
  (`--proxy`). Agent traffic then goes to the credential proxy, which is exempt
  from `HTTP(S)_PROXY`. Without it, the agent's own model traffic is inspected
  too, and most of its requests exceed `max_body_bytes`.

## Limits

- **Not containment.** A process with guest root can remove the firewall and
  the CA. Like `audit` mode, inspection is a workflow guard and an audit trail.
- **What is not inspected.**
  - HTTP/2 and HTTP/3: HTTP/2 is avoided through ALPN, and UDP web egress is
    already blocked.
  - WebSocket payloads: `Upgrade` requests are refused instead.
  - Non-web ports.
  - Response bodies.
- **Probabilistic.** The classifier reduces what a compromised agent can send,
  and records what it tried; it does not prove that nothing leaked. Data split
  across many small requests, each innocuous on its own, is the hardest case
  for any per-request filter.
