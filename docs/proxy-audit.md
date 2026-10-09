# Proxy audit logging

Devbox's authenticated AI and GitHub proxy writes a detailed, host-local audit
record for every request it actually forwards. Its purpose is to answer what an
agent did through host-backed authentication—not merely whether it opened a
connection.

## What is recorded

A `request-open` event is committed before forwarding, followed by a
`completed` event with the same request ID after the final result. An unmatched
opening event indicates an interrupted request. If enabled audit storage cannot
accept the opening event, the proxy refuses to forward. Records include:

- UTC timestamp, provider, proxy source, guest address, and upstream host;
- request method and path, plus query parameter **names** but not values;
- the actual request payload: AI prompts/queries and GitHub REST or GraphQL
  payloads, subject to the body-size cap;
- action classification and whether it can change remote state;
- final HTTP status, elapsed time, upstream attempts, and response byte count.

The classifier treats `POST` as `create-or-action`, `PUT`/`PATCH` as `modify`,
and `DELETE` as `delete`. GitHub GraphQL operations are classified as a
`graphql-mutation` or `graphql-query` from their submitted query. Classification
describes the requested operation; the recorded final status tells whether it
succeeded. Inspect response details in the provider or GitHub when a status
alone is insufficient.

Request headers and response bodies are never recorded. Known JSON credential
keys—such as `authorization`, `access_token`, `refresh_token`, `api_key`, and
`password`—are replaced with `[redacted]`. The raw body SHA-256 is retained for
correlation. Key matching also recognizes camelCase and separator variants,
including `accessToken`, `refreshToken`, `apiKey`, and `clientSecret`.
This is targeted redaction, not a guarantee that user-supplied
prompt or source content contains no secrets.

## Storage and export

The default log is `~/.config/devbox/proxy-audit.jsonl`; Devbox creates it with
mode `0600`. AI-route events (prompts) go to a sibling
`~/.config/devbox/proxy-audit-ai.jsonl` with its own retention, so routine model
traffic cannot rotate GitHub, traffic, and mutation records out of the main log.
The default request-body capture limit is 1 MiB. Large and binary bodies retain
length and SHA-256, but do not retain their full contents. Each request's body is
captured once, in its `request-open` event; the `completed` event repeats only
the body's length and SHA-256.

```sh
devbox proxy audit status
devbox proxy audit show [LIMIT]
devbox proxy audit export [FILE]
```

`export` writes a self-contained HTML report with mode `0600`, defaulting to
`~/.config/devbox/proxy-audit.html`. The report escapes all captured text and
highlights requested state-changing actions. It is still sensitive: it may
contain prompts, source snippets, issue text, pull-request descriptions, and
other request payloads.

Keep both files outside repositories and back them up only into encrypted,
access-controlled storage. Audit storage rotates at 16 MiB, retaining three
backups (64 MiB per log); show/export merge both logs and their retained
backups. A log larger than the quota from before quotas existed is moved aside
intact, as `proxy-audit.jsonl.legacy-<timestamp>`, on the first write; it is not
rotated or deleted, so archive or remove it yourself. The proxy refuses forwarding
when less than 64 MiB of disk space remains or enabled audit storage fails.
Repeated rejected-client events are limited globally and per source, with
suppression counts. Host configuration can change these defaults through
`audit.max_file_bytes`, `backup_count`, `min_free_bytes`, and
`failure_interval_seconds`. Redirected proxy diagnostic logs reset at 8 MiB
(`diagnostics.max_file_bytes`); terminal and pipe output are unaffected. Set
`DEVBOX_PROXY_AUDIT=0`, or `"audit": { "enabled": false }` in the host-local
proxy configuration, before starting the proxy to disable future collection.
Audited generic traffic requires enabled, working audit storage and fails
closed when collection is disabled.

## Opt-in web egress audit

This audit normally covers only requests Devbox's authenticated proxy forwards;
it does not claim to see arbitrary guest networking. Grant `egress = "audit"`
in a policy or `[grants]` (the deprecated flag is `--traffic-audit`, `-T`) when
ordinary web tools must use the same host proxy or fail. Devbox writes a guest
login profile with standard `HTTP_PROXY`, `HTTPS_PROXY`, and `ALL_PROXY`
settings — with `NO_PROXY` exempting only guest loopback and the Devbox proxy
host — and an nftables output rule rejects direct TCP and UDP connections to
ports 80 and 443. A policy without it, or `--traffic-audit=off`, removes both
from a kept box.

The rule is replaced in a checked atomic transaction. Devbox persists a
root-owned boot policy and requires it before supported systemd network
services start, preserving the guard across guest restarts. Audited egress
refuses guests without systemd or a recognized network service. Running legacy
audited boxes receive the boot policy in place on re-entry; stopped legacy boxes without a
verified boot policy must be recreated.

The traffic capability is distinct from the AI/GitHub credential capability,
expires after eight hours, and is refreshed when a kept audited box is
re-entered. Every request checks its box's current host registration generation;
removing the grant or destroying the box invalidates copied capabilities.
Open tunnels recheck the grant at least once per second and close on revocation.
It authorizes only public HTTP(S) destinations; the host proxy
refuses loopback, private, link-local, and other non-global addresses to avoid
becoming a path into host or LAN web services.

With `egress = "inspect"`, each request decrypted inside an inspected tunnel is
recorded like an AI-route request: method, path, query keys, and captured body,
with source `traffic-inspect`. An `inspection` object adds the classifier's
verdict, reason, provider, model, latency, and the `cached`, `skipped` and
`error` fields. The tunnel itself is recorded as a `traffic-connect` event with
action `inspected-connect`. See [inspecting egress proxy](inspect-proxy.md).

CONNECT records have source `traffic-connect` and retain only destination
host/port, status, timing, and request/response byte counts. HTTPS is still
end-to-end encrypted after CONNECT, so Devbox cannot see its paths, headers,
prompts, or request bodies. Ordinary plaintext HTTP proxy requests are visible
and receive the normal detailed request audit. A tool that ignores proxy
variables fails on direct web ports instead of silently bypassing this audit.

This is deliberately not a general network sandbox: non-web ports are outside
the rule, and a process that has guest root/sudo can alter guest nftables rules.
It is suitable for making normal developer tooling proxy-or-fail, not for
containing hostile privileged code. It is also not TLS inspection. A future
inspection mode would need a separately opt-in Devbox CA and will break clients
that pin certificates or use their own trust store.
