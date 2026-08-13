# Proxy audit logging

Devbox's authenticated AI and GitHub proxy writes a detailed, host-local audit
record for every request it actually forwards. Its purpose is to answer what an
agent did through host-backed authentication—not merely whether it opened a
connection.

## What is recorded

One JSONL event is appended after each final request result. Records include:

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
correlation. This is targeted redaction, not a guarantee that user-supplied
prompt or source content contains no secrets.

## Storage and export

The default log is `~/.config/devbox/proxy-audit.jsonl`; Devbox creates it with
mode `0600`. The default request-body capture limit is 1 MiB. Large and binary
bodies retain length and SHA-256, but do not retain their full contents.

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
access-controlled storage. The log is append-only while the proxy is running;
retention and removal stay an explicit host-operator decision. Set
`DEVBOX_PROXY_AUDIT=0`, or `"audit": { "enabled": false }` in the host-local
proxy configuration, before starting the proxy to disable future collection.

## Opt-in web egress audit

This audit normally covers only requests Devbox's authenticated proxy forwards;
it does not claim to see arbitrary guest networking. Add
`--traffic-audit=connect` (or `-T`) when ordinary web tools must use the same
host proxy or fail. Devbox writes a guest login profile with standard
`HTTP_PROXY`, `HTTPS_PROXY`, and `ALL_PROXY` settings, and an nftables output
rule rejects direct TCP and UDP connections to ports 80 and 443. Use
`--traffic-audit=off` to remove both from a kept box.

The traffic capability is distinct from the AI/GitHub credential capability,
expires after eight hours, and is refreshed when a kept audited box is
re-entered. It authorizes only public HTTP(S) destinations; the host proxy
refuses loopback, private, link-local, and other non-global addresses to avoid
becoming a path into host or LAN web services.

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
