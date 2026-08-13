# Devbox OAuth proxy: security rationale and terms boundary

**Status:** design position, not legal advice
**Reviewed:** 2026-08-13

## Purpose

The OAuth path of `devbox --proxy` exists to keep a user's OAuth access and
refresh tokens **outside** a disposable Devbox. Through the proxy, an AI agent
or a script it launches can make only requests matching the configured routes;
it cannot read, copy, retain, replay elsewhere, or exfiltrate the underlying
OAuth credentials.

This is a token firewall, not a mechanism to share an account, create a hosted
AI service, avoid provider limits, or conceal activity from the provider.

## Security model

Without the proxy, a guest needs a copied API key or OAuth credential. Any
process in that guest can then steal the credential and use it after the guest
is destroyed. With the proxy, the host owns and refreshes the credential and
injects it only while forwarding an allowed request:

```text
agent or guest script -- configured route --> host proxy -- OAuth token --> provider
                                                ^
                                                host-only credential storage
```

The proxy does **not** make the guest harmless. A compromised guest can still
use the proxy while it can reach the running host service: it can consume the
account's allowed usage and send prompt content, source snippets, or uploads
through a permitted route. The benefit is that it cannot turn that operational
authority into a portable, long-lived OAuth credential.

Anthropic documents this pattern for agents: run a proxy outside the agent
boundary, inject credentials there, restrict endpoints, and keep credentials
out of the agent environment.  It documents `ANTHROPIC_BASE_URL` for sending
Claude Code requests to such a proxy.

## Permanent single-host, single-user scope

Devbox is a single-host, single-user tool only. The provider-account owner
starts and uses their own VM on that host. There is no account delegation,
sharing, remote service, hosted offering, or multi-user Devbox mode.

The code or agent inside the VM can still be untrusted. It receives operational
access to configured AI routes, not an OAuth token. `--proxy` is not an egress
firewall: the guest otherwise has its ordinary network access, and the OAuth
argument concerns only access through Devbox's configured proxy routes.

The current implementation boundary is deliberately narrower than a
per-guest-credential design:

- The host proxy is shared across locally started Devboxes and its listener may
  bind broadly so Lima guests can reach it.
- AI routes do not currently require a short-lived, per-guest capability. The
  separate GitHub and generic traffic-audit routes have their own capability
  mechanisms, but those do not protect AI routes.
- The built-in route table is constrained, while a host operator can choose an
  explicit custom route configuration.

Keep the listener on the intended host/guest boundary; use a host firewall or a
narrower `listen` setting when the surrounding network is not fully trusted.
Adding a short-lived, per-guest capability to AI routes would strengthen the
same single-user boundary. `--no-auth` remains the clean removal path for
Devbox-managed authentication.

## Provider terms and documentation

This section records the relevant published material, not a legal conclusion.
Terms, product behavior, and negotiated enterprise agreements can change.

### OpenAI / Codex

OpenAI's individual Terms of Use say that an account holder may not share
account credentials or make an account available to someone else, and may not
bypass rate limits, restrictions, or protective measures. We did not find a
provision that expressly addresses a user-operated local proxy; that absence is
not provider approval. In Devbox's stated model there is no account delegation:
the same account owner starts and controls both host and guest. Keeping OAuth
tokens out of an untrusted guest is a defense against guest code, not sharing a
credential with another person.

### Anthropic / Claude Code

Anthropic's secure-agent documentation explicitly recommends an external
credential-injecting proxy.  Its Claude Code documentation also supports LLM
proxy routing through `ANTHROPIC_BASE_URL`.

Anthropic separately says that third-party developers may not offer Claude.ai
login or route requests through Free, Pro, or Max credentials **on behalf of
their users**. Devbox is distributed software, but its intended deployment is a
user operating a local token firewall for that same user's native CLI—not a
service offering another user a Claude subscription login. Anthropic's
published material does not expressly resolve that precise distinction, so this
note does not claim provider approval. Seek written clarification if the
feature's permissibility is questioned.

## Audit logging is separate

In the current default configuration, host-side logging records authenticated
AI and GitHub request payloads. It intentionally omits request headers and
redacts known JSON credential fields, but it can retain prompts, source code,
or uploads. It is not necessary to protect OAuth credentials; it is a separate
sensitive datastore. Its collection, retention, access controls, and employee
notice therefore need an explicit decision.

## References

- [OpenAI Terms of Use](https://openai.com/policies/terms-of-use/)
- [Anthropic: Securely deploying AI agents](https://code.claude.com/docs/en/agent-sdk/secure-deployment)
- [Anthropic: Legal and compliance](https://code.claude.com/docs/en/legal-and-compliance)
- [Anthropic: Environment variables (`ANTHROPIC_BASE_URL`)](https://code.claude.com/docs/en/env-vars)
- [Anthropic: Other LLM gateways](https://code.claude.com/docs/en/llm-gateway)
