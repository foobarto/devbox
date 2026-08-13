# Devbox OAuth proxy: security rationale and terms boundary

**Status:** design position, not legal advice
**Reviewed:** 2026-08-13

## Purpose

The sole purpose of Devbox's OAuth proxy is to keep a user's OAuth access and
refresh tokens **outside** a disposable Devbox.  An AI agent or a script it
launches can make only the provider requests that the proxy permits; it cannot
read, copy, retain, replay elsewhere, or exfiltrate the underlying OAuth
credentials.

This is a token firewall, not a mechanism to share an account, create a hosted
AI service, avoid provider limits, or conceal activity from the provider.

## Security model

Without the proxy, a guest needs a copied API key or OAuth credential.  Any
process in that guest can then steal the credential and use it after the guest
is destroyed.  With the proxy, the host owns and refreshes the credential and
injects it only while forwarding an allowed request:

```text
agent or guest script -- request capability --> host proxy -- OAuth token --> provider
                                                   ^
                                                   host-only credential storage
```

The proxy does **not** make the guest harmless.  A compromised guest can still
use the request capability while it is active: it can consume the account's
allowed usage and send prompt content, source snippets, or uploads through the
permitted route.  The benefit is that it cannot turn that temporary operational
authority into a portable, long-lived OAuth credential.

Anthropic documents this pattern for agents: run a proxy outside the agent
boundary, inject credentials there, restrict endpoints, and keep credentials
out of the agent environment.  It documents `ANTHROPIC_BASE_URL` for sending
Claude Code requests to such a proxy.

## Scope required for this position

The argument depends on Devbox remaining a **single-user, host-local security
feature**.  It must not become a generic way to give other people or machines
access to the host account.

- The person who owns the provider account operates the local Devbox and
  controls the code given this capability.
- OAuth access and refresh tokens never enter the guest, project, image, logs,
  or exported configuration.
- The proxy is reachable only by the intended guest/network boundary and uses
  a short-lived, per-guest request capability.  A broadly reachable proxy URL
  is itself an account capability, even if it contains no provider token.
- Provider routes are allowlisted; the proxy does not act as arbitrary upstream
  forwarding or an account-management relay.
- Provider rate limits, usage limits, safety controls, and account identity are
  preserved.  Devbox must not pool accounts, bypass controls, or use retries or
  concurrency to evade limits.
- `--no-auth` remains a clean removal path for Devbox-managed authentication.

If any of those conditions changes—for example, a shared workstation, remote
proxy, multi-user service, CI service used by several people, or a public
listener—the local token-firewall rationale is insufficient.  Use an
organization-owned API or gateway arrangement instead.

## Provider terms and documentation

This section records the relevant published material, not a legal conclusion.
Terms, product behavior, and negotiated enterprise agreements can change.

### OpenAI / Codex

OpenAI's individual Terms of Use say that an account holder may not share
account credentials or make an account available to someone else, and may not
bypass rate limits, restrictions, or protective measures.  The terms do not
state a general ban on a user-operated local proxy.  Keeping OAuth tokens out
of an untrusted guest supports the credential-sharing restriction, but does not
by itself justify delegating the host account to another person.

For API and business use, the OpenAI Services Agreement expressly permits
customers to integrate the API into customer applications for end users, while
requiring the customer not to share login credentials between multiple users or
circumvent limits.  A corporate gateway therefore needs per-user attribution
and revocation, not a shared personal OAuth session.

### Anthropic / Claude Code

Anthropic's secure-agent documentation explicitly recommends an external
credential-injecting proxy.  Its Claude Code documentation also supports LLM
gateways through `ANTHROPIC_BASE_URL`; gateway documentation describes
centralized authentication, usage tracking, rate limiting, and auditing.

Anthropic separately says that third-party developers may not offer Claude.ai
login or route requests through Free, Pro, or Max credentials **on behalf of
their users**.  Devbox's narrow position is that a user runs a local token
firewall for that same user's native CLI; it is not a service offering another
user a Claude subscription login.  That distinction is important but is not a
substitute for written clarification from Anthropic if the feature's scope
expands or its permissibility is questioned.

## Corporate use

A corporate proxy follows the same security principle but has a different
identity model:

```text
developer identity --> company gateway credential --> organization-owned API or cloud account
```

Each developer should authenticate separately; access should be attributable,
scoped, revocable, and subject to organization budgets, data handling,
monitoring, and retention rules.  Do not substitute a personal subscription
OAuth session for that arrangement.  Anthropic documents both its own SSO-backed
gateway and other organization-operated LLM gateways.  OpenAI-managed accounts
are governed by the organization's agreement and internal policies in addition
to provider policies.

## Audit logging is separate

Host-side request logging can support incident review and accountability, but
it is not necessary to protect OAuth credentials.  It also creates a separate
sensitive datastore that may contain prompts, source code, or uploads.  Its
collection, retention, access controls, and employee notice therefore need an
explicit decision, especially for corporate use.

## References

- [OpenAI Terms of Use](https://openai.com/policies/terms-of-use/)
- [OpenAI Services Agreement](https://openai.com/policies/services-agreement/)
- [Anthropic: Securely deploying AI agents](https://code.claude.com/docs/en/agent-sdk/secure-deployment)
- [Anthropic: Legal and compliance](https://code.claude.com/docs/en/legal-and-compliance)
- [Anthropic: Other LLM gateways](https://code.claude.com/docs/en/llm-gateway)
- [Anthropic: Claude apps gateway](https://code.claude.com/docs/en/claude-apps-gateway)
- [OpenAI: data access for managed ChatGPT accounts](https://help.openai.com/en/articles/20001067)
