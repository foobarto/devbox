# Agent capability security

This document describes the security boundary for a coding agent or any other
process running **inside a Devbox**. It is not the same as running that agent on
the host: the VM restricts filesystem and process access, but each opt-in
Devbox feature grants a specific host-backed capability.

Use these features for code you trust. A compromised or malicious in-VM agent
can exercise every capability you grant it, even when it cannot extract the
underlying host credential.

Each capability below is a **grant**, declared in a [grant policy](policies.md)
or a project's `[grants]` table; the per-grant flags named alongside are
deprecated shorthands. For the `ai_proxy` and `github` grants, preventing
credential exfiltration is the primary security goal:
the guest never receives the host's real API keys or OAuth tokens. The proxy is
not, by itself, a least-authority policy for requests made while the Devbox is
allowed to use it.

## Baseline: Devbox agent versus host agent

| capability | agent inside a default Devbox | same agent on the host |
|---|---|---|
| Files and processes | Sees the mounted project, its narrow Devbox-managed AI session store, and guest filesystem/processes, plus only explicitly mounted or copied host paths. It cannot read the rest of the host home directory or control host processes. | Can read and modify every file and process the host user is permitted to access, including local tool configuration and authentication state. |
| Host credentials | Receives none by default. | Can read, copy, or invoke credentials and authenticated CLIs available to the host user. |
| Desktop session | No access to the host Wayland socket or GPU nodes. | Can use the host desktop session and any local desktop capabilities available to the user. |
| Network and remote services | Has normal guest networking and can use only credentials/capabilities explicitly provided to it. | Can use host network configuration, authenticated clients, and any credentials available to the host user. |

The project directory is mounted read-write by default. Isolation does not stop
an agent from changing the project or sending its contents to a network service
that it is authorized to use. The default per-project session store is also
read-write so resumable transcripts survive clone deletion; use
`--ephemeral-sessions` when that persistence is unwanted.

## Capability matrix

| feature | what an agent in the Devbox can do | what remains outside the Devbox |
|---|---|---|
| Persistent AI sessions (default) | Read and modify this project's Devbox-managed Claude, Codex, OpenCode, Pi, and Stado session records across VM lifecycles. This enables native resume commands but also carries transcript instructions and tool output into future clones. | Other projects' Devbox stores, existing host agent histories, auth files, provider tokens, caches, and general host state remain unmounted. `--ephemeral-sessions` / `-e` disconnects the native session paths for that run. |
| `ssh_agent` (`--ssh-agent`) | Request authentication and signatures using identities currently loaded in the host SSH agent. This includes SSH/Git access accepted by those identities and Devbox's SSH-format Git commit signing. | It cannot read or copy the private-key material from the agent. It does not gain access to unmounted host files or a host shell. |
| `ai_proxy` (`--proxy`) | Make requests through Devbox's configured AI routes using the host's AI-provider logins. It can consume quotas and send prompts, code, and files to those providers. | It does not receive the underlying API keys or OAuth tokens, and it gets no GitHub access. The guest runs its own CLIs; it cannot run host commands through the proxy. |
| `github` (`--gh-proxy`) | Use `gh` as the host's GitHub login: read, create, modify, delete, or upload anything that account can reach through `api.github.com`. | It does not receive the host `gh` token. It is never implied by `ai_proxy` or `-a`. |
| `egress = "audit"` (`--traffic-audit`) | Send proxy-aware public web traffic through a short-lived generic CONNECT capability. Direct TCP/UDP 80/443 fails under the guest firewall; CONNECT audit records reveal destination, timing, and byte counts, while plaintext HTTP can be recorded in detail. | It grants no AI, GitHub, SSH, or host-login credential. HTTPS remains encrypted after CONNECT, and non-web ports remain outside the rule. The generic proxy refuses host/private/LAN destinations. |
| `--gui` / `-G` (not a grant; command-line only) | Become a Wayland client of the host session through Waypipe. | It does not receive the raw host Wayland socket or host GPU/render-device nodes. This is still a host-desktop capability, not an isolation boundary; see [GUI forwarding security](gui-security.md). |
| `agent_config` (`--with-agent-config`) | Read selected preference fields exported from known Claude, Codex, and OpenCode structured configuration schemas. | Only explicitly permitted enum, boolean, and bounded numeric values cross the boundary. Unknown fields, credentials, free-form instructions, hooks, plugin code, and unsupported formats stay on the host. |
| `api_keys` (`--api-keys`) or `host_credentials` (`--with-creds`) | Read actual keys or copied OAuth credentials in the guest. | These deliberately weaken the host-only credential boundary. Prefer `ai_proxy` when the provider workflow supports it. |
| pre-accepted agent prompts *(always on, no flag)* | Start work in the mounted directory without a trust dialog, which also means the repository's own `.claude/settings.json` and hooks run unprompted. See [pre-accepted agent first-run prompts](#pre-accepted-agent-first-run-prompts). | It gains no capability the flags above do not already grant, and trust is never seeded for `$HOME` or for `--mount` paths. |

## Host configuration and file transfers

`agent_config` exports safe fields from `.claude/settings.json`,
`.claude/settings.local.json`, `.codex/config.toml`, and
`.config/opencode/opencode.json`. The current schemas preserve selected model,
reasoning, approval, sandbox, history, and UI preferences. Fields with arbitrary
strings or executable content are excluded. Unknown model identifiers are also
excluded until added to the closed value sets. Stado configuration and JSONC
currently have no supported export schema. The field schemas are in
[`devbox-host-files.py`](../proxy/devbox-host-files.py).

File-name allowlists or secret-pattern detection cannot establish that prose,
custom agents, hooks, rules, or arbitrary configuration are free of secrets.
Transfer such content only through an explicit `copies` grant (`--copy`), which
copies raw data including any secrets. `host_credentials` similarly authorizes
raw credential/configuration transfer; it is separate from `agent_config`.

Before starting or resuming the guest, Devbox opens granted inputs through
no-follow file descriptors and creates private snapshots outside guest mounts.
API-key files must be regular files and fit within 1 MiB. Each operator-named
source is resolved once; the resolved path is then walked without following
links. Structured configuration inputs are capped at 2 MiB.
Directory copies use descriptor-based traversal and omit nested symlinks rather
than resolving their targets. Snapshots are removed when the run ends. This
prevents a guest from changing a source path into unrelated host content during
transfer; it does not make explicitly copied content non-sensitive.

Devbox refuses approved sources below a writable mount of any stored Lima VM,
or below another writable mount planned for this run. It checks pathname and
device/inode ancestry and, on Linux, unfolds mount-namespace coordinates, so
distinct bind-mount or filesystem aliases to the same writable ancestor are
also refused. A guest must not be able to replace a source through a mounted
parent; choose non-overlapping mounts. Grant sources (copies, credential,
configuration and API-key files) at or below another stored instance's
writable mount are refused for the same reason. Devbox also records the device/inode of
mount sources and their ancestors, then checks them around clone/start
operations and refuses changes. Lima resolves
mount paths in a separate process: these surrounding checks cannot atomically
pin the object Lima resolves or rule out a path that changes and changes back
entirely during Lima's operation. Changes by external host processes remain a
trust assumption. Do not mount sensitive paths whose ancestry can be changed
by an untrusted host process. A path-only Lima interface needs a
stable-object mounting mechanism to remove this remaining timing limitation.

## SSH-agent forwarding

Forwarded SSH agent access is an **operation capability**, not a key-copying
mechanism. The guest sees an agent socket and public identities; it can ask the
host agent to sign or authenticate, but cannot export the loaded private keys.
OpenSSH gives the same warning: a remote user able to access the forwarded agent
socket can use the identities for authentication operations even though the key
material remains protected. See the [OpenSSH `ForwardAgent`
documentation](https://man.openbsd.org/ssh_config#ForwardAgent).

That means an untrusted agent with `--ssh-agent` can attempt to authenticate to
any remote system that accepts an identity currently loaded in the host agent.
It may also produce signatures that relying parties accept. Protect this
capability by loading only the key needed for the task, using keys with a short
lifetime, and enabling `ssh-add -c` confirmation or a hardware-backed key where
appropriate. A confirmation prompt is a control point, not a substitute for
reviewing which code receives agent access.

Without `--ssh-agent`, an in-Devbox agent cannot use the host agent. An agent
running directly on the host can normally use the same agent socket and, unlike
the Devbox agent, can also access other host files and authenticated tools that
the user account can reach.

## Persistent AI session state

Devbox mounts one owner-only host directory derived from the canonical project
path and links only the bundled agents' native transcript, index, attachment,
and session-worktree paths into it. It does not mount `~/.claude`, `~/.codex`,
the OpenCode data home, or another broad host configuration directory. Codex's
normal and proxy-specific homes share only their project session records, so
changing the authentication route does not expose or strand the transcript.
The CLI refuses to attach one project store to two differently named boxes at
the same time, avoiding concurrent SQLite/session writers across VMs.

This storage is data persistence, not a security sandbox. An agent can rewrite
its own saved transcript, and a resumed session can reintroduce old prompt
content, source snippets, paths, tool output, or malicious instructions. The
store can therefore act as a cross-lifecycle injection channel. Review a
session before resuming it when the previous VM processed untrusted input.

`devbox destroy` leaves this state intact by design. `devbox sessions path DIR`
shows the exact directory; `devbox sessions clear DIR` removes it after every
box mounting it has been destroyed. The clear command confirms interactively
unless `--yes` is supplied. `--ephemeral-sessions` leaves new transcript data
on the disposable guest disk; on an already-kept box it disconnects the native
agent paths and restarts once to remove the host mount completely.

## Credential proxy

`--proxy` is a **request capability** whose primary security goal is preventing
credential exfiltration. The guest is configured with a host proxy endpoint and
a per-box Devbox capability in place of provider API keys; the host proxy reads
or refreshes the real credentials and injects them per request. For the built-in Claude, Codex, and GitHub paths, the
guest does not receive an access or refresh token. The GitHub wrapper also
rejects guest-side token-changing `gh auth` commands. See the [proxy
design](../proxy/README.md).

For `gh`, the host proxy daemon renews short-lived capabilities directly for
host-registered running Lima boxes; it does not re-evaluate project manifests or
restart guests. `--gh-proxy` replaces Homebrew's public `gh` link with the wrapper
to prevent accidental direct execution, while retaining a private executable
copy for the wrapper itself. Because both remain executable by the guest user,
this routing measure does not stop deliberately hostile same-user code from
finding and invoking the private binary.

GitHub and traffic capabilities include a box identity and registration
generation. The proxy checks the current owner-only host record on every
request, so removing a grant invalidates copied tokens immediately. Open
tunnels recheck at least once per second. Kept boxes are stopped before approved
inputs are snapshotted, and removed host grants are revoked before the next boot.

The host records detailed authenticated-proxy request audits by default,
including prompts and GitHub mutation payloads. This helps attribute actions,
but creates a second sensitive host-local data store. Read [proxy audit
logging](proxy-audit.md) before using `--proxy` with secrets or confidential
source material.

Keeping a token out of the VM prevents a compromised guest from copying that
token elsewhere. It does not prevent that guest from asking the proxy to make
allowed API calls while the capability is active. Treat prompt text, source
code, files uploaded by a CLI, and remote mutations as data/actions the agent
may send or perform under the host account's provider permissions.

The host proxy is shared across Devboxes. It listens on host loopback by
default; Lima delivers guest connections to `host.lima.internal` there. AI
routes add host credentials only to requests that carry a registered per-box
capability (`dbx-ai.<box>.<secret>`, exported as the guest's
`ANTHROPIC_API_KEY`/`OPENAI_API_KEY`). The secret exists only in an owner-only
host file; destroying the box, `--no-auth`, or entering a kept box under a
policy without `ai_proxy` deletes it and revokes the capability. A configuration that sets `"listen"` beyond loopback or
`"ai_client_auth": "none"` widens this boundary; the proxy warns at startup.

Without `--proxy`, an in-Devbox agent has no Devbox-managed access to host AI
logins, and without `--gh-proxy` none to the host GitHub login. The two are
separate trust boundaries: proxying AI requests does not let the box act as the
host's GitHub identity. An agent running on the host can invoke the authenticated
host CLIs directly, inspect accessible credential configuration, and modify the
proxy's host-side configuration.

## Proxy-or-fail web traffic audit

`--traffic-audit=connect` is an explicit egress-control choice, not an implied
part of `--proxy` or `-a`. It gives the guest a separate, short-lived capability
to use the host proxy for public HTTP(S) destinations, exports the usual proxy
variables, and blocks direct TCP/UDP web ports in the guest. This makes normal
tools that ignore the proxy fail rather than silently bypassing the audit.

For an agent inside the Devbox, the practical effect is a broad ability to send
arbitrary public web requests through the host network; it does **not** expose
host provider tokens, and CONNECT does not decrypt HTTPS prompts, paths, or
bodies. A host agent can instead use any host browser, network client, local
service, and credential the user can access. Neither situation should be
treated as safe for untrusted code simply because its traffic is logged.

The guest firewall is not a security boundary against a malicious process with
guest root/sudo, which can remove it. Non-web traffic is also intentionally not
blocked. Use this feature as a proxy-or-fail workflow guard for ordinary
developer tooling; do not rely on it to contain hostile privileged code. The
generic proxy rejects loopback, private, and link-local destinations so this
capability cannot be used as a route to host or LAN web services. See [proxy
audit logging](proxy-audit.md) for the retained data and limitations.

## Combining capabilities

Capabilities compose. For example, `devbox --gui --policy agent` with
`egress = "audit"` in the policy grants non-secret agent
configuration, provider request capability, SSH-agent operations, host GUI
access, and generic proxy-or-fail web egress. A malicious project process can
use every enabled capability; granting one does not make the others safer.

The built-in `agent` policy (and the `-a` shorthand) is `agent_config`,
`ai_proxy`, and `ssh_agent` only; it grants AI requests but never the host
GitHub login. GUI forwarding is not a grant and must be added explicitly with
`--gui` or `-G`.

Avoid granting `ssh_agent`, `ai_proxy`, `github`, or using `--gui` for unknown
code unless you have consciously accepted their separate risks. For the
narrowest untrusted-code environment, begin with a new box:
`devbox --policy none --ephemeral-sessions` grants nothing and overrides any
project or machine-default grants. On a kept box it removes only the proxy,
API-key, and audited-egress state; SSH-agent forwarding, copied files and
credentials, and mounts stay until the box is destroyed, so destroy a box that
held them before reusing it for unknown code.

## Pre-accepted agent first-run prompts

Devbox answers the AI CLIs' own first-run gates for you, on every run:

| prompt | what Devbox writes |
|---|---|
| Claude Code onboarding | `hasCompletedOnboarding` in `~/.claude.json` |
| Claude Code folder trust | `projects."DIR".hasTrustDialogAccepted` |
| Claude Code custom API key | the approval for whatever `ANTHROPIC_API_KEY` the guest resolves |
| Codex folder trust | `[projects."DIR"] trust_level = "trusted"` in `$CODEX_HOME/config.toml` |
| Codex sign-in picker | an api-key-mode `auth.json` holding the value already exported as `OPENAI_API_KEY` (the box's proxy capability under `--proxy`) |

The reasoning is that these dialogs ask a question the operator has already
answered. Choosing to start a Devbox for a directory *is* the decision to run an
agent against that directory, and the VM — not a confirmation inside the agent —
is what bounds the result. Asking twice trains people to hit "yes" without
reading, which makes the prompt worth less everywhere it does matter.

The seeding is scoped to the single mounted project directory. It never trusts
`$HOME`, and never the extra paths added with `--mount`, which default to
read-only. Codex answers already on record are left as they are, so an explicit
`trust_level = "untrusted"` copied in with `--with-agent-config` still stands.
A real `auth.json` copied in with `--with-creds` is never overwritten.

What you give up: Claude Code's folder-trust dialog is also what gates a
repository's own `.claude/settings.json` and hooks from executing. With trust
pre-accepted, a hostile repository's hooks run when the agent starts, without a
prompt. That is the intended trade for a disposable VM whose contents you are
willing to lose, with one caveat worth naming: the box is disposable but the
[session store](#persistent-ai-session-state) is not, so anything that reaches a
transcript outlives the clone. Use `--ephemeral-sessions` for a repository you
would not want resumed. It is *not* a reason to relax the guidance below. Treat
the `ssh_agent`, `ai_proxy`, and `github` grants, `--gui`, and extra writable mounts as the controls
that actually matter, because none of them are gated by an agent-side dialog
either.

## Reviewing repository-controlled requests

A project can request startup commands, resource settings, provisioning, and —
through a `policy` and a `[grants]` table — host grants such as the AI and
GitHub proxies, the SSH agent, mounts, copies, and credentials, all through
`.devbox.toml`; Devbox presents those
requests in a categorized, icon-labelled review before approval. It can also
send the manifest to Codex, Claude, Agy, Copilot, Cursor, OpenCode, or Pi for an
optional summary and safety check; Codex is the default choice. Each adapter is
non-interactive, uses the CLI's native plan/read-only or no-tool controls, and
is instructed to treat the manifest as untrusted data rather than executable
instructions. It runs from an isolated empty working directory. Codex also uses
an ephemeral session with local configuration and exec-policy rules ignored;
other CLIs retain their normal provider-side and host-side session behavior.
The manifest contents still leave the machine for the service configured for
the selected CLI, and the result does not replace your own decision.

Repository manifests cannot select local Lima YAML configurations. Those files
are full host-side Lima configuration rather than ordinary guest images, so a
path-only manifest review cannot safely authorize their transitive settings.
They remain available as an explicit `--image PATH` choice for trusted host
configuration; manifests may select templates or raw disk-image files.

An explicit approval is stored as owner-only user state and reused only while
both the manifest's exact SHA-256 fingerprint and the fingerprint of its
resolved meaning are unchanged — symlinked host paths, effective defaults, the
machine-default policy, and any host policy file it names. Devbox asks again
after any such change, and rechecks both before host-affecting steps and before
executing manifest packages or startup code. Read the prompt and decline anything unexpected. The manifest
cannot enable GUI forwarding, but background processes started in a GUI-enabled
Devbox should still be treated as able to use the capabilities you selected.

## Operational checklist

1. Start with no optional capability (`--policy none`); add only the grant
   required for the task.
2. For `ssh_agent`, load only a restricted key and use confirmation or a
   short key lifetime where practical.
3. For `ai_proxy` and `github`, trust the code that can send requests, and keep the host
   listener on loopback (the default).
4. For `--gui`, trust the application with host-desktop access; see the
   [GUI forwarding security guide](gui-security.md).
5. Remove a capability when finished: exit and destroy the disposable box, or
   re-enter a kept box under a policy without it (e.g. `--policy none`), which
   removes proxy state, API-key profiles, and audited-egress rules it lacks.
6. Treat resumed transcripts as untrusted input when the previous session read
   untrusted material. Use `--ephemeral-sessions` or `devbox sessions clear`
   when cross-lifecycle state is not appropriate.
