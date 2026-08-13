# Agent capability security

This document describes the security boundary for a coding agent or any other
process running **inside a Devbox**. It is not the same as running that agent on
the host: the VM restricts filesystem and process access, but each opt-in
Devbox feature grants a specific host-backed capability.

Use these features for code you trust. A compromised or malicious in-VM agent
can exercise every capability you grant it, even when it cannot extract the
underlying host credential.

For `--proxy`, preventing credential exfiltration is the primary security goal:
the guest never receives the host's real API keys or OAuth tokens. The proxy is
not, by itself, a least-authority policy for requests made while the Devbox is
allowed to use it.

## Baseline: Devbox agent versus host agent

| capability | agent inside a default Devbox | same agent on the host |
|---|---|---|
| Files and processes | Sees the mounted project and guest filesystem/processes, plus only explicitly mounted or copied host paths. It cannot read the rest of the host home directory or control host processes. | Can read and modify every file and process the host user is permitted to access, including local tool configuration and authentication state. |
| Host credentials | Receives none by default. | Can read, copy, or invoke credentials and authenticated CLIs available to the host user. |
| Desktop session | No access to the host Wayland socket or GPU nodes. | Can use the host desktop session and any local desktop capabilities available to the user. |
| Network and remote services | Has normal guest networking and can use only credentials/capabilities explicitly provided to it. | Can use host network configuration, authenticated clients, and any credentials available to the host user. |

The project directory is mounted read-write by default. Isolation does not stop
an agent from changing the project or sending its contents to a network service
that it is authorized to use.

## Capability matrix

| feature | what an agent in the Devbox can do | what remains outside the Devbox |
|---|---|---|
| `--ssh-agent` / `-s` | Request authentication and signatures using identities currently loaded in the host SSH agent. This includes SSH/Git access accepted by those identities and Devbox's SSH-format Git commit signing. | It cannot read or copy the private-key material from the agent. It does not gain access to unmounted host files or a host shell. |
| `--proxy` / `-p` | Make requests through Devbox's configured AI and GitHub routes using the host account's authentication. It can consume quotas and create, read, modify, or upload remote data to the extent the authenticated provider account permits. | It does not receive the underlying API keys, OAuth tokens, or host `gh` token. The guest runs its own CLIs; it cannot run host commands through the proxy. |
| `--traffic-audit` / `-T` | Send proxy-aware public web traffic through a short-lived generic CONNECT capability. Direct TCP/UDP 80/443 fails under the guest firewall; CONNECT audit records reveal destination, timing, and byte counts, while plaintext HTTP can be recorded in detail. | It grants no AI, GitHub, SSH, or host-login credential. HTTPS remains encrypted after CONNECT, and non-web ports remain outside the rule. The generic proxy refuses host/private/LAN destinations. |
| `--gui` / `-G` | Become a Wayland client of the host session through Waypipe. | It does not receive the raw host Wayland socket or host GPU/render-device nodes. This is still a host-desktop capability, not an isolation boundary; see [GUI forwarding security](gui-security.md). |
| `--with-agent-config` / `-g` | Read selected non-secret rules, prompts, settings, and custom agents copied into the guest. Those instructions can affect agent behavior. | Authentication state, histories, caches, key directories, and files detected as credentials are excluded. |
| `--api-keys` / `-K` or `--with-creds` / `-c` | Read actual keys or copied OAuth credentials in the guest. | These deliberately weaken the host-only credential boundary. Prefer `--proxy` when the provider workflow supports it. |

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

## Credential proxy

`--proxy` is a **request capability** whose primary security goal is preventing
credential exfiltration. The guest is configured with routing markers and a
host proxy endpoint; the host proxy reads or refreshes the real credentials and
injects them per request. For the built-in Claude, Codex, and GitHub paths, the
guest does not receive an access or refresh token. The GitHub wrapper also
rejects guest-side token-changing `gh auth` commands. See the [proxy
design](../proxy/README.md).

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

The host proxy is shared across Devboxes. Its default listener is reachable by
guests through Lima's host gateway and may bind broadly so that routing works.
Use a host firewall or a narrower configured `listen` interface when the host
network is not fully trusted. Do not expose the proxy to untrusted networks.

Without `--proxy`, an in-Devbox agent has no Devbox-managed access to host AI
or GitHub credentials. An agent running on the host can invoke the authenticated
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

Capabilities compose. For example, `devbox --gui -a -T` grants non-secret agent
configuration, provider request capability, SSH-agent operations, host GUI
access, and generic proxy-or-fail web egress. A malicious project process can
use every enabled capability; granting one does not make the others safer.

`-a` intentionally remains `--with-agent-config --proxy --ssh-agent` only.
GUI forwarding must be added explicitly with `--gui` or `-G`.

Avoid using `-a`, `--ssh-agent`, `--proxy`, or `--gui` for unknown code unless
you have consciously accepted their separate risks. For the narrowest
untrusted-code environment, begin with `devbox --no-auth` and no extra mounts,
copies, agent forwarding, proxy, or GUI forwarding.

## Reviewing repository-controlled requests

A project can request startup commands, mounts, copies, credentials, resource
settings, and provisioning through `.devbox.toml`; Devbox presents those
host-affecting requests for approval. Read that prompt and decline anything
unexpected. The manifest cannot enable GUI forwarding, but background processes
started in a GUI-enabled Devbox should still be treated as able to use the
capabilities you selected.

## Operational checklist

1. Start with no optional capability; add only the one required for the task.
2. For `--ssh-agent`, load only a restricted key and use confirmation or a
   short key lifetime where practical.
3. For `--proxy`, trust the code that can send requests and firewall the host
   listener to the intended guest/network boundary.
4. For `--gui`, trust the application with host-desktop access; see the
   [GUI forwarding security guide](gui-security.md).
5. Remove a capability when finished: exit and destroy the disposable box, or
   re-enter a kept box with `--no-auth` to remove credential-proxy state and
   `--traffic-audit=off` to remove proxy-or-fail traffic auditing.
