# Grant policies

A Devbox starts with nothing from the host beyond its project mount and its
persistent AI session store. Everything else it may use from the host — the
host's AI logins, its GitHub login, the SSH agent, agent configuration, API
keys, copied credentials, extra mounts and copies, and audited web egress — is a
**grant**. A **policy** is a named set of grants. The grants in effect for a box
come from exactly one place per run, so a box's host access can be read from
one declaration instead of reconstructed from flags.

## Grants

| grant | value | gives the box | replaces |
|---|---|---|---|
| `ai_proxy` | `true` or proxy URL | the host's AI-provider logins through the credential proxy; the box holds only a revocable per-box capability | `--proxy`, manifest `proxy` |
| `github` | `true` or proxy URL | the host's GitHub login for `gh` through the proxy | `--gh-proxy`, manifest `gh_proxy` |
| `ssh_agent` | `true` | requests to the host SSH agent, and SSH-signed commits | `--ssh-agent`, manifest `ssh_agent` |
| `agent_config` | `true` | explicit safe setting fields and values from Claude/Codex/OpenCode structured configuration; free-form and unknown content excluded | `--with-agent-config`, manifest `with_agent_config` |
| `api_keys` | `true` or env-file path | the keys in that file, copied into the box | `--api-keys`, manifest `api_keys` |
| `host_credentials` | `true` | copies of the host AI CLIs' credential files | `--with-creds`, manifest `with_creds` |
| `egress` | `"open"`, `"audit"` or `"inspect"` | `"audit"`: ordinary web traffic only through the audited proxy; `"inspect"`: also decrypted and classified per request ([inspect proxy](inspect-proxy.md)) | `--traffic-audit[=inspect]` |
| `mounts` | list of `PATH[:ro\|:rw]` | those host paths, mounted at creation | manifest `mounts` |
| `copies` | list of `SRC[:DEST]` | copies of those host files and directories | manifest `copies` |

`ai_proxy` and `github` are separate on purpose: proxying AI requests never lets
a box act as the host's GitHub identity.

## Policies

Three policies are built in:

| policy | grants |
|---|---|
| `none` | nothing |
| `agent` | `agent_config`, `ai_proxy`, `ssh_agent` (the set `-a` adds) |
| `agent-github` | `agent` plus `github` |

A host-defined policy is a file `~/.config/devbox/policies/NAME.toml` (under
`$DEVBOX_CONFIG_DIR` when set) holding a `[grants]` table. It takes precedence
over a built-in policy of the same name; a policy file that is a dangling link is
an error rather than a fall-back to the built-in. Relative paths in it resolve
from the directory of the policy file, after following a symlink to it.

```toml
# ~/.config/devbox/policies/review.toml
[grants]
ai_proxy = true
egress = "audit"
mounts = ["~/reference-data:ro"]
```

`devbox policy list` shows the available policies; `devbox policy show NAME`
prints the grants one resolves to.

## Choosing the grants for a run

The first of these that applies decides the grants for the run:

1. `devbox --policy NAME` (`-P NAME`). An explicit command-line choice wins over
   the project.
2. The project's `.devbox.toml`: a base — its own `policy = "NAME"`, or else the
   machine default — then its `[grants]` table, whose keys replace the base's.
   A manifest still using the old top-level grant keys takes exactly those
   grants instead, and no policy is in effect for it.
3. The machine default alone, a top-level `policy = "NAME"` in
   `~/.config/devbox/config.toml`, when there is no manifest.
4. Nothing: no grants.

`egress = "audit"` or `"inspect"` in the machine default is a restriction a
project cannot lift: every manifest keeps at least that egress under such a
default, whatever policy, `[grants]`, or legacy keys it declares. A manifest may
tighten `audit` to `inspect`. The operator's own `--policy` is not bound by it.

```toml
# .devbox.toml
policy = "agent"

[grants]
egress = "audit"
mounts = ["./fixtures:ro"]
```

A repository's manifest is untrusted input, so naming a policy in it is a
request like any other: the approval prompt lists the policy (or the machine
default it builds on) and every grant the combination expands to, and the cached
approval covers that expansion. Editing a host policy file or the machine
default that a manifest builds on therefore asks for approval again.

`--mount` and `--copy` remain available for one-off additions and are added to
the chosen grants.

## A kept box follows its policy

While a policy is in effect (cases 1–3 above), a kept box is brought in line
with it on every entry: a grant the policy no longer contains is removed. That
covers the AI and GitHub proxy wiring (and revokes the box's capability), the
audited-egress firewall rule, and the copied API-key profile. Devbox also forces
SSH-agent forwarding off when the current grants omit `ssh_agent` and either a
policy is in effect or the kept box uses a repository-selected Lima template; a
running box is restarted for this. This migrates boxes made by versions that
could inherit forwarding from that template. Files already
copied in (agent configuration, credentials, `copies`) and mounts fixed at
creation cannot be withdrawn this way. Without a policy, a legacy box whose
base was selected only with CLI flags keeps SSH-agent forwarding until it is
recreated.

Without any policy in effect, Devbox keeps its earlier behaviour: grants are
added by flags and a kept box retains what it was given until `--no-auth` or
`--gh-proxy=off` removes it.

## Compatibility

The per-grant flags (`--proxy`, `--gh-proxy`, `--ssh-agent`,
`--with-agent-config`, `--api-keys`, `--with-creds`, `--traffic-audit`,
`--no-auth`) and the `-a` bundle still work, with a deprecation notice pointing
at `[grants]` and `--policy` (`--no-auth` and a manifest's `no_auth = true` remain
accepted alongside policies). They add to the run's grants; `--no-auth`,
`--gh-proxy=off`, and `--traffic-audit=off` remove the corresponding ones. Unlike
`--policy agent`, which replaces the project's grants and brings a kept box in
line, `-a` only adds agent configuration, the AI proxy, and the SSH agent. The old top-level manifest keys
(`proxy`, `gh_proxy`, `ssh_agent`, `with_agent_config`, `api_keys`, `with_creds`,
`mounts`, `copies`) are still read, with the same notice; a manifest cannot mix
them with `policy` or `[grants]`.
