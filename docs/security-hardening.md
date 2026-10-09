# Security hardening and upgrade compatibility

Golden names use a 64-bit SHA-256 suffix for customized specifications, short
enough for Lima's socket paths. Names alone never authorize reuse: owner-only metadata must match the full
image location, digest, root/user provisioning, and bootstrap schema. Metadata
is written only after toolchain verification and shutdown. Legacy goldens have
no verified record and must be rebuilt with `devbox build --force`; customized
goldens use their new specification names.

Existing project VMs require an owner-only project association before Devbox
changes sessions, forwarding, profiles, or grants. For a previously created
kept VM, verify its writable project mount and explicitly run
`devbox adopt NAME DIR`. Adoption validates that mount and records the
association; it never boots or reconfigures the VM. Recreating the VM is also
supported. Re-entering a running kept VM attaches to it; Devbox restarts it
only to remove SSH-agent forwarding its policy no longer grants, which Lima
applies at boot. Removed proxy grants are revoked live.

A writable mount — the project directory or an extra `:rw` mount — may not be,
or contain, the home directory or Devbox's own state (configuration, proxy
state, approvals, and session storage): a guest able to write there could forge
identity records and grants. Mount a project subdirectory instead. An extra
mount below a directory that this or another Lima instance mounts writable is
refused as well; a writable mount that no longer exists, or is reached through
a symlink, is resolved or ignored rather than blocking every run.

Host grant transfers use private descriptor-based snapshots and schema-based
configuration exports. Operator-named sources (copies, the API-key file,
credential and settings files) are resolved once, so links from dotfile
managers work; the snapshot then walks the resolved path without following
links. Sources at or below a writable mount of another stored Lima instance
are refused, since that guest controls their content. The host
must keep external host processes that can replace mount ancestry trusted:
Lima accepts paths rather than immutable object descriptors. See
[capability boundaries](agent-capabilities-security.md) for the remaining
mount timing limitation and raw-copy authorization requirements.

GitHub and traffic tokens use live per-box generations. Old stateless tokens
stop working after the proxy upgrades; re-enter an explicitly registered box
to deliver replacements. Destroying a box or removing its grant revokes copied
capabilities, and active tunnels close on their next check. Replacing the
guest traffic firewall uses a checked atomic nftables transaction, preserving
the old rules on failure. A root-owned boot policy runs before supported
systemd network services, so restarting the guest cannot clear the guard.
A running legacy audited guest receives that boot policy in place when it is
re-entered. A stopped legacy audited guest without a verified boot policy is refused;
recreate it rather than booting with a gap in enforcement. Audited egress
requires systemd and a recognized network service in the guest.

The proxy bounds threads, sockets, and buffered bodies globally and per box;
chunked bodies are charged incrementally. It also bounds stream lifetimes, audit
storage, and rejected-client logging. Enabled audits commit an opening event
before forwarding and fail closed when storage is unavailable. IPv6 authority
formatting and credential-key normalization preserve audit coverage. Defaults
and operator controls are documented in the [proxy guide](../proxy/README.md)
and [audit guide](proxy-audit.md).

The Homebrew bootstrap script uses an immutable upstream commit and an embedded
SHA-256 check. Tool installation uses checksum-verifying package managers;
mutable shell-installer and unversioned Go fallbacks are removed. This verifies
artifacts while allowing package-manager updates; it is not a lockfile for the
entire golden toolchain. Change the bootstrap identity schema when adopting a
different bootstrap policy so older goldens cannot silently satisfy it.

Website version automation creates a unique branch per run, checks the PR's
repository, ref, base, changed file, and exact head SHA, and merges with that
head as a precondition. A branch update after inspection cannot substitute a
different commit at merge time.
