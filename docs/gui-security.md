# GUI forwarding security

`devbox gui`, `devbox --gui`, and `-G` let Wayland applications in a Devbox
appear in the host Wayland session. They are designed for trusted development
work, not for safely running untrusted projects or applications. GUI forwarding
is always explicit: `-a` does not enable it.

For the separate SSH-agent and credential-proxy capabilities available to an
agent in a Devbox, see [agent capability security](agent-capabilities-security.md).

## Security position

GUI forwarding deliberately creates a capability from the guest to the host
desktop. A forwarded application becomes a Wayland client of the host
compositor, with whichever protocol permissions that compositor grants to its
clients. Treat a GUI-enabled Devbox as trusted code with a VM boundary around
its filesystem and processes—not as a boundary around the host desktop.

Waypipe documents that it provides no strong security guarantees for untrusted
peers. In particular, it generally forwards compositor protocols without
filtering them, which can expose screenshot or lock-screen capabilities if the
host compositor exposes those capabilities to ordinary clients. It can also
carry denial-of-service attacks and implementation vulnerabilities between a
client and compositor. See Waypipe's
[security documentation](https://man.archlinux.org/man/extra/waypipe/waypipe.1.en#SECURITY).

## What Devbox protects

- The host Wayland socket is **not** mounted into the guest.
- The host does not pass DRM or render-device nodes to the guest.
- Waypipe runs over Lima's per-instance SSH transport; there is no separate
  unauthenticated network listener.
- Devbox passes Waypipe `--no-gpu`, which disables Wayland protocols that need
  GPU render-node access.
- GUI commands and their working directories are shell-quoted before running
  in the guest.
- `.devbox.toml` has no `gui` option. A repository cannot enable GUI forwarding
  merely by being opened; the operator must choose a GUI CLI flag.

These controls avoid exposing the raw host socket and GPU devices. They do not
make a forwarded GUI client harmless.

## Risks to account for

### Host desktop authority

A GUI app from the Devbox can create convincing windows, dialogs, and clipboard
offers. Depending on the compositor and enabled protocols, it may gain further
desktop capabilities such as screen capture. Do not use GUI forwarding for
unknown software, unreviewed projects, or code you would not run as a normal
local desktop application.

Waypipe uses Unix sockets on the guest for the forwarded display. Other code
running as the same guest user should be considered capable of attempting to
use that display. This matters for project startup commands or background
processes: once you open a GUI-enabled shell, treat all code in that Devbox as
having access to the forwarded-desktop capability.

### The `-a` preset

`-a` expands to `--with-agent-config --proxy --ssh-agent`. It does not enable
`--with-creds` or GUI forwarding, so it neither copies AI OAuth files into the
guest nor creates a host-GUI path. Add `--gui` or `-G` separately only when you
intend to grant that capability, for example `devbox --gui -a`.

### Existing Devboxes and package installation

New golden images include guest-side Waypipe. For an older existing Devbox,
the first GUI launch runs the guest's supported package manager with `sudo` to
install `waypipe`. That is a normal guest-package supply-chain decision: use
updated, trusted guest package repositories and do not enable GUI forwarding in
a guest whose package configuration you do not trust.

### Availability and data exposure

A malicious GUI client can consume host compositor resources or crash its
connection. Waypipe also warns that its process memory can hold proxied input
and current/recent frame data; encrypted swap reduces the risk of that data
being written to disk. SSH protects message contents in transit, but Waypipe
notes that traffic size and timing can still reveal interaction patterns.

## Safe operating guidance

1. Use `devbox --gui` or `-G` only for trusted project code and applications.
   If you would not run an application directly on the host, do not forward its
   GUI into the host session.
2. Inspect a repository's `.devbox.toml` before approving its requested startup
   command, mounts, copies, or provisioning. Decline the prompt if it asks for
   access you do not intend to grant.
3. Prefer the smallest set of flags. GUI forwarding is always opt-in; omit
   `--gui`/`-G` unless it is required. Omit `-a` when proxy access or
   SSH-agent forwarding is not required.
4. Keep the host and guest Waypipe packages updated. Use an ordinary package
   source you trust for an older Devbox's first-time installation.
5. End the GUI shell or app when finished. Unless `--keep` is set, Devbox then
   removes the disposable instance; use `devbox destroy NAME` to remove a kept
   instance.
6. For genuinely untrusted GUI software, use a separate disposable host user
   session or a purpose-built sandbox. Devbox GUI forwarding is not that
   sandbox.

## Implementation reference

The implementation checks for an active host Wayland socket and host Waypipe,
starts the remote Waypipe server over Lima SSH, and invokes it with `--no-gpu`.
The relevant code is in [`bin/devbox`](../bin/devbox), under `GUI / Waypipe`.
