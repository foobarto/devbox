#!/usr/bin/env bash
#
# Destructive, host-integrated Devbox verification. It intentionally creates
# and removes real Lima instances, calls the configured Claude/Codex OAuth
# proxy, and (when explicitly enabled) copies the local AI credentials into a
# disposable VM. Nothing runs unless the caller opts in.
#
#   DEVBOX_E2E=1 DEVBOX_E2E_WITH_CREDS=1 test/e2e.sh
#
set -euo pipefail

[[ "${DEVBOX_E2E:-}" == 1 ]] || {
  echo "set DEVBOX_E2E=1 to run destructive integration tests" >&2
  exit 2
}
[[ "${DEVBOX_E2E_WITH_CREDS:-}" == 1 ]] || {
  echo "set DEVBOX_E2E_WITH_CREDS=1 to test --with-creds in a disposable VM" >&2
  exit 2
}

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
DEVBOX_BIN="${DEVBOX_BIN:-$ROOT/bin/devbox}"
PROJECT_ROOT="$(mktemp -d "${TMPDIR:-/var/tmp}/devbox-e2e.XXXXXX")"
MANIFEST_PROJECT="$PROJECT_ROOT/manifest-project"
MOUNT_SOURCE="$PROJECT_ROOT/mount-source"
COPY_SOURCE="$PROJECT_ROOT/copy-source.txt"
KEY_FILE="$PROJECT_ROOT/api-keys.env"
export DEVBOX_E2E_PTY_LOG="$PROJECT_ROOT/pty-transcript.log"

need() { command -v "$1" >/dev/null 2>&1 || { echo "missing required command: $1" >&2; exit 1; }; }
need limactl
need python3
need ssh-add
need ssh-keygen
need git

manifest_name() {
  bash -c 'source "$1"; instance_name ubuntu-24.04 "$2"' _ "$DEVBOX_BIN" "$1"
}

destroy_project_box() {
  local project="$1" name
  name="$(manifest_name "$project")"
  "$DEVBOX_BIN" destroy "$name" >/dev/null 2>&1 || true
}

cleanup() {
  destroy_project_box "$MANIFEST_PROJECT"
  [[ "${DEVBOX_E2E_KEEP_ARTIFACTS:-}" == 1 ]] || rm -rf "$PROJECT_ROOT"
}
trap cleanup EXIT INT TERM

# Execute Devbox in a pty so the manifest consent gate gets an actual terminal.
# For accepted sessions we send `exit` only after Devbox has finished setup and
# announced its shell. A declined manifest must exit non-zero before any VM is
# touched.
run_session() { # $1 approve|decline; remaining arguments are the devbox argv
  local mode="$1"
  shift
  python3 - "$mode" "$@" <<'PY'
import os
import pty
import select
import sys
import time

mode, *argv = sys.argv[1:]
pid, fd = pty.fork()
if pid == 0:
    os.execvp(argv[0], argv)

deadline = time.monotonic() + 600
transcript = bytearray()
sent_approval = False
sent_exit = False
status = None
while time.monotonic() < deadline:
    ready, _, _ = select.select([fd], [], [], 0.2)
    if ready:
        try:
            data = os.read(fd, 65536)
        except OSError:
            data = b""
        if data:
            transcript.extend(data)
    view = bytes(transcript)
    if not sent_approval and b"Do you agree? [y/N]" in view:
        os.write(fd, b"y\n" if mode == "approve" else b"n\n")
        sent_approval = True
    if mode == "approve" and not sent_exit and b"Entering " in view:
        os.write(fd, b"exit\n")
        sent_exit = True
    done, child_status = os.waitpid(pid, os.WNOHANG)
    if done:
        status = child_status
        break
else:
    os.kill(pid, 15)
    _, status = os.waitpid(pid, 0)
    print("devbox session timed out", file=sys.stderr)
    sys.exit(1)

text = transcript.decode("utf-8", "replace")
log_path = os.environ.get("DEVBOX_E2E_PTY_LOG")
if log_path:
    with open(log_path, "wb") as log:
        log.write(transcript)
if mode == "approve":
    expected = sent_exit and os.WIFEXITED(status) and os.WEXITSTATUS(status) == 0
else:
    expected = sent_approval and os.WIFEXITED(status) and os.WEXITSTATUS(status) != 0
if not expected:
    print(text, file=sys.stderr)
    sys.exit(1)
PY
}

assert_guest() { # $1 instance $2 guest command
  limactl shell "$1" -- bash -lc "$2"
}

mkdir -p "$MANIFEST_PROJECT" "$MOUNT_SOURCE"
printf 'mounted-data\n' > "$MOUNT_SOURCE/readable.txt"
printf 'copied-data\n' > "$COPY_SOURCE"
printf 'DEVBOX_E2E_API_KEY=non-secret-e2e-value\n' > "$KEY_FILE"

python3 - "$MANIFEST_PROJECT/.devbox.toml" "$MOUNT_SOURCE" "$COPY_SOURCE" <<'PY'
import json
import pathlib
import sys

path, mount_source, copy_source = map(pathlib.Path, sys.argv[1:])
steps = (
    ("ssh-socket", 'test -S "$SSH_AUTH_SOCK"'),
    ("ssh-agent", "ssh-add -l >/dev/null"),
    ("anthropic-proxy", 'test "$ANTHROPIC_BASE_URL" = "http://host.lima.internal:4141"'),
    ("openai-proxy", 'test "$OPENAI_BASE_URL" = "http://host.lima.internal:4141/v1"'),
    ("signing-key", 'test -f "$HOME/.devbox/git-signing-key.pub"'),
    ("mount", f'test -r {json.dumps(str(mount_source / "readable.txt"))}'),
    ("copy", 'test "$(tr -d \'\\n\' < \"$HOME/e2e-copy.txt\")" = copied-data'),
    ("package", "brew list --versions hello >/dev/null"),
    ("git-init", "git init -q ."),
    ("git-content", "printf signed > signature-proof.txt"),
    ("git-add", "git add signature-proof.txt"),
    ("git-commit", 'git commit --allow-empty -qm "Devbox E2E signature"'),
    ("git-verify", 'test "$(git log -1 --format=%G?)" = G'),
    ("claude-oauth", 'test -f .e2e-oauth-complete || timeout 120 claude -p "Reply exactly: claude-e2e-ok" > .claude-e2e-output'),
    ("codex-oauth", 'test -f .e2e-oauth-complete || timeout 120 codex exec "Reply exactly: codex-e2e-ok" > .codex-e2e-output'),
    ("claude-output", "test -s .claude-e2e-output"),
    ("codex-output", "test -s .codex-e2e-output"),
    ("oauth-complete", "touch .e2e-oauth-complete"),
)
start_parts = ["set -eu"]
for label, command in steps:
    start_parts.extend((f"printf {label} > .e2e-stage", command))
start_parts.append("printf manifest-started > .e2e-started")
start = "; ".join(start_parts)
path.write_text(
    "\n".join((
        'image = "ubuntu-24.04"',
        'packages = ["hello"]',
        f"start = {json.dumps(start)}",
        "ssh_agent = true",
        "keep = true",
        "proxy = true",
        f"mounts = [{json.dumps(str(mount_source) + ':ro')}]",
        f"copies = [{json.dumps(str(copy_source) + ':e2e-copy.txt')}]",
        "",
    ))
)
PY

echo "[e2e] reject manifest consent without creating a VM"
manifest_instance="$(manifest_name "$MANIFEST_PROJECT")"
run_session decline "$DEVBOX_BIN" "$MANIFEST_PROJECT"
if limactl list -q | grep -Fxq "$manifest_instance"; then
  echo "declined manifest created an instance unexpectedly" >&2
  exit 1
fi

echo "[e2e] manifest approval, image, package, start, mount, copy, SSH signing, and OAuth proxy"
run_session approve "$DEVBOX_BIN" "$MANIFEST_PROJECT"
limactl list -q | grep -Fxq "$manifest_instance"
test -f "$MANIFEST_PROJECT/.e2e-started"
test -s "$MANIFEST_PROJECT/.claude-e2e-output"
test -s "$MANIFEST_PROJECT/.codex-e2e-output"
git -C "$MANIFEST_PROJECT" cat-file -p HEAD | grep -q '^gpgsig -----BEGIN SSH SIGNATURE-----'
curl -fsS http://127.0.0.1:4141/_devbox | grep -q devbox-ai-proxy

echo "[e2e] API keys and --with-creds on the same retained, disposable VM"
run_session approve "$DEVBOX_BIN" "$MANIFEST_PROJECT" --api-keys="$KEY_FILE"
assert_guest "$manifest_instance" 'test -f /etc/profile.d/zz-devbox-10-proxy.sh; test -f /etc/profile.d/zz-devbox-11-codex-proxy.sh; test -f /etc/profile.d/zz-devbox-20-keys.sh; grep -q DEVBOX_E2E_API_KEY /etc/profile.d/zz-devbox-20-keys.sh'

run_session approve "$DEVBOX_BIN" "$MANIFEST_PROJECT" --with-creds
# shellcheck disable=SC2016 # $HOME expands inside the guest shell.
assert_guest "$manifest_instance" 'test -f "$HOME/.claude/.credentials.json"'

echo "[e2e] --no-auth removes every Devbox-managed auth profile"
run_session approve "$DEVBOX_BIN" "$MANIFEST_PROJECT" --no-auth
# shellcheck disable=SC2016 # $HOME expands inside the guest shell.
assert_guest "$manifest_instance" 'test ! -e /etc/profile.d/zz-devbox-10-proxy.sh; test ! -e /etc/profile.d/zz-devbox-11-codex-proxy.sh; test ! -e /etc/profile.d/zz-devbox-20-keys.sh; test ! -d "$HOME/.devbox/codex-proxy"'
destroy_project_box "$MANIFEST_PROJECT"
if limactl list -q | grep -Fxq "$manifest_instance"; then
  echo "manifest instance survived explicit cleanup" >&2
  exit 1
fi

echo "[e2e] PASS"
