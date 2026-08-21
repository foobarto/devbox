#!/usr/bin/env bats
#
# Unit tests for devbox's pure logic (name derivation, image-stanza + golden
# YAML generation, dispatch). No VM is spun up. Run with:  bats test/
#
# Prereq: bats-core (brew install bats-core). limactl-dependent tests skip
# automatically when limactl is absent.

setup() {
  DEVBOX="${BATS_TEST_DIRNAME}/../bin/devbox"
  # sourceable: dispatch is guarded, so this loads functions only.
  source "$DEVBOX"
  # Relax only nounset: test bodies reference optional vars. errexit MUST stay
  # on — bats detects a failing assertion via errexit, so `set +e` here silently
  # turns the whole suite green regardless of what it asserts.
  set +u
}

# Permission bits, portably: BSD stat (macOS) spells the mode %Lp, and its %a is
# the access time — so the GNU format cannot simply be reused. GNU goes first:
# BSD stat rejects `-c` cleanly, while GNU stat reads `-f` as --file-system and
# prints a filesystem-info block to stdout before failing on the format operand.
file_mode() { # $1 path
  stat -c %a "$1" 2>/dev/null || stat -f %Lp "$1" 2>/dev/null
}

# Resolve a golden the way Lima does at create/boot time: emit the yaml, then
# merge its base-template chain with `tmpl copy --fill`. Assertions on the
# RESOLVED config — the config Lima actually boots — catch fields the merge
# silently rewrites, which grepping our own emitted text never can. The
# canonical trap is mounts: an empty `mounts: []` reads as "unset" during the
# merge and the golden re-inherits template:_default's ~ mount.
#
# Call require_resolver() DIRECTLY in the test body first: `skip` cannot fire
# from inside the `$(resolved_golden …)` subshell, so the gate must run in the
# test's own shell before the substitution.
require_resolver() {
  command -v limactl >/dev/null 2>&1 || skip "limactl required to resolve the template chain"
  python3 -c 'import yaml' 2>/dev/null || skip "PyYAML required to read the resolved config"
}
resolved_golden() { # $1 image  $2.. optional emit args (cpus memory disk …)
  local image="$1"; shift
  local raw="$BATS_TEST_TMPDIR/golden-raw.yaml"
  emit_golden_yaml "$image" "$raw" "$@"
  limactl tmpl copy --fill "$raw" - 2>/dev/null
}
# Mount locations from a resolved config on stdin, one per line. Reads the
# `mounts:` list structurally so it never picks up a stray `location:` under
# `images:`.
mount_locations() {
  python3 -c 'import yaml,sys; print("\n".join(m.get("location","") for m in (yaml.safe_load(sys.stdin).get("mounts") or [])))'
}
# A dotted scalar (e.g. ssh.forwardAgent) from a resolved config on stdin.
yaml_get() { # $1 dotted.path
  python3 -c '
import yaml, sys
d = yaml.safe_load(sys.stdin)
for k in sys.argv[1].split("."):
    d = d.get(k) if isinstance(d, dict) else None
print("" if d is None else d)' "$1"
}

# ------------------------------------------------------------------ _slug ----
@test "_slug lowercases, replaces non-alnum, collapses and trims" {
  run _slug "Hello  World!!" 30
  [ "$status" -eq 0 ]
  [ "$output" = "hello-world" ]
}

@test "_slug caps length" {
  run _slug "abcdefghijklmnop" 5
  [ "$output" = "abcde" ]
}

@test "_slug falls back to x on empty result" {
  run _slug "!!!" 30
  [ "$output" = "x" ]
}

# ---------------------------------------------------------------- imgslug ----
@test "imgslug of a template name is a clean slug (no hash)" {
  run imgslug ubuntu-24.04
  [ "$output" = "ubuntu-24-04" ]
}

@test "imgslug of a path gets a deterministic hash suffix" {
  run imgslug /images/kali.qcow2
  [ "$status" -eq 0 ]
  [[ "$output" =~ ^kali-qcow2-[0-9a-f]{6}$ ]]
  # deterministic
  run imgslug /images/kali.qcow2
  [[ "$output" =~ ^kali-qcow2-[0-9a-f]{6}$ ]]
}

# ------------------------------------------------------------- golden_name ----
@test "golden_name format" {
  run golden_name ubuntu-24.04
  [ "$output" = "devbox-golden-ubuntu-24-04" ]
}

# ----------------------------------------------------------- instance_name ----
@test "instance_name is deterministic for the same (image, dir)" {
  a="$(instance_name ubuntu-24.04 /home/u/proj)"
  b="$(instance_name ubuntu-24.04 /home/u/proj)"
  [ "$a" = "$b" ]
  [[ "$a" =~ ^devbox-proj-[0-9a-f]{8}$ ]]
}

@test "instance_name differs by directory" {
  a="$(instance_name ubuntu-24.04 /home/u/proj)"
  b="$(instance_name ubuntu-24.04 /home/u/other)"
  [ "$a" != "$b" ]
}

@test "instance_name differs by image" {
  a="$(instance_name ubuntu-24.04 /home/u/proj)"
  b="$(instance_name debian-12   /home/u/proj)"
  [ "$a" != "$b" ]
}

# ------------------------------------------------------ session persistence ----
@test "project session state follows the project rather than the VM image" {
  original="$AGENT_SESSION_BASE"
  AGENT_SESSION_BASE="$BATS_TEST_TMPDIR/state"
  a="$(project_session_dir /home/u/proj)"
  b="$(project_session_dir /home/u/proj)"
  [ "$a" = "$b" ]
  [[ "$a" =~ /proj-[0-9a-f]{16}$ ]]
  [ "$a" != "$(project_session_dir /home/u/other)" ]
  AGENT_SESSION_BASE="$original"
}

@test "project session state is created owner-only" {
  original="$AGENT_SESSION_BASE"
  AGENT_SESSION_BASE="$BATS_TEST_TMPDIR/state"
  path="$(project_session_dir /home/u/proj)"
  prepare_session_dir "$path"
  [ -d "$path" ]
  [ "$(file_mode "$AGENT_SESSION_BASE")" = 700 ]
  [ "$(file_mode "$path")" = 700 ]
  AGENT_SESSION_BASE="$original"
}

@test "session persistence covers native stores without persisting auth homes" {
  run declare -f apply_session_persistence
  [ "$status" -eq 0 ]
  [[ "$output" == *'.claude/projects'* ]]
  [[ "$output" == *'codex_home/sessions'* ]]
  [[ "$output" == *'.devbox/codex-proxy'* ]]
  [[ "$output" == *'.pi/agent/sessions'* ]]
  [[ "$output" == *'OPENCODE_DB'* ]]
  [[ "$output" == *'.local/share/stado/sessions'* ]]
  [[ "$output" != *'.codex/auth.json'* ]]
  [[ "$output" != *'.local/share/opencode/auth.json'* ]]
}

@test "a new box mounts the session store writable unless the run is ephemeral" {
  # Behavioral: drive the real clone-mount assembly rather than grep for a line
  # of source. Every mount is --mount-only (see _clone_mount_args), the project
  # is always writable, and the session store rides along unless ephemeral.
  local with_state without_state
  with_state="$(_clone_mount_args /proj /state/sess | tr '\n' ' ')"
  [[ "$with_state" == *'--mount-only /proj:w'* ]]
  [[ "$with_state" == *'--mount-only /state/sess:w'* ]]
  without_state="$(_clone_mount_args /proj '' | tr '\n' ' ')"
  [[ "$without_state" == *'--mount-only /proj:w'* ]]
  [[ "$without_state" != *sess* ]]
}

@test "a kept box gains the session store through an in-place limactl edit" {
  # ensure_session_mount attaches the store to an existing box. Stub limactl,
  # run the real helper, and assert the edit it issues. The box here is Stopped,
  # which also guards the set -e trap this test surfaced: the helper is the
  # final command of a `… || ensure_session_mount` list, so if it returned 1 on
  # the not-Running path (a trailing `[[ … ]] &&` does), devbox would abort
  # before handover. Asserting status 0 keeps that fixed.
  run bash -c "
    source '$DEVBOX' 2>/dev/null; set +u
    limactl() {
      case \"\$*\" in
        *--json*)   printf '[]\n';;          # store not attached yet -> proceed
        *--format*) printf 'Stopped\n';;     # not Running -> no stop/start dance
        edit*)      printf 'EDIT: %s\n' \"\$*\" >&2;;  # helper sends edit stdout to /dev/null
        *)          return 0;;
      esac
    }
    ensure_session_mount box /state/sess
  "
  [ "$status" -eq 0 ]
  [[ "$output" == *"EDIT: edit box --mount /state/sess:w"* ]]
}

@test "clearing session persistence removes only the session mount" {
  run bash -c "
    source '$DEVBOX' 2>/dev/null; set +u
    limactl() {
      case \"\$*\" in
        *--json*)   printf '[{\"config\":{\"mounts\":[{\"location\":\"/state/sess\",\"writable\":true}]}}]\n';;
        *--format*) printf 'Stopped\n';;
        edit*)      printf 'EDIT: %s\n' \"\$*\" >&2;;  # helper sends edit stdout to /dev/null
        *)          return 0;;
      esac
    }
    remove_session_mount box /state/sess
  "
  [ "$status" -eq 0 ]
  [[ "$output" == *"EDIT: edit box --set"* ]]
  [[ "$output" == *'del(.mounts[]'* ]]
  [[ "$output" == *'/state/sess'* ]]
}

@test "session-persistence wiring: reuse guard and the ephemeral opt-out exist" {
  # Pure CLI/guard wiring with no behavior to exercise in isolation — a source
  # check is the honest level here.
  source_text="$(<"$DEVBOX")"
  [[ "$source_text" == *'session_state_other_instance "$session_state" "$name"'* ]]
  [[ "$source_text" == *'--ephemeral-sessions|-e) ephemeral_sessions=1'* ]]
}

# --------------------------------------------------------- emit_base_stanza ----
@test "base stanza: bare template name" {
  run emit_base_stanza ubuntu-24.04
  [ "$output" = 'base: "template:ubuntu-24.04"' ]
}

@test "base stanza: template:// is normalized to template:" {
  run emit_base_stanza template://ubuntu-25.04
  [ "$output" = 'base: "template:ubuntu-25.04"' ]
}

@test "base stanza: qcow2 path becomes an images: block" {
  run emit_base_stanza /images/kali.qcow2
  [[ "$output" == *"images:"* ]]
  [[ "$output" == *'location: "/images/kali.qcow2"'* ]]
}

@test "base stanza: .yaml path becomes a base: file reference" {
  run emit_base_stanza /vms/box.yaml
  [ "$output" = 'base: "/vms/box.yaml"' ]
}

@test "base stanza: http(s) URL becomes an images: block" {
  run emit_base_stanza https://example.com/cloud.qcow2
  [[ "$output" == *"images:"* ]]
  [[ "$output" == *'location: "https://example.com/cloud.qcow2"'* ]]
}

# -------------------------------------------------------- emit_golden_yaml ----
@test "Lima's merge re-adds a mount to a golden that declares mounts: [] (why --mount-none is needed)" {
  require_resolver
  # THE trap this suite exists for. We emit `mounts: []`, but Lima resolves the
  # base-template chain at create time and an empty list reads as "unset", so
  # the RESOLVED config comes back carrying template:_default's read-only ~
  # mount — which then clones into every box and shadows the writable project
  # mount that lives under it. The old `grep '^mounts: \[\]'` test could not see
  # this because it only read the text we emit. This is why cmd_build creates
  # the golden with --mount-none (an edit-layer override applied after the
  # merge). If this list ever comes back empty, Lima's merge changed and the
  # guard can be revisited.
  local locations
  locations="$(resolved_golden ubuntu-24.04 | mount_locations)"
  [ -n "$locations" ]
}

@test "a resolved golden does not load host pubkeys" {
  require_resolver
  [ "$(resolved_golden ubuntu-24.04 | yaml_get ssh.loadDotSSHPubKeys)" = False ]
}

@test "a resolved golden leaves SSH-agent forwarding disabled until explicitly requested" {
  # Assert on the merged result, not our text: the base template enables
  # forwarding, so this proves our override actually wins the merge.
  require_resolver
  local fwd
  fwd="$(resolved_golden ubuntu-24.04 | yaml_get ssh.forwardAgent)"
  [ "$fwd" = False ] || [ -z "$fwd" ]
}

@test "a resolved golden disables Lima's unused containerd bootstrap" {
  require_resolver
  local resolved
  resolved="$(resolved_golden ubuntu-24.04)"
  [ "$(printf '%s' "$resolved" | yaml_get containerd.system)" = False ]
  [ "$(printf '%s' "$resolved" | yaml_get containerd.user)" = False ]
}

@test "a golden configures systemd-resolved to use Lima's host-aware DNS" {
  tmp="$BATS_TEST_TMPDIR/g.yaml"
  emit_golden_yaml ubuntu-24.04 "$tmp"
  grep -q '99-devbox-host-dns.conf' "$tmp"
  grep -q 'DNS=192.168.5.3' "$tmp"
  grep -q 'systemctl restart systemd-resolved' "$tmp"
}

@test "SSH signing is not baked into a golden image" {
  tmp="$BATS_TEST_TMPDIR/g.yaml"
  emit_golden_yaml ubuntu-24.04 "$tmp"
  ! grep -q 'git-signing-key' "$tmp"
}

@test "new SSH-agent boxes set forwarding in the clone config before boot" {
  source_text="$(<"$DEVBOX")"
  [[ "$source_text" == *"clone_args+=(--set '.ssh.forwardAgent = true')"* ]]
  [[ "$source_text" == *'limactl --tty=false clone'* ]]
}

@test "golden yaml installs the AI and GitHub CLI toolchain" {
  tmp="$BATS_TEST_TMPDIR/g.yaml"
  emit_golden_yaml ubuntu-24.04 "$tmp"
  grep -q 'brew install --cask foobarto/tap/stado' "$tmp"
  grep -q 'brew install codex' "$tmp"
  grep -q 'brew install gh' "$tmp"
  grep -q 'sst/tap/opencode' "$tmp"
  grep -q 'claude.ai/install.sh' "$tmp"
  grep -q 'brew install node' "$tmp"
  grep -q 'npm install -g --ignore-scripts @earendil-works/pi-coding-agent' "$tmp"
  grep -q 'brew install herdr' "$tmp"
}

@test "golden yaml includes the Stado Linux sandbox helpers and scoped Ubuntu bwrap policy" {
  tmp="$BATS_TEST_TMPDIR/g.yaml"
  emit_golden_yaml ubuntu-24.04 "$tmp"
  grep -q 'bubblewrap passt apparmor apparmor-profiles' "$tmp"
  grep -q 'apparmor_restrict_unprivileged_userns' "$tmp"
  grep -q 'bwrap-userns-restrict' "$tmp"
  grep -q '/usr/share/apparmor/extra-profiles/bwrap-userns-restrict' "$tmp"
  grep -q '/usr/sbin/apparmor_parser -r /etc/apparmor.d/bwrap-userns-restrict' "$tmp"
  ! grep -q 'apparmor_restrict_unprivileged_userns=0' "$tmp"
}

@test "golden yaml installs Waypipe through every supported guest package manager" {
  tmp="$BATS_TEST_TMPDIR/g.yaml"
  emit_golden_yaml ubuntu-24.04 "$tmp"
  grep -q 'python3-pip waypipe' "$tmp"
  grep -q 'python-pip waypipe' "$tmp"
}

@test "golden yaml fetches GitHub host keys through the Meta API" {
  tmp="$BATS_TEST_TMPDIR/g.yaml"
  emit_golden_yaml ubuntu-24.04 "$tmp"
  grep -q 'https://api.github.com/meta' "$tmp"
  grep -Fq 'github.com \(.)' "$tmp"
  grep -Fq '$HOME/.ssh/known_hosts' "$tmp"
}

@test "golden yaml has a GitHub Docs host-key fallback for API rate limits" {
  tmp="$BATS_TEST_TMPDIR/g.yaml"
  emit_golden_yaml ubuntu-24.04 "$tmp"
  grep -q 'githubs-ssh-key-fingerprints' "$tmp"
  grep -q 'Never use ssh-keyscan here' "$tmp"
}

@test "golden verification requires all published GitHub host keys" {
  source_text="$(<"$DEVBOX")"
  [[ "$source_text" == *'ssh-keygen -F github.com'* ]]
  [[ "$source_text" == *"grep -c '^github.com '"* ]]
  [[ "$source_text" == *'Golden verification failed; removing unusable'* ]]
}

@test "golden verification exercises Stado's Linux sandbox helpers" {
  source_text="$(<"$DEVBOX")"
  [[ "$source_text" == *'for t in brew gh claude codex opencode pi herdr stado bwrap pasta'* ]]
  [[ "$source_text" == *'bwrap --unshare-user --unshare-net --uid 0 --gid 0'* ]]
  [[ "$source_text" == *'pasta --help 2>&1 | grep -q -- "--splice-only"'* ]]
}

@test "generated golden yaml validates with limactl" {
  command -v limactl >/dev/null || skip "limactl not installed"
  tmp="$BATS_TEST_TMPDIR/g.yaml"
  emit_golden_yaml ubuntu-24.04 "$tmp"
  run limactl validate "$tmp"
  [ "$status" -eq 0 ]
}

# ----------------------------------------------------- --mount / --copy args ----
@test "mount arg: bare path is read-only" {
  run _lima_mount_arg /data
  [ "$output" = "/data" ]
}

@test "mount arg: :rw becomes lima :w" {
  run _lima_mount_arg /data:rw
  [ "$output" = "/data:w" ]
}

@test "mount arg: :ro is read-only (suffix stripped)" {
  run _lima_mount_arg /data:ro
  [ "$output" = "/data" ]
}

@test "every clone mount is --mount-only, so no golden mount can leak through" {
  # --mount-only OVERRIDES the source golden's mounts; --mount would ADD to
  # them, letting an inherited ~ mount survive into the clone. Assert the
  # assembled flags: one --mount-only per mount, project writable, extra modes
  # preserved, and never a bare --mount.
  local args
  args="$(_clone_mount_args /proj /state/sess /ro/extra /rw/extra:rw | tr '\n' ' ')"
  [[ "$args" == *'--mount-only /proj:w'* ]]
  [[ "$args" == *'--mount-only /state/sess:w'* ]]
  [[ "$args" == *'--mount-only /ro/extra'* ]]      # bare == read-only
  [[ "$args" == *'--mount-only /rw/extra:w'* ]]    # :rw -> lima :w
  # exactly four mounts, and not one plain --mount
  [ "$(printf '%s\n' "$args" | grep -o -- '--mount-only' | wc -l)" -eq 4 ]
  [[ "$args" != *' --mount '* ]]
}

@test "cmd_build creates the golden with --mount-none to defeat the template ~ mount" {
  # Behavioral: drive the real build with a stubbed limactl that records its
  # argv, and assert the golden is started with --mount-none. Paired with the
  # merge trap-guard test, this is the unit-level proof that devbox neutralizes
  # the inherited mount; the booted proof lives in e2e.
  run bash -c "
    source '$DEVBOX' 2>/dev/null; set +u
    export CONFIG_DIR='$BATS_TEST_TMPDIR/cfg'; mkdir -p \"\$CONFIG_DIR\"
    STARTLOG='$BATS_TEST_TMPDIR/start.log'; : > \"\$STARTLOG\"
    cd '$BATS_TEST_TMPDIR'   # no project manifest in scope
    limactl() {
      case \"\$*\" in
        start*)     printf '%s\n' \"\$*\" >> \"\$STARTLOG\"; return 0;;
        'list -q')  return 0;;                      # empty -> golden does not exist yet
        *--format*) printf 'Stopped\n';;
        *'for t in'*)     printf '  ok   brew   /home/linuxbrew/.linuxbrew/bin/brew\n';;
        *known_hosts*)    printf 'github.com ssh-rsa A\ngithub.com ssh-ed25519 B\ngithub.com ecdsa-sha2-nistp256 C\n';;
        *'pasta --help'*) printf -- '--splice-only\n';;
        *) return 0;;
      esac
    }
    cmd_build --image ubuntu-24.04 --yes >/dev/null 2>&1
    cat \"\$STARTLOG\"
  "
  [ "$status" -eq 0 ]
  [[ "$output" == *start* ]]
  [[ "$output" == *--mount-none* ]]
}

@test "require_project_writable refuses a box whose project mount is missing or read-only" {
  # The guard reads the resolved mount state and refuses before handover, so a
  # box that cannot write its project fails loudly instead of on first write.
  # Accepts a writable project mount:
  run bash -c "
    source '$DEVBOX' 2>/dev/null; set +u
    limactl() { printf '[{\"config\":{\"mounts\":[{\"location\":\"/proj\",\"writable\":true}]}}]\n'; }
    require_project_writable box /proj
  "
  [ "$status" -eq 0 ]
  # Refuses a read-only project mount:
  run bash -c "
    source '$DEVBOX' 2>/dev/null; set +u
    limactl() { printf '[{\"config\":{\"mounts\":[{\"location\":\"/proj\",\"writable\":false}]}}]\n'; }
    require_project_writable box /proj
  "
  [ "$status" -ne 0 ]
  [[ "$output" == *"not mounted writable"* ]]
  # Refuses when the project is not mounted at all (only ~ is):
  run bash -c "
    source '$DEVBOX' 2>/dev/null; set +u
    limactl() { printf '[{\"config\":{\"mounts\":[{\"location\":\"/home/u\",\"writable\":false}]}}]\n'; }
    require_project_writable box /proj
  "
  [ "$status" -ne 0 ]
}

@test "copy spec: no colon -> src as-is, dest is basename" {
  run _copy_src /host/thing.txt;  [ "$output" = "/host/thing.txt" ]
  run _copy_dest /host/thing.txt; [ "$output" = "thing.txt" ]
}

@test "copy spec: SRC:DEST splits on last colon" {
  run _copy_src /host/dir:/guest/dest;  [ "$output" = "/host/dir" ]
  run _copy_dest /host/dir:/guest/dest; [ "$output" = "/guest/dest" ]
}

# ----------------------------------------------------------- agent config ----
@test "agent config allowlist excludes known credential paths" {
  config_paths="$(printf '%s\n' "${AGENT_CONFIG_PATHS[@]}")"
  [[ "$config_paths" == *"$HOME/.claude/settings.json"* ]]
  [[ "$config_paths" == *"$HOME/.codex/config.toml"* ]]
  [[ "$config_paths" != *"$HOME/.claude/.credentials.json"* ]]
  [[ "$config_paths" != *"$HOME/.claude.json"* ]]
  [[ "$config_paths" != *"$HOME/.codex/auth.json"* ]]
  [[ "$config_paths" != *"$HOME/.config/stado/keys"* ]]
}

@test "agent config credential detector skips assignments but accepts ordinary settings" {
  safe="$BATS_TEST_TMPDIR/safe.toml"
  suspect="$BATS_TEST_TMPDIR/suspect.toml"
  empty="$BATS_TEST_TMPDIR/empty.md"
  printf 'model = "gpt-5"\n' > "$safe"
  printf 'api_key = "placeholder-value"\n' > "$suspect"
  : > "$empty"
  run agent_config_contains_credential "$safe"
  [ "$status" -ne 0 ]
  run agent_config_contains_credential "$empty"
  [ "$status" -ne 0 ]
  run agent_config_contains_credential "$suspect"
  [ "$status" -eq 0 ]
}

@test "agent config follows an allowlisted directory symlink but not nested links" {
  root="$BATS_TEST_TMPDIR/agent-config"
  mkdir -p "$root/real-hooks"
  printf '#!/bin/sh\n' > "$root/real-hooks/guard.sh"
  printf 'not agent config\n' > "$root/outside"
  ln -s real-hooks "$root/hooks"
  ln -s "$root/outside" "$root/real-hooks/escape"

  run bash -c 'source "$1"; agent_config_files "$2" | tr "\\0" "\\n"' _ "$DEVBOX" "$root/hooks"
  [ "$status" -eq 0 ]
  [ "$output" = "$root/hooks/guard.sh" ]
}

# ------------------------------------------------------------------- proxy ----
@test "proxy_port extracts port and defaults to 4141" {
  run proxy_port http://host.lima.internal:4141; [ "$output" = "4141" ]
  run proxy_port http://host.lima.internal:5001; [ "$output" = "5001" ]
  run proxy_port http://host;                     [ "$output" = "4141" ]
}

@test "GitHub proxy URL carries its capability as HTTP proxy userinfo" {
  run bash -c 'printf %s "$2" | { source "$1"; github_proxy_url "$3"; }' _ "$DEVBOX" "part.one" "http://host.lima.internal:4141"
  [ "$status" -eq 0 ]
  [ "$output" = "http://part.one@host.lima.internal:4141" ]
}

@test "traffic proxy URL uses the same capability-safe bare endpoint format" {
  run bash -c 'printf %s "$2" | { source "$1"; traffic_proxy_url "$3"; }' _ "$DEVBOX" "part.one" "http://host.lima.internal:4141"
  [ "$status" -eq 0 ]
  [ "$output" = "http://part.one@host.lima.internal:4141" ]
}

@test "GitHub proxy URL rejects a proxy URL with existing credentials or a path" {
  run bash -c 'printf %s "$2" | { source "$1"; github_proxy_url "$3"; }' _ "$DEVBOX" "part.one" "http://user@host.lima.internal:4141"
  [ "$status" -ne 0 ]
  run bash -c 'printf %s "$2" | { source "$1"; github_proxy_url "$3"; }' _ "$DEVBOX" "part.one" "http://host.lima.internal:4141/path"
  [ "$status" -ne 0 ]
}

@test "GitHub proxy remembers only a bare host-side endpoint with owner-only permissions" {
  original_config_dir="$CONFIG_DIR"
  CONFIG_DIR="$BATS_TEST_TMPDIR/config"
  endpoint="http://host.lima.internal:4141"
  record_gh_proxy_endpoint devbox-test "$endpoint"
  [ "$(stored_gh_proxy_endpoint devbox-test)" = "$endpoint" ]
  [ "$(file_mode "$(gh_proxy_state_path devbox-test)")" = "600" ]
  ! valid_gh_proxy_endpoint "http://capability@host.lima.internal:4141"
  ! valid_gh_proxy_endpoint "https://host.lima.internal:4141"
  CONFIG_DIR="$original_config_dir"
}

@test "traffic proxy remembers only a bare host-side endpoint with owner-only permissions" {
  original_config_dir="$CONFIG_DIR"
  CONFIG_DIR="$BATS_TEST_TMPDIR/config"
  endpoint="http://host.lima.internal:4141"
  record_traffic_proxy_endpoint devbox-test "$endpoint"
  [ "$(stored_traffic_proxy_endpoint devbox-test)" = "$endpoint" ]
  [ "$(file_mode "$(traffic_proxy_state_path devbox-test)")" = "600" ]
  ! valid_gh_proxy_endpoint "http://capability@host.lima.internal:4141"
  CONFIG_DIR="$original_config_dir"
}

@test "proxy setup keeps gh credentials on the host behind a guest wrapper" {
  source_text="$(<"$DEVBOX")"
  [[ "$source_text" == *'gh-wrapper.py'* ]]
  [[ "$source_text" == *'zz-devbox-12-gh-proxy.sh'* ]]
  [[ "$source_text" == *'gh-proxy-ca.pem'* ]]
  [[ "$source_text" == *'gh auth login'* ]]
  [[ "$source_text" == *'gh() {'* ]]
  [[ "$source_text" == *'DEVBOX_GH_PROXY_URL_FILE'* ]]
  [[ "$source_text" == *'renew_gh_proxy_capability'* ]]
  [[ "$source_text" != *'start_gh_proxy_capability_renewal'* ]]
  [[ "$source_text" == *'stored_gh_proxy_endpoint'* ]]
  [[ "$source_text" == *'formula_prefix="$("$brew_bin" --prefix gh'* ]]
  [[ "$source_text" == *'real_gh="$real_dir/gh-real"'* ]]
  [[ "$source_text" == *'ln -s "$wrapper" "$brew_gh"'* ]]
  [[ "$source_text" == *'"$brew_bin" link --overwrite gh'* ]]
  [[ "$source_text" == *'rm -rf -- "$HOME/.devbox/codex-proxy" "$HOME/.devbox/gh-proxy"'* ]]
}

@test "proxy refresh bypasses project manifest and image resolution" {
  project="$BATS_TEST_TMPDIR/project"
  fake_launcher="$BATS_TEST_TMPDIR/proxy-launcher"
  mkdir -p "$project"
  printf '%s\n' 'this is deliberately not valid TOML' > "$project/.devbox.toml"
  printf '%s\n' '#!/usr/bin/env bash' 'printf "launcher:%s\n" "$1"' > "$fake_launcher"
  chmod +x "$fake_launcher"
  proxy_ensure() { printf 'ensure:%s\n' "$1"; }
  proxy_launcher() { printf '%s' "$fake_launcher"; }

  cd "$project"
  output="$(cmd_proxy refresh)"

  [[ "$output" == *'ensure:http://host.lima.internal:4141'* ]]
  [[ "$output" == *'launcher:--refresh-gh-proxy-boxes'* ]]
}

@test "proxy command exposes host-owned audit viewing and HTML export" {
  source_text="$(<"$DEVBOX")"
  [[ "$source_text" == *'proxy audit [status|show [LIMIT]|export [FILE]]'* ]]
  [[ "$source_text" == *'--audit-status'* ]]
  [[ "$source_text" == *'--audit-show'* ]]
  [[ "$source_text" == *'--audit-export'* ]]
}

@test "traffic audit is explicit, proxy-or-fail, and removable from kept boxes" {
  source_text="$(<"$DEVBOX")"
  [[ "$source_text" == *'--traffic-audit[=connect|off], -T'* ]]
  [[ "$source_text" == *'--traffic-audit|-T) traffic_audit=connect'* ]]
  [[ "$source_text" == *'--traffic-audit=*|-T=*) traffic_audit='* ]]
  [[ "$source_text" == *'ensure_guest_nftables'* ]]
  [[ "$source_text" == *'table inet devbox_traffic_audit'* ]]
  [[ "$source_text" == *'tcp dport { 80, 443 } reject'* ]]
  [[ "$source_text" == *'udp dport { 80, 443 } reject'* ]]
  [[ "$source_text" == *'clear_connect_traffic_audit'* ]]
  [[ "$source_text" != *'-a) with_agent_config=1; proxy="$PROXY_DEFAULT_URL"; ssh_agent=1; traffic_audit='* ]]
}

@test "GUI commands use Waypipe over Lima SSH without exposing the host socket" {
  source_text="$(<"$DEVBOX")"
  [[ "$source_text" == *'cmd_gui() { cmd_run --gui "$@"; }'* ]]
  [[ "$source_text" == *'--gui|-G) gui=1'* ]]
  [[ "$source_text" == *'-a) with_agent_config=1; proxy="$PROXY_DEFAULT_URL"; ssh_agent=1'* ]]
  [[ "$source_text" != *'-a) with_agent_config=1; proxy="$PROXY_DEFAULT_URL"; ssh_agent=1; gui=1'* ]]
  [[ "$source_text" == *'waypipe --no-gpu'*'ssh -F "$ssh_config" "lima-$name"'* ]]
  [[ "$source_text" == *'ssh -F "$ssh_config" -tt "lima-$name"'* ]]
  [[ "$source_text" == *'gui_remote_command'*'shlex.quote'* ]]
  [[ "$source_text" == *'gui_remote_shell'*'exec bash -l'* ]]
  [[ "$source_text" == *'{{.SSHConfigFile}}'* ]]
  [[ "$source_text" == *'host Wayland socket'* ]]
  [[ "$source_text" != *'--mount "$XDG_RUNTIME_DIR'* ]]
}

@test "GUI command starts in the mounted project directory with safely quoted arguments" {
  run gui_remote_command "/project with spaces" code "." "a value" "\$HOME"
  [ "$status" -eq 0 ]
  [ "$output" = "cd '/project with spaces' && exec code . 'a value' '\$HOME'" ]
}

@test "GUI runner uses the instance SSH config and forwards its quoted project command" {
  host_wayland_socket() { :; }
  ensure_guest_waypipe() { :; }
  lima_ssh_config() { printf '%s' /tmp/devbox-gui-ssh.config; }
  waypipe() { printf '%s\0' "$@" > "$BATS_TEST_TMPDIR/waypipe-args"; }
  run_gui devbox-test "/project with spaces" code "." "a value"
  mapfile -d '' -t args < "$BATS_TEST_TMPDIR/waypipe-args"
  [ "${args[0]}" = "--no-gpu" ]
  [ "${args[3]}" = "ssh" ]
  [ "${args[4]}" = "-F" ]
  [ "${args[5]}" = "/tmp/devbox-gui-ssh.config" ]
  [ "${args[6]}" = "lima-devbox-test" ]
  [ "${args[7]}" = "bash" ]
  [ "${args[9]}" = "cd '/project with spaces' && exec code . 'a value'" ]
}

@test "GUI shell starts in the mounted project directory" {
  run gui_remote_shell "/project with spaces"
  [ "$status" -eq 0 ]
  [ "$output" = "cd '/project with spaces' && exec bash -l" ]
}

@test "GUI shell keeps Waypipe alive over an interactive Lima SSH session" {
  host_wayland_socket() { :; }
  ensure_guest_waypipe() { :; }
  lima_ssh_config() { printf '%s' /tmp/devbox-gui-ssh.config; }
  waypipe() { printf '%s\0' "$@" > "$BATS_TEST_TMPDIR/waypipe-args"; }
  run_gui_shell devbox-test "/project with spaces"
  mapfile -d '' -t args < "$BATS_TEST_TMPDIR/waypipe-args"
  [ "${args[0]}" = "--no-gpu" ]
  [ "${args[3]}" = "ssh" ]
  [ "${args[4]}" = "-F" ]
  [ "${args[5]}" = "/tmp/devbox-gui-ssh.config" ]
  [ "${args[6]}" = "-tt" ]
  [ "${args[7]}" = "lima-devbox-test" ]
  [ "${args[8]}" = "bash" ]
  [ "${args[10]}" = "cd '/project with spaces' && exec bash -l" ]
}

# ------------------------------------------------------- project manifest ----
@test "project_manifest normalizes .devbox.toml settings" {
  run project_manifest "$BATS_TEST_DIRNAME/fixtures/project.devbox.toml"
  [ "$status" -eq 0 ]
  [[ "$output" == *'"image": "debian-12"'* ]]
  [[ "$output" == *'"packages": ["node", "go"]'* ]]
  [[ "$output" == *'"ssh_agent": true'* ]]
  [[ "$output" == *'"proxy": "http://host.lima.internal:4141"'* ]]
  [[ "$output" == *'"with_agent_config": true'* ]]
}

@test "manifest package transport handles a single package" {
  run manifest_package_lines '["hello"]'
  [ "$status" -eq 0 ]
  [ "$output" = "hello" ]
}

@test "manifest package transport emits every package on its own line" {
  run manifest_package_lines '["node", "go"]'
  [ "$status" -eq 0 ]
  [ "$output" = $'node\ngo' ]
}

# --------------------------------------------------------------- resources ----
@test "size_to_gib accepts GiB, MiB and bare numbers" {
  [ "$(size_to_gib 12GiB)" = "12" ]
  [ "$(size_to_gib 100)" = "100" ]
  [ "$(size_to_gib 512MiB)" = "0.5" ]
  [ "$(size_to_gib 1TiB)" = "1024" ]
}

@test "size_to_gib rejects nonsense" {
  run size_to_gib "lots"
  [ "$status" -ne 0 ]
}

@test "resource precedence: CLI beats manifest beats global beats default" {
  # cli cpus, manifest memory, global disk
  run resolve_resources 16 "" "" '{"cpus":8,"memory":"12GiB","disk":""}' '{"cpus":2,"memory":"2GiB","disk":"70GiB"}'
  [ "$status" -eq 0 ]
  [ "$output" = $'16\t12GiB\t70GiB' ]
}

@test "resource precedence falls back to built-in defaults" {
  run resolve_resources "" "" "" '{}' '{}'
  [ "$status" -eq 0 ]
  [ "$output" = "$DEFAULT_CPUS"$'\t'"$DEFAULT_MEMORY"$'\t'"$DEFAULT_DISK" ]
}

@test "default disk ceiling is generous (sparse qcow2 costs only what is used)" {
  [ "$(size_to_gib "$DEFAULT_DISK")" -ge 100 ]
}

# ------------------------------------------------------- golden_spec_hash ----
@test "a stock image has no spec hash, so its golden name is unchanged" {
  run golden_spec_hash ubuntu-24.04 "" "" ""
  [ "$status" -eq 0 ]
  [ -z "$output" ]
  run golden_name ubuntu-24.04 ""
  [ "$output" = "devbox-golden-ubuntu-24-04" ]
}

@test "custom provisioning produces a distinct, deterministic golden name" {
  h1="$(golden_spec_hash /images/kali.qcow2 "" "apt-get install -y nmap" "")"
  h2="$(golden_spec_hash /images/kali.qcow2 "" "apt-get install -y nmap" "")"
  [ -n "$h1" ]
  [ "$h1" = "$h2" ]
  [[ "$(golden_name /images/kali.qcow2 "$h1")" =~ ^devbox-golden-kali-qcow2-[0-9a-f]{6}-[0-9a-f]{6}$ ]]
}

@test "changing provisioning changes the golden identity" {
  a="$(golden_spec_hash /images/kali.qcow2 "" "apt-get install -y nmap" "")"
  b="$(golden_spec_hash /images/kali.qcow2 "" "apt-get install -y ffuf" "")"
  [ "$a" != "$b" ]
}

@test "digest and user provisioning are part of the golden identity" {
  base="$(golden_spec_hash /images/kali.qcow2 "" "x" "")"
  [ "$base" != "$(golden_spec_hash /images/kali.qcow2 "sha512:abc" "x" "")" ]
  [ "$base" != "$(golden_spec_hash /images/kali.qcow2 "" "x" "pipx install updog")" ]
}

# --------------------------------------------------- manifest [image] table ----
@test "manifest accepts the [image] table with location, digest and provisioning" {
  run project_manifest "$BATS_TEST_DIRNAME/fixtures/image-table.devbox.toml"
  [ "$status" -eq 0 ]
  [[ "$output" == *'"image": "/images/kali.qcow2"'* ]]
  [[ "$output" == *'"image_digest": "sha512:deadbeef"'* ]]
  [[ "$output" == *'kali-linux-headless'* ]]
  [[ "$output" == *'updog'* ]]
  [[ "$output" == *'"cpus": 8'* ]]
  [[ "$output" == *'"memory": "12GiB"'* ]]
  [[ "$output" == *'"disk": "80GiB"'* ]]
}

@test "manifest still accepts the bare top-level image string" {
  run project_manifest "$BATS_TEST_DIRNAME/fixtures/project.devbox.toml"
  [ "$status" -eq 0 ]
  [[ "$output" == *'"image": "debian-12"'* ]]
  [[ "$output" == *'"image_digest": ""'* ]]
}

@test "manifest rejects an unknown key inside [image]" {
  f="$BATS_TEST_TMPDIR/bad.toml"
  printf '[image]\nlocation = "x"\nnope = 1\n' > "$f"
  run project_manifest "$f"
  [ "$status" -ne 0 ]
  [[ "$output" == *"image"* ]]
}

@test "manifest rejects a non-positive cpu count and a malformed size" {
  f="$BATS_TEST_TMPDIR/bad2.toml"
  printf '[resources]\ncpus = 0\n' > "$f"
  run project_manifest "$f"
  [ "$status" -ne 0 ]
  printf '[resources]\nmemory = "loads"\n' > "$f"
  run project_manifest "$f"
  [ "$status" -ne 0 ]
}

# ------------------------------------------- golden yaml with customisation ----
@test "a resolved golden carries the requested resources through the merge" {
  require_resolver
  local resolved
  resolved="$(resolved_golden ubuntu-24.04 8 "12GiB" "80GiB")"
  [ "$(printf '%s' "$resolved" | yaml_get cpus)" = 8 ]
  [ "$(printf '%s' "$resolved" | yaml_get memory)" = 12GiB ]
  [ "$(printf '%s' "$resolved" | yaml_get disk)" = 80GiB ]
}

@test "golden yaml embeds a digest when one is supplied" {
  out="$BATS_TEST_TMPDIR/g.yaml"
  emit_golden_yaml /images/kali.qcow2 "$out" 4 "6GiB" "50GiB" "sha512:deadbeef"
  grep -q 'digest: "sha512:deadbeef"' "$out"
}

@test "project provisioning is NOT embedded in the golden yaml" {
  # Lima fails a start whose boot scripts outrun its readiness wait — and
  # `--timeout` does not extend that wait. Long project provisioning therefore
  # runs after boot, under devbox's control, never as a Lima provision entry.
  out="$BATS_TEST_TMPDIR/g.yaml"
  emit_golden_yaml ubuntu-24.04 "$out" 4 "6GiB" "50GiB" "" "apt-get install -y kali-linux-headless" "pipx install updog"
  ! grep -q 'kali-linux-headless' "$out"
  ! grep -q 'pipx install updog' "$out"
}

@test "a golden yaml still validates when the project supplies provisioning" {
  command -v limactl >/dev/null || skip "limactl not installed"
  out="$BATS_TEST_TMPDIR/g.yaml"
  emit_golden_yaml ubuntu-24.04 "$out" 8 "12GiB" "80GiB" "" $'echo one\necho two' "pipx install updog"
  run limactl validate "$out"
  [ "$status" -eq 0 ]
}

@test "post-boot provisioning runs system as root and user unprivileged" {
  src="$(<"$DEVBOX")"
  [[ "$src" == *"apply_golden_provisioning"* ]]
  # the system stage must elevate; the user stage must not
  run declare -f apply_golden_provisioning
  [ "$status" -eq 0 ]
  [[ "$output" == *"sudo"* ]]
}

@test "provisioning scripts reach the guest over stdin, not the argv" {
  # Multi-line scripts with quotes must not be word-split or re-quoted through a
  # command line; they are piped to `bash … -s`.
  run declare -f apply_golden_provisioning
  [ "$status" -eq 0 ]
  [[ "$output" == *"bash -e -s"* ]]
  [[ "$output" == *"bash -l -e -s"* ]]
}

@test "a project script that fails halfway fails the provisioning phase" {
  # A shell reading from stdin exits with its LAST command's status, so a
  # manifest whose `brew install` failed still "succeeded" if its closing line
  # worked — and the golden was baked without the toolchain it asked for.
  run bash -c "
    source '$DEVBOX' 2>/dev/null; set +u
    limactl() { shift 3; \"\$@\"; }   # drop 'shell NAME --', run the rest locally
    sudo() { env \"\$@\"; }           # env, so the DEBIAN_FRONTEND prefix applies
    apply_golden_provisioning fake-golden 'false
true' ''
  "
  [ "$status" -ne 0 ]
  [[ "$output" == *"project system provisioning failed"* ]]
}

@test "a golden whose project provisioning failed is deleted, not left to clone" {
  # Every later run treats an existing golden as a usable clone source, so a
  # retained half-provisioned one turns one visible build error into boxes that
  # are quietly missing their toolchain.
  src="$(<"$DEVBOX")"
  [[ "$src" == *'if ! apply_golden_provisioning "$golden" "$provision" "$provision_user"; then'* ]]
  [[ "$src" == *"Removing incomplete \$golden."* ]]
  # the phase itself must report failure rather than exiting past the cleanup
  run declare -f apply_golden_provisioning
  [ "$status" -eq 0 ]
  [[ "$output" != *"die "* ]]
  [[ "$output" == *"return 1"* ]]
}

# ------------------------------------------------------------ build timeout ----
@test "golden builds wait far longer than Lima's default boot timeout" {
  # Lima gives boot scripts 10 minutes and then fails with "did not receive an
  # event with the running status". Baking a distro toolchain into a golden
  # legitimately takes longer, so the build must raise the limit.
  [[ "$(<"$DEVBOX")" == *'--timeout'* ]]
  [[ "$DEFAULT_BUILD_TIMEOUT" =~ ^([0-9]+)m$ ]]
  [ "${BASH_REMATCH[1]}" -ge 30 ]
}

@test "build timeout is overridable from the environment" {
  [[ "$(<"$DEVBOX")" == *'DEVBOX_BUILD_TIMEOUT'* ]]
}

# ---------------------------------------------------------------- dispatch ----
@test "--help prints usage and exits 0" {
  # help case is dispatched before `need limactl`, so it works with no VM stack.
  run bash "$DEVBOX" --help
  [ "$status" -eq 0 ]
  [[ "$output" == *"disposable"* ]]
}

@test "--help documents --no-auth" {
  run bash "$DEVBOX" --help
  [ "$status" -eq 0 ]
  [[ "$output" == *"--no-auth"* ]]
}

@test "shortcuts document the agent-config safe default" {
  run bash "$DEVBOX" -h
  [ "$status" -eq 0 ]
  [[ "$output" == *"--with-agent-config, -g"* ]]
  [[ "$output" == *"--gui, -G"* ]]
  [[ "$output" == *"shortcut for --with-agent-config --proxy --ssh-agent"* ]]
  [[ "$output" != *"shortcut for --with-agent-config --proxy --ssh-agent --gui"* ]]
  run bash "$DEVBOX" -V
  [ "$status" -eq 0 ]
  [ "$output" = "devbox $(tr -d "[:space:]" < "$BATS_TEST_DIRNAME/../VERSION")" ]
}

@test "every long run, build, and destroy flag has a single-letter alias" {
  source_text="$(<"$DEVBOX")"
  for alias in \
    '--image|-i' '--keep|-k' '--ephemeral-sessions|-e' '--ssh-agent|-s' '--proxy|-p' '--no-auth|-n' \
    '--api-keys|-K' '--with-creds|-c' '--with-agent-config|-g' \
    '--gui|-G' '--traffic-audit|-T' \
    '--mount|-m' '--copy|-C' '--name|-N' '--force|-f' '--all|-A' '--goldens|-G' \
    '--cpus|-j' '--memory|-M' '--disk|-D' '--yes|-y'; do
    [[ "$source_text" == *"$alias"* ]]
  done
}

@test "sessions path works without Lima and clear has an explicit destructive path" {
  project="$BATS_TEST_TMPDIR/project"
  session_base="$BATS_TEST_TMPDIR/session-root"
  mkdir -p "$project"
  run env DEVBOX_SESSION_DIR="$session_base" bash "$DEVBOX" sessions path "$project"
  [ "$status" -eq 0 ]
  state="$output"
  [[ "$state" == "$session_base/"* ]]
  mkdir -p "$state"
  printf 'session transcript\n' > "$state/example.jsonl"
  run env DEVBOX_SESSION_DIR="$session_base" bash "$DEVBOX" sessions clear --yes "$project"
  [ "$status" -eq 0 ]
  [ ! -e "$state" ]
}

@test "help states that --keep is the only opt-out from cleanup" {
  run bash "$DEVBOX" --help
  [ "$status" -eq 0 ]
  [[ "$output" == *"on exit unless that invocation uses --keep"* ]]
}

@test "--version reads the release version without Lima" {
  run bash "$DEVBOX" --version
  [ "$status" -eq 0 ]
  [ "$output" = "devbox $(tr -d "[:space:]" < "$BATS_TEST_DIRNAME/../VERSION")" ]
}

@test "--version resolves the real path when invoked through a symlink" {
  link="$BATS_TEST_TMPDIR/devbox"
  ln -s "$DEVBOX" "$link"
  run "$link" --version
  [ "$status" -eq 0 ]
  [ "$output" = "devbox $(tr -d "[:space:]" < "$BATS_TEST_DIRNAME/../VERSION")" ]
}

@test "unknown run flag is rejected" {
  command -v limactl >/dev/null || skip "limactl not installed"
  run bash "$DEVBOX" --definitely-not-a-flag
  [ "$status" -ne 0 ]
  [[ "$output" == *"unknown flag"* ]]
}

# ------------------------------------------------ golden sandbox verification --
# Ubuntu 24.04 ships passt 0.0~git20240220, which predates
# `pasta --splice-only`, so requiring it deleted every golden built from the
# default image. bwrap remains fatal; the passt capability only warns.

@test "golden verification probes bwrap and pasta separately" {
  source_text="$(<"$DEVBOX")"
  # A single combined probe cannot report which prerequisite is missing.
  [[ "$source_text" != *'bwrap --unshare-user --unshare-net --uid 0 --gid 0 --ro-bind / / true
    pasta --help'* ]]
  [[ "$source_text" == *"golden cannot run bwrap"* ]]
  [[ "$source_text" == *"the passt build did not succeed"* ]]
}

@test "an unusable bwrap still fails the golden" {
  run bash -c "
    source '$DEVBOX' 2>/dev/null; set +u
    limactl() {
      case \"\$*\" in
        *'for t in'*)             printf '  ok   brew      /home/linuxbrew/.linuxbrew/bin/brew\n';;
        *'bwrap --unshare-user'*) return 1;;
        *known_hosts*) printf 'github.com ssh-rsa A\ngithub.com ssh-ed25519 B\ngithub.com ecdsa-sha2-nistp256 C\n';;
        *) return 0;;
      esac
    }
    verify_golden fake-golden
  "
  [ "$status" -ne 0 ]
  [[ "$output" == *"golden cannot run bwrap"* ]]
}

@test "a passt without --splice-only warns but keeps the golden" {
  run bash -c "
    source '$DEVBOX' 2>/dev/null; set +u
    limactl() {
      case \"\$*\" in
        *'for t in'*)     printf '  ok   brew      /home/linuxbrew/.linuxbrew/bin/brew\n';;
        *'pasta --help'*) return 1;;
        *known_hosts*) printf 'github.com ssh-rsa A\ngithub.com ssh-ed25519 B\ngithub.com ecdsa-sha2-nistp256 C\n';;
        *) return 0;;
      esac
    }
    verify_golden fake-golden
  "
  [ "$status" -eq 0 ]
  [[ "$output" == *"the passt build did not succeed"* ]]
  [[ "$output" == *"the golden is kept"* ]]
}

@test "a golden without Homebrew is rejected, not kept with a warning" {
  # brew installs gh, every AI CLI, and whatever the manifest's provision_user
  # asks for, so keeping a brew-less golden hands an empty toolchain to every
  # box cloned from it long after the build log explaining it has scrolled off.
  run bash -c "
    source '$DEVBOX' 2>/dev/null; set +u
    limactl() {
      case \"\$*\" in
        *'for t in'*) printf '  MISS brew      (not on PATH)\n  ok   claude    /home/u/.local/bin/claude\n';;
        *cloud-init-output.log*) printf 'curl: (22) The requested URL returned error: 429\n';;
        *known_hosts*) printf 'github.com ssh-rsa A\ngithub.com ssh-ed25519 B\ngithub.com ecdsa-sha2-nistp256 C\n';;
        *) return 0;;
      esac
    }
    verify_golden fake-golden
  "
  [ "$status" -ne 0 ]
  [[ "$output" == *"golden has no Homebrew"* ]]
  # the cause is lifted out of the guest before cmd_build deletes the instance
  [[ "$output" == *"429"* ]]
}

@test "an unreachable guest fails verification instead of passing it" {
  # The probe is keyed on a positive 'ok brew' line, so a shell that returns
  # nothing at all cannot read as a clean toolchain.
  run bash -c "
    source '$DEVBOX' 2>/dev/null; set +u
    limactl() { return 1; }
    verify_golden fake-golden
  "
  [ "$status" -ne 0 ]
}

@test "the Homebrew installer fetch retries and falls back off the raw CDN" {
  source_text="$(<"$DEVBOX")"
  # GitHub's raw-content tier fails independently of its API tier — during the
  # 2026-08-17 partial outage raw answered 429 and then nothing at all, while
  # api.github.com served the same file — so a single-source fetch there is
  # what emptied a golden's entire toolchain.
  [[ "$source_text" != *'/bin/bash -c "$(curl -fsSL https://raw.githubusercontent.com/Homebrew/install/HEAD/install.sh)"'* ]]
  [[ "$source_text" == *'https://api.github.com/repos/Homebrew/install/contents/install.sh'* ]]
  [[ "$source_text" == *'Accept: application/vnd.github.raw'* ]]
  [[ "$source_text" == *'devbox: Homebrew is unavailable; the CLI toolchain will be missing'* ]]
}

@test "bwrap AppArmor profile install is not gated on the racy userns sysctl" {
  source_text="$(<"$DEVBOX")"
  # The sysctl is applied by apparmor's own units, so reading it during
  # provisioning races the package upgrade in the same apt run.
  [[ "$source_text" != *'&& [[ "$(</proc/sys/kernel/apparmor_restrict_unprivileged_userns)" == 1 ]]'* ]]
  [[ "$source_text" == *"install -D -m 0644 /usr/share/apparmor/extra-profiles/bwrap-userns-restrict"* ]]
}

@test "a failed apparmor_parser does not abort golden provisioning" {
  source_text="$(<"$DEVBOX")"
  [[ "$source_text" == *"could not load bwrap AppArmor profile; it will load at next boot"* ]]
}

@test "golden provisioning builds a pinned upstream passt when the distro's is too old" {
  source_text="$(<"$DEVBOX")"
  # Ubuntu 24.04's passt predates --splice-only and noble has no backport.
  [[ "$source_text" == *'if ! pasta --help 2>&1 | grep -q -- "--splice-only"; then'* ]]
  # Pinned to a tag AND verified against the commit it must resolve to:
  # passt.top publishes no checksums for its prebuilt binaries.
  [[ "$source_text" == *"passt_tag=2026_07_28.f8df3f1"* ]]
  [[ "$source_text" == *"passt_commit=f8df3f1b228fe19a74a269334fdfe6cc7d0605ce"* ]]
  [[ "$source_text" == *'rev-parse HEAD)" == "$passt_commit"'* ]]
  [[ "$source_text" == *"https://passt.top/passt"* ]]
}

@test "a failed passt build does not abort golden provisioning" {
  source_text="$(<"$DEVBOX")"
  [[ "$source_text" == *"could not build passt \$passt_tag; keeping the distro version"* ]]
}

# ------------------------------------------------------- e2e harness limits ----

@test "e2e builds the golden outside the per-session timeout" {
  suite="$(<"$BATS_TEST_DIRNAME/e2e.sh")"
  # Folding a 90-minute golden build into a capped session made the suite fail
  # on any machine without a golden, and orphan a half-provisioned one.
  [[ "$suite" == *'"$DEVBOX_BIN" build --image ubuntu-24.04 --yes'* ]]
  build_line="$(grep -n 'build --image ubuntu-24.04 --yes' "$BATS_TEST_DIRNAME/e2e.sh" | cut -d: -f1)"
  first_session="$(grep -n 'run_session decline' "$BATS_TEST_DIRNAME/e2e.sh" | head -1 | cut -d: -f1)"
  [ "$build_line" -lt "$first_session" ]
}

@test "e2e session timeout is overridable and no longer 600s" {
  suite="$(<"$BATS_TEST_DIRNAME/e2e.sh")"
  [[ "$suite" == *'DEVBOX_E2E_SESSION_TIMEOUT'* ]]
  [[ "$suite" != *"time.monotonic() + 600"* ]]
}

# ------------------------------------------------- agent trust seeding ----
# Starting a devbox for a directory is the trust decision, so the box
# pre-answers the AI CLIs' first-run gates. These cover the pure merge
# functions; the guest-side wiring is exercised by test/e2e.sh.

@test "claude_trust_config trusts only the mounted directory" {
  run bash -c "printf '' | { source '$DEVBOX'; set +u; claude_trust_config /work/proj ''; }"
  [ "$status" -eq 0 ]
  trusted="$(printf '%s' "$output" | python3 -c 'import json,sys; c=json.load(sys.stdin); print(list(c["projects"]))')"
  [ "$trusted" = "['/work/proj']" ]
  [[ "$output" == *'"hasTrustDialogAccepted": true'* ]]
  [[ "$output" == *'"hasCompletedOnboarding": true'* ]]
}

@test "claude_trust_config preserves unrelated existing config" {
  existing='{"theme":"dark","projects":{"/other":{"allowedTools":["Bash"]}}}'
  run bash -c "printf '%s' '$existing' | { source '$DEVBOX'; set +u; claude_trust_config /work/proj ''; }"
  [ "$status" -eq 0 ]
  [[ "$output" == *'"theme": "dark"'* ]]
  [[ "$output" == *'"/other"'* ]]
  [[ "$output" == *'"/work/proj"'* ]]
}

@test "claude_trust_config approves the key by its last 20 characters" {
  # Claude Code stores an approved custom key as key.trim().slice(-20).
  run bash -c "printf '' | { source '$DEVBOX'; set +u; claude_trust_config /work/proj 'PREFIX-0123456789abcdefghij'; }"
  [ "$status" -eq 0 ]
  [[ "$output" == *'"0123456789abcdefghij"'* ]]
  [[ "$output" != *"PREFIX-0123456789abcdefghij"* ]]
}

@test "claude_trust_config drops a stale rejection for the same key" {
  existing='{"customApiKeyResponses":{"approved":[],"rejected":["devbox-proxy"]}}'
  run bash -c "printf '%s' '$existing' | { source '$DEVBOX'; set +u; claude_trust_config /work/proj devbox-proxy; }"
  [ "$status" -eq 0 ]
  rejected="$(printf '%s' "$output" | python3 -c 'import json,sys; print(json.load(sys.stdin)["customApiKeyResponses"]["rejected"])')"
  [ "$rejected" = "[]" ]
  [[ "$output" == *'"devbox-proxy"'* ]]
}

@test "claude_trust_config records no key approval when none is set" {
  run bash -c "printf '' | { source '$DEVBOX'; set +u; claude_trust_config /work/proj ''; }"
  [ "$status" -eq 0 ]
  [[ "$output" != *"customApiKeyResponses"* ]]
}

@test "claude_trust_config recovers from an unparseable config" {
  run bash -c "printf 'not json{' | { source '$DEVBOX'; set +u; claude_trust_config /work/proj ''; }"
  [ "$status" -eq 0 ]
  [[ "$output" == *'"hasTrustDialogAccepted": true'* ]]
}

@test "codex_trust_config appends a trusted project table" {
  run bash -c "printf 'model = \"x\"' | { source '$DEVBOX'; set +u; codex_trust_config /work/proj; }"
  [ "$status" -eq 0 ]
  [[ "$output" == *'model = "x"'* ]]
  [[ "$output" == *'[projects."/work/proj"]'* ]]
  [[ "$output" == *'trust_level = "trusted"'* ]]
}

@test "codex_trust_config leaves an answer already on record alone" {
  # A host config copied in with --with-agent-config, or an earlier run.
  existing=$'[projects."/work/proj"]\ntrust_level = "untrusted"\n'
  run bash -c "printf '%s' '$existing' | { source '$DEVBOX'; set +u; codex_trust_config /work/proj; }"
  [ "$status" -eq 0 ]
  [ "$output" = "$(printf '%s' "$existing")" ]
}

@test "codex_trust_config is idempotent" {
  once="$(printf '' | bash -c "source '$DEVBOX'; set +u; codex_trust_config /work/proj")"
  twice="$(printf '%s\n' "$once" | bash -c "source '$DEVBOX'; set +u; codex_trust_config /work/proj")"
  [ "$once" = "$(printf '%s' "$twice")" ]
}

@test "codex_trust_config emits parseable TOML for a path needing escapes" {
  run bash -c "printf '' | { source '$DEVBOX'; set +u; codex_trust_config '/work/my \"repo\"'; }"
  [ "$status" -eq 0 ]
  run bash -c "printf '%s' '$output' | python3 -c 'import sys,tomllib; d=tomllib.loads(sys.stdin.read()); print(d[\"projects\"][\"/work/my \\\"repo\\\"\"][\"trust_level\"])'"
  [ "$status" -eq 0 ]
  [ "$output" = "trusted" ]
}

@test "seed_agent_trust runs on every box, with no flag to gate it" {
  source_text="$(<"$DEVBOX")"
  [[ "$source_text" == *'seed_agent_trust "$name" "$dir"'* ]]
  run bash "$DEVBOX" -h
  [ "$status" -eq 0 ]
  [[ "$output" == *"Agent first-run prompts"* ]]
}

@test "guest_login_value survives a guest profile that greets on stdout" {
  # A login shell is needed for /etc/profile.d values, but a chatty profile must
  # not be mistaken for the value: that used to corrupt the merged config and
  # produce a garbage CODEX_HOME path.
  run bash -c "
    source '$DEVBOX' 2>/dev/null; set +u
    limactl() { printf 'Welcome to Ubuntu! 3 updates available.\n<devbox:/home/u/.codex:xobved>'; }
    guest_login_value fake-box '\${CODEX_HOME:-\$HOME/.codex}'
  "
  [ "$status" -eq 0 ]
  [ "$output" = "/home/u/.codex" ]
}

@test "guest_login_value yields empty when the fence never appears" {
  run bash -c "
    source '$DEVBOX' 2>/dev/null; set +u
    limactl() { echo 'limactl: instance not running'; return 1; }
    guest_login_value fake-box '\${ANTHROPIC_API_KEY:-}'
  "
  [ "$output" = "" ]
}
