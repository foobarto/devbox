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
@test "golden yaml has no host mount and does not load host pubkeys" {
  tmp="$BATS_TEST_TMPDIR/g.yaml"
  emit_golden_yaml ubuntu-24.04 "$tmp"
  grep -q '^mounts: \[\]' "$tmp"
  grep -q 'loadDotSSHPubKeys: false' "$tmp"
}

@test "a golden leaves SSH-agent forwarding disabled until explicitly requested" {
  tmp="$BATS_TEST_TMPDIR/g.yaml"
  emit_golden_yaml ubuntu-24.04 "$tmp"
  ! grep -q 'forwardAgent: true' "$tmp"
}

@test "a golden disables Lima's unused containerd bootstrap" {
  tmp="$BATS_TEST_TMPDIR/g.yaml"
  emit_golden_yaml ubuntu-24.04 "$tmp"
  grep -A2 '^containerd:' "$tmp" | grep -q 'system: false'
  grep -A2 '^containerd:' "$tmp" | grep -q 'user: false'
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

@test "GitHub proxy URL rejects a proxy URL with existing credentials or a path" {
  run bash -c 'printf %s "$2" | { source "$1"; github_proxy_url "$3"; }' _ "$DEVBOX" "part.one" "http://user@host.lima.internal:4141"
  [ "$status" -ne 0 ]
  run bash -c 'printf %s "$2" | { source "$1"; github_proxy_url "$3"; }' _ "$DEVBOX" "part.one" "http://host.lima.internal:4141/path"
  [ "$status" -ne 0 ]
}

@test "proxy setup keeps gh credentials on the host behind a guest wrapper" {
  source_text="$(<"$DEVBOX")"
  [[ "$source_text" == *'gh-wrapper.py'* ]]
  [[ "$source_text" == *'zz-devbox-12-gh-proxy.sh'* ]]
  [[ "$source_text" == *'gh-proxy-ca.pem'* ]]
  [[ "$source_text" == *'gh auth login'* ]]
  [[ "$source_text" == *'rm -rf "$HOME/.devbox/codex-proxy" "$HOME/.devbox/gh-proxy"'* ]]
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
@test "golden yaml carries resolved resources" {
  out="$BATS_TEST_TMPDIR/g.yaml"
  emit_golden_yaml ubuntu-24.04 "$out" 8 "12GiB" "80GiB"
  grep -q '^cpus: 8$' "$out"
  grep -q '^memory: "12GiB"$' "$out"
  grep -q '^disk: "80GiB"$' "$out"
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
  # command line; they are piped to `bash -s`.
  run declare -f apply_golden_provisioning
  [ "$status" -eq 0 ]
  [[ "$output" == *"bash -s"* ]]
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
  [[ "$output" == *"shortcut for --with-agent-config --proxy --ssh-agent"* ]]
  run bash "$DEVBOX" -V
  [ "$status" -eq 0 ]
  [ "$output" = "devbox $(tr -d "[:space:]" < "$BATS_TEST_DIRNAME/../VERSION")" ]
}

@test "every long run, build, and destroy flag has a single-letter alias" {
  source_text="$(<"$DEVBOX")"
  for alias in \
    '--image|-i' '--keep|-k' '--ssh-agent|-s' '--proxy|-p' '--no-auth|-n' \
    '--api-keys|-K' '--with-creds|-c' '--with-agent-config|-g' \
    '--mount|-m' '--copy|-C' '--name|-N' '--force|-f' '--all|-A' '--goldens|-G' \
    '--cpus|-j' '--memory|-M' '--disk|-D' '--yes|-y'; do
    [[ "$source_text" == *"$alias"* ]]
  done
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
