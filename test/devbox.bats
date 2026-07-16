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
  set +eu   # relax the script's `set -euo pipefail` for the test body
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

@test "golden yaml installs the AI toolchain (stado via cask, claude installer)" {
  tmp="$BATS_TEST_TMPDIR/g.yaml"
  emit_golden_yaml ubuntu-24.04 "$tmp"
  grep -q 'brew install --cask foobarto/tap/stado' "$tmp"
  grep -q 'brew install codex' "$tmp"
  grep -q 'sst/tap/opencode' "$tmp"
  grep -q 'claude.ai/install.sh' "$tmp"
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

# ---------------------------------------------------------------- dispatch ----
@test "--help prints usage and exits 0" {
  # help case is dispatched before `need limactl`, so it works with no VM stack.
  run bash "$DEVBOX" --help
  [ "$status" -eq 0 ]
  [[ "$output" == *"disposable"* ]]
}

@test "unknown run flag is rejected" {
  command -v limactl >/dev/null || skip "limactl not installed"
  run bash "$DEVBOX" --definitely-not-a-flag
  [ "$status" -ne 0 ]
  [[ "$output" == *"unknown flag"* ]]
}
