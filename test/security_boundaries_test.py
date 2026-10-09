"""Synthetic host/guest boundary checks: no real VMs, firewall, or credentials."""
import json
import os
from pathlib import Path
import re
import subprocess
import sys
import tempfile
from unittest import TestCase


ROOT = Path(__file__).resolve().parents[1]
DEVBOX = ROOT / "bin" / "devbox"
IDENTITIES = ROOT / "proxy" / "devbox-identities.py"


class SecurityBoundaryTests(TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory(prefix="devbox-boundary-test-")
        self.addCleanup(self.temporary.cleanup)
        self.root = Path(self.temporary.name)
        self.home = self.root / "home"
        self.home.mkdir()
        self.config = self.root / "config"
        self.project = self.root / "project"
        self.project.mkdir()
        self.events = self.root / "events"
        self.environment = dict(os.environ, HOME=str(self.home),
                                DEVBOX_CONFIG_DIR=str(self.config),
                                DEVBOX_SESSION_DIR=str(self.root / "sessions"),
                                XDG_STATE_HOME=str(self.root / "xdg-state"),
                                XDG_CONFIG_HOME=str(self.home / ".config"),
                                DEVBOX_PROXY_STATE_DIR=str(self.config),
                                FIXTURE_EVENTS=str(self.events))
        for key in ("DEVBOX_PROXY_CONFIG", "DEVBOX_POLICY", "BASH_ENV", "ENV"):
            self.environment.pop(key, None)

    def shell(self, body, *args):
        return subprocess.run(["bash", "-c", 'source "$1"; shift\n' + body,
                               "boundary-fixture", str(DEVBOX), *map(str, args)],
                              env=self.environment, capture_output=True, text=True, timeout=15)

    def identity(self, operation, payload=None):
        arguments = [sys.executable, str(IDENTITIES), str(self.config),
                     "golden", operation, "devbox-golden-fixture"]
        if payload is not None:
            arguments.append(json.dumps(payload))
        return subprocess.run(arguments, env=self.environment, capture_output=True,
                              text=True, timeout=5)

    def test_golden_checks_full_metadata_and_missing_records(self):
        specification = {"schema": 2, "bootstrap": "integrity-checked-v1",
                         "location": "fixture-image", "digest": "sha256:fixture",
                         "provision": "echo root-fixture", "provision_user": "echo user-fixture"}
        self.assertNotEqual(self.identity("check", specification).returncode, 0)
        self.assertEqual(self.identity("write", specification).returncode, 0)
        self.assertEqual(self.identity("check", specification).returncode, 0)
        for field in specification:
            with self.subTest(field=field):
                changed = dict(specification, **{field: "different-fixture"})
                result = self.identity("check", changed)
                self.assertNotEqual(result.returncode, 0)
                self.assertIn("provenance does not match", result.stderr)
        record = self.config / "golden-identities" / "devbox-golden-fixture.json"
        self.assertEqual(record.stat().st_mode & 0o777, 0o600)
        self.assertEqual(record.parent.stat().st_mode & 0o777, 0o700)

    def test_golden_refuses_symlink_and_public_record(self):
        specification = {"schema": 2, "location": "fixture"}
        self.assertEqual(self.identity("write", specification).returncode, 0)
        record = self.config / "golden-identities" / "devbox-golden-fixture.json"
        record.chmod(0o644)
        self.assertNotEqual(self.identity("check", specification).returncode, 0)
        target = self.root / "synthetic-record.json"
        target.write_text(json.dumps(specification))
        target.chmod(0o600)
        record.unlink()
        record.symlink_to(target)
        self.assertNotEqual(self.identity("check", specification).returncode, 0)
        self.assertEqual(json.loads(target.read_text()), specification)

    def test_existing_box_owner_refusal_precedes_all_mutation(self):
        body = """
instance_exists() { return 0; }
require_ssh_agent() { return 0; }
global_default_policy() { return 0; }
global_config_json() { printf '{}'; }
mutated() { printf '%s\\n' "$1" >> "$FIXTURE_EVENTS"; return 91; }
for operation in prepare_session_dir ensure_session_mount enable_ssh_agent proxy_ensure apply_ai_proxy apply_gh_proxy apply_connect_traffic_audit prepare_host_inputs apply_git_signing limactl; do
  eval "$operation() { mutated $operation; }"
done
cmd_run --keep --name devbox-fixture --ssh-agent --proxy --gh-proxy "$1"
"""
        result = self.shell(body, self.project)
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("not registered to this project", result.stderr)
        self.assertFalse(self.events.exists(), self.events.read_text() if self.events.exists() else "")
        self.assertFalse((self.root / "sessions").exists())
        wrong_project = self.root / "different-project"
        wrong_project.mkdir()
        recorded = self.shell('record_instance_owner devbox-fixture "$1"', wrong_project)
        self.assertEqual(recorded.returncode, 0, recorded.stderr)
        result = self.shell(body, self.project)
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("not registered to this project", result.stderr)
        self.assertFalse(self.events.exists())

    def test_matching_box_owner_attaches_to_a_running_box_without_restarting_it(self):
        self.environment["FIXTURE_PROJECT"] = str(self.project)
        self.environment["FIXTURE_STATUS"] = str(self.root / "status")
        (self.root / "status").write_text("Running")
        body = """
record_instance_owner devbox-fixture "$1"
instance_exists() { return 0; }
global_default_policy() { return 0; }
global_config_json() { printf '{}'; }
require_project_writable() { printf 'writable\\n' >> "$FIXTURE_EVENTS"; }
instance_status() { cat "$FIXTURE_STATUS"; }
session_state_other_instance() { return 0; }
guest_mount_paths() { printf '%s\\n' "$FIXTURE_PROJECT"; }
guest_writable_mount_paths() { printf '%s\\n' "$FIXTURE_PROJECT"; }
ensure_session_mount() { printf 'session-mount\\n' >> "$FIXTURE_EVENTS"; }
apply_session_persistence() { printf 'session-profile\\n' >> "$FIXTURE_EVENTS"; }
seed_agent_trust() { printf 'agent-trust\\n' >> "$FIXTURE_EVENTS"; }
limactl() {
  printf '%s\\n' "$1" >> "$FIXTURE_EVENTS"
  case "$1" in
    stop) printf Stopped > "$FIXTURE_STATUS";;
    start) printf Running > "$FIXTURE_STATUS";;
    shell) return 0;;
    *) return 92;;
  esac
}
cmd_run --keep --name devbox-fixture "$1"
[[ -z "$_DB_INPUT_SNAPSHOT" ]]
"""
        result = self.shell(body, self.project)
        self.assertEqual(result.returncode, 0, result.stderr)
        events = self.events.read_text().splitlines()
        self.assertEqual(events[0], "writable")
        # Re-entering a running kept box must not stop it: other shells, agents
        # and servers inside it keep running.
        self.assertNotIn("stop", events)
        self.assertNotIn("start", events)
        self.assertLess(events.index("session-mount"), events.index("session-profile"))
        self.assertLess(events.index("session-profile"), events.index("agent-trust"))
        self.assertEqual(events[-1], "shell")
        self.assertEqual((self.root / "status").read_text(), "Running")

    def test_grant_source_writable_by_another_instance_is_refused_before_snapshot(self):
        shared = self.root / "shared"
        shared.mkdir()
        (shared / "settings.json").write_text("{}")
        self.environment["FIXTURE_PROJECT"] = str(self.project)
        self.environment["FIXTURE_SHARED"] = str(shared)
        body = """
record_instance_owner devbox-fixture "$1"
instance_exists() { return 0; }
global_default_policy() { return 0; }
global_config_json() { printf '{}'; }
require_project_writable() { :; }
instance_status() { printf Running; }
session_state_other_instance() { return 0; }
guest_mount_paths() { printf '%s\\n' "$FIXTURE_PROJECT"; }
# Another stored instance mounts $FIXTURE_SHARED writable.
guest_writable_mount_paths() { printf '%s\\n' "$FIXTURE_PROJECT" "$FIXTURE_SHARED"; }
limactl() { printf '%s\\n' "$1" >> "$FIXTURE_EVENTS"; return 0; }
cmd_run --keep --name devbox-fixture --copy "$FIXTURE_SHARED/settings.json" "$1"
"""
        result = self.shell(body, self.project)
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("writable by another Lima instance", result.stderr)
        events = self.events.read_text().splitlines() if self.events.exists() else []
        self.assertNotIn("shell", events)
        self.assertNotIn("copy", events)

    def test_new_clone_identity_failure_stops_revokes_and_deletes_destination(self):
        self.environment["FIXTURE_PROJECT"] = str(self.project)
        self.environment["FIXTURE_CLONED"] = str(self.root / "cloned")
        body = """
golden="$(golden_name "$DEFAULT_IMAGE")"
identity_state golden write "$golden" "$(golden_identity "$DEFAULT_IMAGE" "" "" "")"
instance_exists() { [[ "$1" == devbox-golden-* ]]; }
global_default_policy() { return 0; }
global_config_json() { printf '{}'; }
session_state_other_instance() { return 0; }
guest_mount_paths() { return 0; }
guest_writable_mount_paths() { return 0; }
ensure_golden_stopped() { return 0; }
verify_mount_identities() { [[ ! -f "$FIXTURE_CLONED" ]]; }
revoke_ai_proxy_token() { printf 'revoke-ai\\n' >> "$FIXTURE_EVENTS"; }
clear_gh_proxy_endpoint() { printf 'revoke-gh\\n' >> "$FIXTURE_EVENTS"; }
clear_traffic_proxy_endpoint() { printf 'revoke-traffic\\n' >> "$FIXTURE_EVENTS"; }
forget_instance_identity() { printf 'forget-identity\\n' >> "$FIXTURE_EVENTS"; }
limactl() {
  case "$1" in
    list) printf 107374182400;;
    --tty=false)
      [[ "$2" == clone ]]
      printf 'clone\\n' >> "$FIXTURE_EVENTS"
      printf created > "$FIXTURE_CLONED";;
    stop) printf 'stop\\n' >> "$FIXTURE_EVENTS";;
    delete) printf 'delete\\n' >> "$FIXTURE_EVENTS"; rm "$FIXTURE_CLONED";;
    *) printf 'unexpected-%s\\n' "$1" >> "$FIXTURE_EVENTS"; return 92;;
  esac
}
cmd_run --keep --name devbox-fixture "$1"
"""
        result = self.shell(body, self.project)
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("approved mount source changed", result.stderr)
        events = self.events.read_text().splitlines()
        self.assertEqual(events[0], "clone")
        self.assertIn("stop", events)
        self.assertIn("revoke-ai", events)
        self.assertIn("revoke-gh", events)
        self.assertIn("revoke-traffic", events)
        self.assertLess(events.index("revoke-traffic"), events.index("delete"))
        self.assertEqual(events[-1], "forget-identity")
        self.assertFalse((self.root / "cloned").exists())

    def test_bulk_revocation_attempts_every_grant_when_any_helper_exits(self):
        body = """
record_revocation() {
  printf '%s\\n' "$1" >> "$FIXTURE_EVENTS"
  [[ "$FIXTURE_FAIL" != "$1" ]] || exit 23
}
revoke_ai_proxy_token() { record_revocation ai; }
clear_gh_proxy_endpoint() { record_revocation github; }
clear_traffic_proxy_endpoint() { record_revocation traffic; }
revoke_proxy_grants devbox-fixture
"""
        for failed in ("ai", "github", "traffic"):
            with self.subTest(failed=failed):
                self.events.unlink(missing_ok=True)
                self.environment["FIXTURE_FAIL"] = failed
                result = self.shell(body)
                self.assertEqual(result.returncode, 1)
                self.assertEqual(self.events.read_text().splitlines(), ["ai", "github", "traffic"])

    def test_kept_policy_and_no_auth_revoke_removed_grants_before_boot(self):
        self.environment["FIXTURE_PROJECT"] = str(self.project)
        self.environment["FIXTURE_STATUS"] = str(self.root / "status")
        body = """
record_instance_owner devbox-fixture "$1"
instance_exists() { return 0; }
global_default_policy() { return 0; }
global_config_json() { printf '{}'; }
require_project_writable() { return 0; }
instance_status() { cat "$FIXTURE_STATUS"; }
session_state_other_instance() { return 0; }
guest_mount_paths() { printf '%s\\n' "$FIXTURE_PROJECT"; }
guest_writable_mount_paths() { printf '%s\\n' "$FIXTURE_PROJECT"; }
ensure_session_mount() { return 0; }
apply_session_persistence() { return 0; }
seed_agent_trust() { return 0; }
clear_auth() { printf 'guest-auth-cleanup\\n' >> "$FIXTURE_EVENTS"; }
revoke_ai_proxy_token() { printf 'revoke-ai\\n' >> "$FIXTURE_EVENTS"; }
clear_gh_proxy_endpoint() { printf 'revoke-gh\\n' >> "$FIXTURE_EVENTS"; }
clear_traffic_proxy_endpoint() { printf 'revoke-traffic\\n' >> "$FIXTURE_EVENTS"; }
limactl() {
  printf '%s\\n' "$1" >> "$FIXTURE_EVENTS"
  case "$1" in
    stop) printf Stopped > "$FIXTURE_STATUS";;
    start) printf Running > "$FIXTURE_STATUS";;
    shell) return 0;;
    *) return 92;;
  esac
}
project="$1"; shift
cmd_run --keep --name devbox-fixture "$@" "$project"
"""
        for status in ("Running", "Stopped"):
            for flags, revoked in ((("--policy", "none"), ("ai", "gh", "traffic")),
                                   (("--no-auth",), ("ai", "gh"))):
                with self.subTest(status=status, flags=flags):
                    self.events.unlink(missing_ok=True)
                    (self.root / "status").write_text(status)
                    result = self.shell(body, self.project, *flags)
                    self.assertEqual(result.returncode, 0, result.stderr)
                    events = self.events.read_text().splitlines()
                    # Revocation is live; a running box is not restarted for it.
                    self.assertNotIn("stop", events)
                    for grant in revoked:
                        if status == "Stopped":
                            self.assertLess(events.index("revoke-" + grant), events.index("start"))
                        self.assertLess(events.index("revoke-" + grant), events.index("shell"))
                    self.assertEqual(events[-1], "shell")

    def retained_traffic_body(self):
        self.environment["FIXTURE_PROJECT"] = str(self.project)
        self.environment["FIXTURE_STATUS"] = str(self.root / "status")
        return """
record_instance_owner devbox-fixture "$1"
case "$2" in
  matching) record_traffic_firewall devbox-fixture http://fixture.example:4141;;
  wrong) record_traffic_firewall devbox-fixture http://different.example:4141;;
esac
instance_exists() { return 0; }
global_default_policy() { return 0; }
global_config_json() { printf '{}'; }
require_project_writable() { return 0; }
instance_status() { cat "$FIXTURE_STATUS"; }
session_state_other_instance() { return 0; }
guest_mount_paths() { printf '%s\\n' "$FIXTURE_PROJECT"; }
guest_writable_mount_paths() { printf '%s\\n' "$FIXTURE_PROJECT"; }
ensure_session_mount() { return 0; }
apply_session_persistence() { return 0; }
seed_agent_trust() { return 0; }
stored_traffic_proxy_endpoint() { printf http://fixture.example:4141; }
ensure_guest_nftables() { return 0; }
apply_connect_traffic_firewall() { printf 'persist-policy\\n' >> "$FIXTURE_EVENTS"; }
apply_connect_traffic_audit() { printf 'traffic-profile\\n' >> "$FIXTURE_EVENTS"; }
proxy_ensure() { printf 'proxy-ready\\n' >> "$FIXTURE_EVENTS"; }
limactl() {
  printf '%s\\n' "$1" >> "$FIXTURE_EVENTS"
  case "$1" in
    stop)
      identity_state traffic check devbox-fixture "$(traffic_firewall_identity http://fixture.example:4141)"
      printf Stopped > "$FIXTURE_STATUS";;
    start) printf Running > "$FIXTURE_STATUS";;
    shell) return 0;;
    *) return 92;;
  esac
}
cmd_run --keep --name devbox-fixture "$1"
"""

    def test_stopped_audited_box_missing_or_wrong_boot_marker_refuses_before_start(self):
        body = self.retained_traffic_body()
        for marker in ("missing", "wrong"):
            with self.subTest(marker=marker):
                (self.root / "status").write_text("Stopped")
                result = self.shell(body, self.project, marker)
                self.assertNotEqual(result.returncode, 0)
                self.assertIn("predates boot-time egress enforcement", result.stderr)
                self.assertFalse(self.events.exists())
                self.assertEqual((self.root / "status").read_text(), "Stopped")

    def test_stopped_audited_box_matching_boot_marker_permits_start(self):
        body = self.retained_traffic_body()
        (self.root / "status").write_text("Stopped")
        result = self.shell(body, self.project, "matching")
        self.assertEqual(result.returncode, 0, result.stderr)
        events = self.events.read_text().splitlines()
        self.assertEqual(events[0], "start")
        self.assertNotIn("persist-policy", events)
        self.assertLess(events.index("start"), events.index("traffic-profile"))
        self.assertEqual(events[-1], "shell")

    def test_running_audited_box_persists_and_records_boot_marker_in_place(self):
        body = self.retained_traffic_body()
        (self.root / "status").write_text("Running")
        result = self.shell(body, self.project, "missing")
        self.assertEqual(result.returncode, 0, result.stderr)
        events = self.events.read_text().splitlines()
        self.assertIn("persist-policy", events)
        self.assertNotIn("stop", events)
        marker = self.config / "traffic-identities/devbox-fixture.json"
        self.assertEqual(json.loads(marker.read_text()),
                         {"schema": 1, "endpoint": "http://fixture.example:4141", "boot_policy": "systemd-v1"})
        self.assertEqual(marker.stat().st_mode & 0o777, 0o600)

    def firewall(self, check_fails):
        state = self.root / "firewall-state"
        state.write_text("existing-deny-policy\n")
        commands = self.root / "fake-bin"
        commands.mkdir()
        guest = self.root / "guest"
        (guest / "run" / "systemd" / "system").mkdir(parents=True)
        self.guest = guest
        runner = commands / "guest-runner.py"
        runner.write_text("""import os, shlex, subprocess, sys
root = os.environ["FIXTURE_GUEST"]
def translate(script):
    # Production fixes root's PATH. The disposable guest copy instead pins
    # it to the fixture's fake commands so it cannot reach the host firewall.
    script = script.replace("export PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin",
                            "export PATH=" + shlex.quote(os.environ["PATH"]))
    for path in ("/usr/local/libexec", "/etc", "/run"):
        script = script.replace(path, root + path)
    return script
arguments = sys.argv[1:]
if arguments[:2] == ["bash", "-s"]:
    result = subprocess.run(arguments, input=translate(sys.stdin.read()), text=True)
elif arguments[:2] == ["bash", "-c"]:
    arguments[2] = translate(arguments[2])
    result = subprocess.run(arguments)
else:
    raise SystemExit("unsupported synthetic guest command")
raise SystemExit(result.returncode)
""")
        sudo = commands / "sudo"
        sudo.write_text("""#!/usr/bin/env python3
import os, pathlib, subprocess, sys
arguments = sys.argv[1:]
root = os.environ["FIXTURE_GUEST"]
command = arguments[0]
if command in ("nft", "systemctl"):
    raise SystemExit(subprocess.run(arguments).returncode)
if command == "install":
    if not arguments[-1].startswith(root + "/"):
        raise SystemExit("fixture install destination escaped guest root")
    # Owner/group changes are represented by the sudo boundary in this
    # unprivileged fixture; actual modes and assets are still installed.
    clean = [command]
    index = 1
    while index < len(arguments):
        if arguments[index] in ("-o", "-g"):
            index += 2
        else:
            clean.append(arguments[index]); index += 1
    if "-d" in clean:
        # The directory form may have multiple destinations. Verify every
        # absolute operand, not just the last one.
        if any(not value.startswith(root + "/") for value in clean[1:] if value.startswith("/")):
            raise SystemExit("fixture directory destination escaped guest root")
    raise SystemExit(subprocess.run(clean).returncode)
if command in ("rm", "rmdir", "mv"):
    if any(not value.startswith(root + "/") for value in arguments[1:] if not value.startswith("-")):
        raise SystemExit("fixture removal escaped guest root")
    with open(os.environ["FIXTURE_EVENTS"], "a") as events:
        events.write(command + " " + " ".join(arguments[1:]) + "\\n")
    raise SystemExit(subprocess.run(arguments).returncode)
if command == "mktemp":
    if not arguments[-1].startswith(root + "/"):
        raise SystemExit("fixture temporary escaped guest root")
    raise SystemExit(subprocess.run(arguments).returncode)
if command.startswith(root + "/"):
    raise SystemExit(subprocess.run(arguments).returncode)
raise SystemExit("unsupported synthetic sudo command: " + command)
""")
        sudo.chmod(0o700)
        systemctl = commands / "systemctl"
        systemctl.write_text("""#!/bin/bash
set -euo pipefail
printf 'systemctl %s\\n' "$*" >> "$FIXTURE_EVENTS"
[[ "$FIXTURE_SYSTEMD" == 1 ]] || exit 1
case "$1" in
  --version) printf 'systemd fixture\\n';;
  show) if [[ "$2" == NetworkManager.service ]]; then printf 'loaded\\n'; else printf 'not-found\\n'; fi;;
  daemon-reload|enable|disable) exit 0;;
  *) exit 94;;
esac
""")
        systemctl.chmod(0o700)
        getent = commands / "getent"
        getent.write_text("#!/bin/bash\nprintf '192.0.2.20 STREAM fixture\\n'\n")
        getent.chmod(0o700)
        nft = commands / "nft"
        nft.write_text("""#!/bin/bash
set -euo pipefail
printf 'nft %s\\n' "$*" >> "$FIXTURE_EVENTS"
if [[ "$1" == list ]]; then [[ -f "$FIXTURE_FIREWALL" ]]; exit; fi
if [[ "$1" == -c ]]; then
  cp "$3" "$FIXTURE_RULES"
  [[ "$FIXTURE_CHECK_FAILS" == 0 ]] || exit 42
  exit 0
fi
if [[ "$1" == -f ]]; then cp "$2" "$FIXTURE_FIREWALL"; exit 0; fi
if [[ "$1" == delete ]]; then rm -f "$FIXTURE_FIREWALL"; exit 0; fi
exit 90
""")
        nft.chmod(0o700)
        self.environment.update(FIXTURE_CHECK_FAILS=str(int(check_fails)),
                                FIXTURE_RULES=str(self.root / "checked-rules"),
                                FIXTURE_FIREWALL=str(state),
                                FIXTURE_GUEST=str(guest),
                                FIXTURE_SYSTEMD="1",
                                PATH=str(commands) + os.pathsep + self.environment["PATH"])
        body = """
limactl() { shift 3; python3 "$FIXTURE_GUEST_RUNNER" "$@"; }
apply_connect_traffic_firewall devbox-fixture fixture.example 4141
"""
        self.environment["FIXTURE_GUEST_RUNNER"] = str(runner)
        return self.shell(body), state

    def firewall_action(self, command):
        body = """
limactl() { shift 3; python3 "$FIXTURE_GUEST_RUNNER" "$@"; }
clear_traffic_proxy_endpoint() { printf 'revoke-traffic\\n' >> "$FIXTURE_EVENTS"; }
""" + command
        return self.shell(body)

    def test_firewall_check_failure_preserves_existing_rules(self):
        result, state = self.firewall(check_fails=True)
        self.assertEqual(result.returncode, 42)
        self.assertEqual(state.read_text(), "existing-deny-policy\n")
        lines = self.events.read_text().splitlines()
        calls = [line.removeprefix("nft ") for line in lines if line.startswith("nft ")]
        # The staged ruleset is validated before anything is installed or
        # applied, so a rejected ruleset never reaches the boot path.
        self.assertEqual(len(calls), 1)
        self.assertTrue(calls[0].startswith("-c -f "))
        self.assertFalse(any(line.startswith(("systemctl enable", "systemctl daemon-reload")) for line in lines))
        rules = (self.root / "checked-rules").read_text()
        self.assertIn("tcp dport { 80, 443 } reject", rules)

    def test_firewall_success_uses_one_checked_replacement_transaction(self):
        result, state = self.firewall(check_fails=False)
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(state.read_text(), (self.root / "checked-rules").read_text())
        calls = [line.removeprefix("nft ") for line in self.events.read_text().splitlines()
                 if line.startswith("nft ")]
        self.assertEqual(sum(call.startswith("-f ") for call in calls), 1)
        self.assertTrue(calls[-1].startswith("-f "))
        self.assertFalse(any(call.startswith("delete ") for call in calls))

    def test_firewall_persists_boot_guard_and_restores_empty_runtime_before_network(self):
        result, state = self.firewall(check_fails=False)
        self.assertEqual(result.returncode, 0, result.stderr)
        policy = self.guest / "etc/devbox/traffic-audit.nft"
        wrapper = self.guest / "usr/local/libexec/devbox-traffic-audit"
        unit = self.guest / "etc/systemd/system/devbox-traffic-audit.service"
        self.assertEqual(policy.stat().st_mode & 0o777, 0o600)
        self.assertEqual(wrapper.stat().st_mode & 0o777, 0o755)
        self.assertEqual(unit.stat().st_mode & 0o777, 0o644)
        unit_text = unit.read_text()
        self.assertIn("DefaultDependencies=no", unit_text)
        self.assertIn("Before=network-pre.target", unit_text)
        self.assertIn("WantedBy=network-pre.target", unit_text)
        self.assertIn("nftables.service ufw.service firewalld.service", unit_text)
        for network in ("NetworkManager", "systemd-networkd", "networking", "wicked", "wickedd", "ifup@"):
            dependency = self.guest / ("etc/systemd/system/" + network + ".service.d/10-devbox-traffic-audit.conf")
            self.assertEqual(dependency.stat().st_mode & 0o777, 0o644)
            self.assertIn("Requires=devbox-traffic-audit.service", dependency.read_text())
            self.assertIn("After=devbox-traffic-audit.service", dependency.read_text())
        self.assertIn("systemctl enable devbox-traffic-audit.service", self.events.read_text())
        # A reboot empties the runtime table. Execute the installed disposable
        # wrapper itself to prove it reads persisted rules and checks them first.
        state.unlink()
        self.events.unlink()
        result = subprocess.run([str(wrapper)], env=self.environment,
                                capture_output=True, text=True, timeout=10)
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(state.read_text(), policy.read_text())
        calls = self.events.read_text().splitlines()
        self.assertEqual(len(calls), 3)
        self.assertTrue(calls[0].startswith("nft list table"))
        self.assertTrue(calls[1].startswith("nft -c -f "))
        self.assertTrue(calls[2].startswith("nft -f "))

    def test_firewall_clear_removes_own_assets_and_preserves_unrelated_network_config(self):
        result, state = self.firewall(check_fails=False)
        self.assertEqual(result.returncode, 0, result.stderr)
        network_directory = self.guest / "etc/systemd/system/NetworkManager.service.d"
        unrelated = network_directory / "unrelated.conf"
        unrelated.write_text("[Service]\nEnvironment=FIXTURE=1\n")
        self.events.unlink()
        result = self.firewall_action("clear_connect_traffic_audit devbox-fixture")
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertTrue(unrelated.exists())
        self.assertFalse(state.exists())
        self.assertFalse((self.guest / "etc/devbox/traffic-audit.nft").exists())
        self.assertFalse((self.guest / "usr/local/libexec/devbox-traffic-audit").exists())
        self.assertFalse((self.guest / "etc/systemd/system/devbox-traffic-audit.service").exists())
        self.assertFalse(list((self.guest / "etc/systemd/system").glob("*.service.d/10-devbox-traffic-audit.conf")))
        calls = self.events.read_text().splitlines()
        reload_index = calls.index("systemctl daemon-reload")
        disable_index = calls.index("systemctl disable --now devbox-traffic-audit.service")
        last_dependency_removal = max(index for index, call in enumerate(calls)
                                      if call.startswith("rm ") and "10-devbox-traffic-audit.conf" in call)
        self.assertLess(last_dependency_removal, reload_index)
        self.assertLess(reload_index, disable_index)
        self.assertEqual(calls[-1], "nft delete table inet devbox_traffic_audit")

    def test_firewall_missing_systemd_refuses_without_changing_existing_policy(self):
        result, state = self.firewall(check_fails=False)
        self.assertEqual(result.returncode, 0, result.stderr)
        previous = state.read_text()
        (self.guest / "run/systemd/system").rmdir()
        self.events.unlink()
        result = self.firewall_action("apply_connect_traffic_firewall devbox-fixture fixture.example 4141")
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("requires a systemd guest", result.stderr)
        self.assertEqual(state.read_text(), previous)
        self.assertFalse(self.events.exists())

    def test_workflow_merges_only_the_verified_immutable_expected_head(self):
        workflow = (ROOT / ".github/workflows/sync-site-version.yml").read_text()
        self.assertIn('expected_head="$(git rev-parse HEAD)"', workflow)
        self.assertRegex(workflow, r'gh pr merge[^\n]+--match-head-commit "\$expected_head"')
        self.assertIn(".head.repo.full_name, .head.ref, .head.sha, .base.ref", workflow)
        self.assertIn('gh pr diff "$pr_url" --name-only', workflow)
        self.assertIn("secrets.token_hex", workflow)
        self.assertNotIn("existing_pr=", workflow)
        self.assertLess(workflow.index('expected_head="$(git rev-parse HEAD)"'),
                        workflow.index('git push --set-upstream'))

    def test_bootstrap_has_immutable_homebrew_ref_integrity_check_and_no_pipe_installers(self):
        generated = self.root / "golden.yaml"
        result = self.shell('emit_golden_yaml ubuntu-24.04 "$1"', generated)
        self.assertEqual(result.returncode, 0, result.stderr)
        script = generated.read_text()
        self.assertNotIn("Homebrew/install/HEAD/", script)
        self.assertRegex(script, r'raw\.githubusercontent\.com/Homebrew/install/[0-9a-f]{40}/install\.sh')
        self.assertRegex(script, r'api\.github\.com/repos/Homebrew/install/contents/install\.sh\?ref=[0-9a-f]{40}')
        self.assertRegex(script, r'(sha256sum|shasum|hashlib\.sha256)')
        self.assertRegex(script, r'[0-9a-f]{64}')
        self.assertLess(script.index("sha256sum --check --status"), script.index('/bin/bash "$brew_installer"'))
        self.assertIsNone(re.search(r"curl[^\n]*\|\s*(bash|sh)\b", script))
