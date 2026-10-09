"""Synthetic host-file grant boundary tests; no local credentials or VM needed."""

import contextlib
import importlib.util
import io
import json
import os
from pathlib import Path
import stat
import tarfile
import tempfile
from types import SimpleNamespace
import unittest
from unittest import mock


spec = importlib.util.spec_from_file_location(
    "devbox_host_files", Path(__file__).resolve().parents[1] / "proxy/devbox-host-files.py")
host = importlib.util.module_from_spec(spec)
spec.loader.exec_module(host)


class HostFilesTests(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory()
        self.root = Path(self.temporary.name).resolve()
        self.snapshots = self.root / "snapshots"
        self.snapshots.mkdir(mode=0o700)

    def tearDown(self):
        self.temporary.cleanup()

    def fixture(self, name, data=b"fixture-data"):
        source = self.root / name
        source.parent.mkdir(parents=True, exist_ok=True)
        source.write_bytes(data)
        return source

    def entries(self):
        return json.loads((self.snapshots / "index.json").read_text())

    def test_regular_input_is_private_snapshot_and_does_not_reopen_source(self):
        source = self.fixture("keys")
        host.snapshot(str(self.snapshots), [("api", str(source), "")])
        source.write_bytes(b"later-content")
        output = Path(self.entries()[0]["snapshot"])
        self.assertEqual(output.read_bytes(), b"fixture-data")
        self.assertEqual(stat.S_IMODE(output.stat().st_mode), 0o400)
        self.assertEqual(stat.S_IMODE((self.snapshots / "index.json").stat().st_mode), 0o400)

    def test_regular_executable_copy_retains_owner_execute(self):
        source = self.fixture("tool.sh")
        source.chmod(0o755)
        host.snapshot(str(self.snapshots), [("copy", str(source), "tool.sh")])
        output = Path(self.entries()[0]["snapshot"])
        self.assertEqual(stat.S_IMODE(output.stat().st_mode), 0o500)

    def test_read_limit_is_enforced_even_when_observed_size_is_smaller(self):
        source = self.fixture("bounded-read", b"synthetic-content-longer-than-limit")
        with host.open_source(str(source)) as (fd, actual, _):
            # Exercise the read guard independently of potentially stale
            # metadata; this is a synthetic fixture, not a timing/race test.
            metadata = SimpleNamespace(st_mode=actual.st_mode, st_size=1,
                                       st_mtime_ns=actual.st_mtime_ns, st_ctime_ns=actual.st_ctime_ns)
            with self.assertRaisesRegex(host.UnsafeSource, "exceeds size limit"):
                host.read_regular(fd, metadata, max_bytes=8)

    def test_api_key_input_has_a_bounded_size(self):
        source = self.fixture("large-api-input", b"fixture" * 150000)
        with self.assertRaisesRegex(host.UnsafeSource, "exceeds size limit"):
            host.snapshot(str(self.snapshots), [("api", str(source), "")])

    def test_root_symlink_is_refused_for_all_raw_grants(self):
        source = self.fixture("source")
        link = self.root / "link"
        link.symlink_to(source)
        for category in ("api", "copy", "credentials"):
            with self.subTest(category=category), self.assertRaises(host.UnsafeSource):
                host.snapshot(str(self.snapshots), [(category, str(link), "target")])

    def test_parent_symlink_is_refused(self):
        source = self.fixture("real/file")
        (self.root / "alias").symlink_to(source.parent, target_is_directory=True)
        with self.assertRaises(host.UnsafeSource):
            host.snapshot(str(self.snapshots), [("api", str(self.root / "alias/file"), "")])

    def test_fifo_and_api_directory_are_refused(self):
        fifo = self.root / "fifo"
        os.mkfifo(fifo)
        for source in (fifo, self.root):
            with self.subTest(source=str(source)), self.assertRaises(host.UnsafeSource):
                host.snapshot(str(self.snapshots), [("api", str(source), "")])

    def test_directory_copy_excludes_nested_symlinks_and_their_targets(self):
        source = self.fixture("tree/sub/file", b"safe").parents[1]
        outside = self.fixture("outside", b"excluded-fixture")
        (source / "link-file").symlink_to(outside)
        (source / "link-directory").symlink_to(outside.parent, target_is_directory=True)
        host.snapshot(str(self.snapshots), [("copy", str(source), "tree")])
        with tarfile.open(self.entries()[0]["snapshot"]) as archive:
            self.assertEqual(archive.getnames(), ["./sub", "./sub/file"])
            self.assertEqual(archive.extractfile("./sub/file").read(), b"safe")

    def test_mount_identity_detects_source_and_parent_changes(self):
        source = self.fixture("parent/source")
        captured = host.mount_identities([str(source)])
        replacement = self.fixture("replacement")
        os.replace(replacement, source)
        self.assertNotEqual(captured, host.mount_identities([str(source)]))
        captured = host.mount_identities([str(source)])
        source.parent.rename(self.root / "old-parent")
        self.fixture("parent/source")
        self.assertNotEqual(captured, host.mount_identities([str(source)]))

    def test_mount_identity_rejects_a_symlink(self):
        source = self.fixture("source")
        (self.root / "link").symlink_to(source)
        with self.assertRaises(host.UnsafeSource):
            host.mount_identities([str(self.root / "link")])

    def test_codex_config_exports_closed_fields_without_unknown_data(self):
        data = b'''model = "gpt-6-sol"
model_reasoning_effort = "high"
my_login = "opaque-sensitive-fixture"
developer_instructions = "freeform-sensitive-fixture"
[history]
persistence = "save-all"
unknown = "nested-sensitive-fixture"
'''
        output = host.sanitize_config(".codex/config.toml", data).decode()
        self.assertIn('model = "gpt-6-sol"', output)
        self.assertIn('history.persistence = "save-all"', output)
        self.assertNotIn("fixture", output)
        import tomllib
        self.assertEqual(tomllib.loads(output)["history"], {"persistence": "save-all"})

    def test_claude_and_opencode_only_export_safe_enum_boolean_fields(self):
        cases = (
            (".claude/settings.json", {"model": "opus", "env": {"LOGIN": "sensitive-fixture"},
                                       "permissions": {"defaultMode": "plan", "allow": ["sensitive-fixture"]}},
             {"model": "opus", "permissions": {"defaultMode": "plan"}}),
            (".config/opencode/opencode.json", {"model": "openai/gpt-6-sol", "autoupdate": False,
                                               "provider": {"opaque": "sensitive-fixture"}, "instructions": ["private"]},
             {"model": "openai/gpt-6-sol", "autoupdate": False}),
        )
        for relative, original, expected in cases:
            with self.subTest(relative=relative):
                output = host.sanitize_config(relative, json.dumps(original).encode())
                self.assertEqual(json.loads(output), expected)

    def test_unknown_formats_freeform_and_unknown_model_values_are_omitted(self):
        for relative in (".codex/AGENTS.md", ".claude/hooks/script.sh",
                         ".config/opencode/opencode.jsonc", ".config/stado/system-prompt.md"):
            self.assertIsNone(host.sanitize_config(relative, b"opaque-sensitive-fixture"))
        self.assertIsNone(host.sanitize_config(".codex/config.toml", b'model = "opaque-sensitive-fixture"'))

    def test_invalid_config_is_skipped_without_disclosing_its_content(self):
        source = self.fixture("invalid.json", b"opaque-sensitive-fixture invalid JSON")
        with contextlib.redirect_stderr(io.StringIO()) as output:
            host.snapshot(str(self.snapshots), [("config", str(source), ".claude/settings.json")])
        self.assertEqual(self.entries(), [])
        self.assertNotIn("opaque-sensitive-fixture", output.getvalue())

    def test_snapshot_directory_requires_owner_only_permissions(self):
        self.snapshots.chmod(0o755)
        with self.assertRaises(host.UnsafeSource):
            host.snapshot(str(self.snapshots), [])

    def test_snapshots_must_stay_outside_every_guest_mount(self):
        for mount in (self.root, self.snapshots, self.snapshots / "nested"):
            with self.subTest(mount=str(mount)), self.assertRaises(host.UnsafeSource):
                host.check_snapshot_isolation(str(self.snapshots), [str(mount)])
        host.check_snapshot_isolation(str(self.snapshots), [str(self.root / "project")])

    def test_mount_policy_allows_distinct_roots_and_each_mounts_own_root(self):
        project = self.root / "project"
        cache = self.root / "cache"
        project.mkdir()
        cache.mkdir()
        host.check_mount_policy({"sources": [str(project), str(cache)],
                                 "writable_roots": [str(project), str(cache)]})

    def test_mount_policy_ignores_missing_and_symlinked_foreign_roots(self):
        # Another instance's writable mount may be gone (deleted project, Lima's
        # /tmp/lima after a reboot) or reached through a symlink (macOS /tmp).
        source = self.root / "source"
        source.mkdir()
        real = self.root / "real"
        (real / "lima").mkdir(parents=True)
        (self.root / "tmp-link").symlink_to(real)
        host.check_mount_policy({"sources": [str(source)],
                                 "writable_roots": [str(self.root / "missing" / "lima"),
                                                    str(self.root / "tmp-link" / "lima")]})

    def test_grant_sources_at_or_below_a_foreign_writable_root_are_refused(self):
        shared = self.root / "shared"
        (shared / "nested").mkdir(parents=True)
        (shared / "nested" / "credentials.json").write_text("{}")
        (self.root / "alias").symlink_to(shared)
        for source in (shared, shared / "nested" / "credentials.json",
                       self.root / "alias" / "nested" / "credentials.json"):
            with self.subTest(source=str(source)), self.assertRaises(host.UnsafeSource):
                host.check_mount_policy({"sources": [], "writable_roots": [],
                                         "grant_sources": [str(source)],
                                         "foreign_writable_roots": [str(shared)]})
        independent = self.root / "independent.json"
        independent.write_text("{}")
        host.check_mount_policy({"sources": [], "writable_roots": [],
                                 "grant_sources": [str(independent)],
                                 "foreign_writable_roots": [str(shared)]})

    def test_mount_policy_without_sources_needs_no_root_inspection(self):
        host.check_mount_policy({"sources": [], "writable_roots": [str(self.root / "missing")]})

    def test_mount_policy_still_refuses_a_source_beneath_a_symlinked_root(self):
        real = self.root / "real"
        (real / "lima" / "nested").mkdir(parents=True)
        (self.root / "tmp-link").symlink_to(real)
        with self.assertRaisesRegex(host.UnsafeSource, "beneath a guest-writable"):
            host.check_mount_policy({"sources": [str(real / "lima" / "nested")],
                                     "writable_roots": [str(self.root / "tmp-link" / "lima")]})

    def test_mount_policy_refuses_descendants_of_guest_writable_roots(self):
        project = self.root / "project"
        with self.assertRaisesRegex(host.UnsafeSource, "beneath a guest-writable"):
            host.check_mount_policy({"sources": [str(project / "nested")],
                                     "writable_roots": [str(project)]})
        # A sibling sharing the textual prefix is a distinct directory.
        project.mkdir()
        project_other = self.root / "project-other"
        project_other.mkdir()
        host.check_mount_policy({"sources": [str(project_other)],
                                 "writable_roots": [str(project)]})

    def test_mount_policy_checks_aliases_and_resolved_directory_ancestry(self):
        actual = self.root / "actual"
        actual.mkdir()
        alias = self.root / "alias"
        alias.symlink_to(actual, target_is_directory=True)
        cases = (
            {"sources": [str(alias / "nested")], "writable_roots": [str(actual)]},
            {"sources": [str(actual / "nested")], "writable_roots": [str(alias)]},
        )
        for policy in cases:
            with self.subTest(policy=policy), self.assertRaises(host.UnsafeSource):
                host.check_mount_policy(policy)

    def test_mount_policy_checks_writable_ancestor_across_descendant_bind_alias(self):
        writable_alias = self.root / "writable-alias"
        source_alias = self.root / "source-alias" / "nested"
        writable_alias.mkdir()
        source_alias.mkdir(parents=True)
        directory_mode = stat.S_IFDIR | 0o700

        def directory(device, inode):
            return SimpleNamespace(st_dev=device, st_ino=inode, st_mode=directory_mode)

        filesystem_root = host.identity(directory(1, 1))
        temporary_root = host.identity(directory(1, 2))
        writable_root = host.identity(directory(1, 3))
        aliased_subdirectory = host.identity(directory(1, 4))
        nested_source = host.identity(directory(1, 5))
        records = {
            str(writable_alias): (directory(1, 3),
                                  [filesystem_root, temporary_root, writable_root]),
            str(source_alias): (directory(1, 5),
                                [filesystem_root, temporary_root,
                                 aliased_subdirectory, nested_source]),
        }
        mounts = [
            (1, "1:1", "/", "/"),
            (2, "1:1", str(writable_alias / "subdirectory"),
             str(source_alias.parent)),
        ]

        @contextlib.contextmanager
        def aliased_source(path):
            source_stat, ancestry = records[path]
            yield -1, source_stat, ancestry

        with mock.patch.object(host, "_linux_mountinfo", return_value=mounts), \
                mock.patch.object(host, "open_source", side_effect=aliased_source):
            with self.assertRaisesRegex(host.UnsafeSource, "beneath a guest-writable"):
                host.check_mount_policy({"sources": [str(source_alias)],
                                         "writable_roots": [str(writable_alias)]})

    def test_mount_policy_allows_the_same_root_object_through_distinct_aliases(self):
        writable_alias = self.root / "writable-alias"
        source_alias = self.root / "source-alias"
        writable_alias.mkdir()
        source_alias.mkdir()
        shared = SimpleNamespace(st_dev=1, st_ino=3, st_mode=stat.S_IFDIR | 0o700)
        shared_identity = host.identity(shared)

        @contextlib.contextmanager
        def aliased_source(_path):
            yield -1, shared, [[1, 1, stat.S_IFDIR], shared_identity]

        with mock.patch.object(host, "_linux_mountinfo", return_value=[]), \
                mock.patch.object(host, "open_source", side_effect=aliased_source):
            host.check_mount_policy({"sources": [str(source_alias)],
                                     "writable_roots": [str(writable_alias)]})

    def test_mount_policy_cli_reads_verified_private_policy_file(self):
        import subprocess
        import sys
        policy = self.fixture("mount-policy.json", json.dumps({
            "sources": [str(self.root / "project/nested")],
            "writable_roots": [str(self.root / "project")],
        }).encode())
        result = subprocess.run([sys.executable, host.__file__, "mount-policy", str(policy)],
                                capture_output=True, text=True, timeout=5)
        self.assertEqual(result.returncode, 1)
        self.assertIn("beneath a guest-writable", result.stderr)


if __name__ == "__main__":
    unittest.main()
