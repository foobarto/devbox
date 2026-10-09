#!/usr/bin/env python3
"""Descriptor-based host grant snapshots and mount identity checks.

Only the explicit raw-copy/credential grants copy arbitrary content. Agent
configuration exports bounded fields from known schemas; unknown fields,
instructions, hooks and executable content require an explicit raw-copy grant.
"""

import argparse
import contextlib
import json
import os
import shutil
import stat
import sys
import tarfile
from pathlib import Path


class UnsafeSource(ValueError):
    pass


def identity(st):
    return [st.st_dev, st.st_ino, stat.S_IFMT(st.st_mode)]


@contextlib.contextmanager
def open_source(path):
    """Walk from / with no-follow directory descriptors, retaining ancestry.

    O_NONBLOCK prevents a substituted FIFO/device from blocking the host. The
    final descriptor is validated before any content is read.
    """
    path = os.path.abspath(os.path.expanduser(path))
    parts = Path(path).parts[1:]
    flags = os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK
    descriptors = []
    ancestry = []
    try:
        fd = os.open("/", flags | os.O_DIRECTORY)
        descriptors.append(fd)
        ancestry.append(identity(os.fstat(fd)))
        for index, part in enumerate(parts):
            fd = os.open(part, flags | (os.O_DIRECTORY if index < len(parts) - 1 else 0),
                         dir_fd=fd)
            descriptors.append(fd)
            ancestry.append(identity(os.fstat(fd)))
        st = os.fstat(fd)
        if not (stat.S_ISREG(st.st_mode) or stat.S_ISDIR(st.st_mode)):
            raise UnsafeSource(f"source must be a regular file or directory: {path}")
        yield fd, st, ancestry
    except OSError as error:
        raise UnsafeSource(f"cannot safely open host source {path}: {error.strerror}") from error
    finally:
        for fd in reversed(descriptors):
            os.close(fd)


def read_regular(fd, st, max_bytes=4 * 1024 * 1024):
    if not stat.S_ISREG(st.st_mode):
        raise UnsafeSource("secret/config source must be a regular file")
    if st.st_size > max_bytes:
        raise UnsafeSource("host input exceeds size limit")
    with os.fdopen(os.dup(fd), "rb") as stream:
        # The descriptor can grow after fstat. Bound the read itself rather
        # than treating its observed metadata as a memory-allocation limit.
        data = stream.read(max_bytes + 1)
    if len(data) > max_bytes:
        raise UnsafeSource("host input exceeds size limit")
    after = os.fstat(fd)
    if (st.st_size, st.st_mtime_ns, st.st_ctime_ns) != (after.st_size, after.st_mtime_ns, after.st_ctime_ns):
        raise UnsafeSource("host file changed while being snapshotted")
    return data


def copy_regular(fd, st, output):
    output_fd = os.open(output, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
    with os.fdopen(output_fd, "wb") as target, os.fdopen(os.dup(fd), "rb") as source:
        shutil.copyfileobj(source, target, length=1024 * 1024)
    after = os.fstat(fd)
    if (st.st_size, st.st_mtime_ns, st.st_ctime_ns) != (after.st_size, after.st_mtime_ns, after.st_ctime_ns):
        raise UnsafeSource("host file changed while being snapshotted")
    os.chmod(output, 0o500 if st.st_mode & 0o111 else 0o400)


def archive_directory(fd, archive, prefix="."):
    before = os.fstat(fd)
    for name in sorted(os.listdir(fd)):
        st = os.stat(name, dir_fd=fd, follow_symlinks=False)
        if stat.S_ISLNK(st.st_mode):
            # Links are omitted entirely; neither host nor guest resolves them.
            continue
        if not (stat.S_ISREG(st.st_mode) or stat.S_ISDIR(st.st_mode)):
            raise UnsafeSource("copy directory contains a non-regular entry")
        child = os.open(name, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK |
                        (os.O_DIRECTORY if stat.S_ISDIR(st.st_mode) else 0), dir_fd=fd)
        try:
            actual = os.fstat(child)
            if identity(actual) != identity(st):
                raise UnsafeSource("copy directory entry changed during traversal")
            member = tarfile.TarInfo(prefix + "/" + name)
            member.mode = stat.S_IMODE(actual.st_mode) & 0o777
            member.mtime = actual.st_mtime
            if stat.S_ISDIR(actual.st_mode):
                member.type = tarfile.DIRTYPE
                archive.addfile(member)
                archive_directory(child, archive, member.name)
            else:
                member.size = actual.st_size
                with os.fdopen(os.dup(child), "rb") as source:
                    archive.addfile(member, source)
                after = os.fstat(child)
                if (actual.st_size, actual.st_mtime_ns, actual.st_ctime_ns) != (after.st_size, after.st_mtime_ns, after.st_ctime_ns):
                    raise UnsafeSource("copy directory file changed while being snapshotted")
        finally:
            os.close(child)
    after = os.fstat(fd)
    if (before.st_mtime_ns, before.st_ctime_ns) != (after.st_mtime_ns, after.st_ctime_ns):
        raise UnsafeSource("copy directory changed while being snapshotted")


# Closed value sets intentionally prevent free-form strings in a permitted
# field from silently becoming a credential export channel.
MODELS = {"gpt-4.1", "gpt-4o", "gpt-5", "gpt-5.1", "gpt-5.2", "gpt-5.3-codex",
          "gpt-5.4", "gpt-5.6-sol", "gpt-6", "gpt-6-sol", "gpt-6.1-sol",
          "gpt-6-astra", "gpt-6-luna", "daybreak-blue", "o3", "o4-mini",
          "sonnet", "opus", "haiku", "claude-sonnet-4-6", "claude-opus-4-6"}
REASONING = {"none", "minimal", "low", "medium", "high", "xhigh", "max", "ultra"}
SCHEMAS = {
    ".codex/config.toml": {
        "model": MODELS,
        "model_reasoning_effort": REASONING,
        "model_reasoning_summary": {"auto", "concise", "detailed", "none"},
        "model_verbosity": {"low", "medium", "high"},
        "approval_policy": {"untrusted", "on-failure", "on-request", "never"},
        "sandbox_mode": {"read-only", "workspace-write", "danger-full-access"},
        "personality": {"none", "friendly", "pragmatic"},
        "disable_paste_burst": bool,
        "check_for_update_on_startup": bool,
        "history.persistence": {"save-all", "none"},
        "history.max_bytes": (0, 1000000000),
        "tui.animations": bool,
        "tui.notifications": bool,
        "tui.alternate_screen": {"auto", "always", "never"},
    },
    ".claude/settings.json": {
        "model": MODELS, "effortLevel": REASONING,
        "permissions.defaultMode": {"default", "acceptEdits", "plan", "bypassPermissions", "dontAsk"},
        "alwaysThinkingEnabled": bool, "showTurnDuration": bool,
        "cleanupPeriodDays": (0, 365),
    },
    ".config/opencode/opencode.json": {
        "model": {f"{provider}/{model}" for provider in ("openai", "anthropic", "opencode") for model in MODELS},
        "small_model": {f"{provider}/{model}" for provider in ("openai", "anthropic", "opencode") for model in MODELS},
        "autoupdate": bool, "share": {"manual", "auto", "disabled"},
        "theme": {"opencode", "system", "catppuccin", "nord", "tokyonight", "gruvbox"},
    },
    ".config/stado/config.toml": {},
}
SCHEMAS[".claude/settings.local.json"] = SCHEMAS[".claude/settings.json"]


def sanitize_config(relative, data):
    schema = SCHEMAS.get(relative)
    if schema is None:
        return None
    if relative.endswith(".toml"):
        try:
            import tomllib
        except ImportError:
            import tomli as tomllib
        parsed = tomllib.loads(data.decode("utf-8"))
    else:
        parsed = json.loads(data)
    if not isinstance(parsed, dict):
        raise UnsafeSource("agent config must be an object/table")
    selected = {}
    for key, permitted in schema.items():
        value = parsed
        for part in key.split("."):
            value = value.get(part) if isinstance(value, dict) else None
        valid = ((type(value) is bool) if permitted is bool else
                 (type(value) is int and permitted[0] <= value <= permitted[1]) if isinstance(permitted, tuple) else
                 (isinstance(value, str) and value in permitted))
        if not valid:
            continue
        target = selected
        parts = key.split(".")
        for part in parts[:-1]:
            target = target.setdefault(part, {})
        target[parts[-1]] = value
    if not selected:
        return None
    if relative.endswith(".toml"):
        lines = []
        for key, value in selected.items():
            if isinstance(value, dict):
                for nested, item in value.items():
                    lines.append(f"{key}.{nested} = {json.dumps(item)}")
            else:
                lines.append(f"{key} = {json.dumps(value)}")
        return ("\n".join(lines) + "\n").encode()
    return (json.dumps(selected, indent=2) + "\n").encode()


def write_private(path, data):
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
    with os.fdopen(fd, "wb") as stream:
        stream.write(data)
    os.chmod(path, 0o400)


def snapshot(root, requests):
    st = os.lstat(root)
    if not stat.S_ISDIR(st.st_mode) or st.st_uid != os.getuid() or stat.S_IMODE(st.st_mode) != 0o700:
        raise UnsafeSource("snapshot directory must be owned by current user and mode 0700")
    entries = []
    for category, source, destination in requests:
        if category not in {"api", "copy", "credentials", "config"}:
            raise UnsafeSource("unknown host snapshot grant category")
        try:
            with open_source(source) as (fd, st, _):
                output = os.path.join(root, str(len(entries)))
                kind = "file"
                if category == "config":
                    if st.st_size > 2 * 1024 * 1024:
                        raise UnsafeSource("agent config is too large")
                    data = sanitize_config(destination, read_regular(fd, st, max_bytes=2 * 1024 * 1024))
                    if data is None:
                        print(f"[devbox] skipped agent config without safe schema fields: {destination}", file=sys.stderr)
                        continue
                    write_private(output, data)
                elif stat.S_ISDIR(st.st_mode):
                    if category == "api":
                        raise UnsafeSource("API-key source must be a regular file")
                    kind = "directory"
                    output_fd = os.open(output, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
                    with os.fdopen(output_fd, "wb") as stream, tarfile.open(fileobj=stream, mode="w") as archive:
                        archive_directory(fd, archive)
                    os.chmod(output, 0o400)
                else:
                    if category == "api":
                        write_private(output, read_regular(fd, st, max_bytes=1024 * 1024))
                    else:
                        copy_regular(fd, st, output)
                entries.append(dict(category=category, source=source, destination=destination,
                                    kind=kind, snapshot=output))
        except (UnsafeSource, ValueError, UnicodeError) as error:
            if category != "config":
                raise
            print(f"[devbox] skipped unsupported/unsafe agent config: {destination} ({type(error).__name__})", file=sys.stderr)
    write_private(os.path.join(root, "index.json"), json.dumps(entries).encode())


def mount_identities(paths):
    records = []
    for path in paths:
        with open_source(path) as (_, _, ancestry):
            records.append(dict(path=os.path.abspath(path), ancestry=ancestry))
    return records


def check_snapshot_isolation(root, mounts):
    root = os.path.realpath(root)
    for mount in mounts:
        mount = os.path.realpath(os.path.expanduser(mount))
        if os.path.commonpath((root, mount)) in {root, mount}:
            raise UnsafeSource("private grant snapshots overlap a guest mount; choose a narrower mount")


def _mountinfo_path(value):
    # Linux mountinfo uses these octal escapes for otherwise ambiguous fields.
    # Decode backslash last so a literal "\\040" filename stays literal.
    for escaped, character in (("\\040", " "), ("\\011", "\t"),
                               ("\\012", "\n"), ("\\134", "\\")):
        value = value.replace(escaped, character)
    return value


def _linux_mountinfo():
    """Return Linux mount namespace coordinates needed to unfold bind aliases."""
    if not sys.platform.startswith("linux"):
        return []
    try:
        with open("/proc/self/mountinfo", encoding="utf-8") as stream:
            lines = stream.readlines()
    except OSError as error:
        raise UnsafeSource(f"cannot inspect filesystem mount aliases: {error.strerror}") from error
    records = []
    for line in lines:
        before, separator, _ = line.partition(" - ")
        fields = before.split()
        if not separator or len(fields) < 6:
            raise UnsafeSource("cannot parse filesystem mount aliases")
        try:
            mount_id = int(fields[0])
        except ValueError as error:
            raise UnsafeSource("cannot parse filesystem mount aliases") from error
        root = os.path.normpath(_mountinfo_path(fields[3]))
        mount_point = os.path.normpath(_mountinfo_path(fields[4]))
        if not os.path.isabs(root) or not os.path.isabs(mount_point):
            raise UnsafeSource("cannot parse filesystem mount aliases")
        records.append((mount_id, fields[2], root, mount_point))
    return records


def _mount_coordinates(path, mounts):
    """Map a namespace path to its device and path within that filesystem."""
    path = os.path.normpath(path)
    covering = [record for record in mounts
                if os.path.commonpath((path, record[3])) == record[3]]
    if not covering:
        return None
    # The deepest mount wins. For stacked mounts at one point, the newest ID is
    # the visible one in the current namespace.
    _, device, root, mount_point = max(
        covering, key=lambda record: (len(Path(record[3]).parts), record[0]))
    relative = os.path.relpath(path, mount_point)
    filesystem_path = root if relative == "." else os.path.normpath(os.path.join(root, relative))
    return device, filesystem_path


def check_mount_policy(policy):
    """Refuse mount sources whose directory entry another guest can replace.

    A writable directory mount cannot replace its own root through that mount,
    but it can replace descendant directory entries. Path comparisons cover
    ordinary aliases, object identities cover unrelated names for one object,
    and Linux mount coordinates expose bind-mounted descendants.

    Grant sources (copies, credential, configuration and API-key files) are
    checked against other guests' writable mounts inclusively: a source that
    is such a mount, not only one beneath it, has guest-controlled content.
    """
    if not isinstance(policy, dict):
        raise UnsafeSource("mount policy must be an object")
    sources = policy.get("sources")
    writable_roots = policy.get("writable_roots")
    if not isinstance(sources, list) or not isinstance(writable_roots, list):
        raise UnsafeSource("mount policy requires source and writable-root lists")
    grant_sources = policy.get("grant_sources", [])
    foreign_roots = policy.get("foreign_writable_roots", [])
    if not isinstance(grant_sources, list) or not isinstance(foreign_roots, list):
        raise UnsafeSource("grant sources and foreign writable roots must be lists")
    _refuse_beneath(sources, writable_roots, inclusive=False, label="mount source")
    _refuse_beneath(grant_sources, foreign_roots, inclusive=True, label="grant source")


def _refuse_beneath(sources, writable_roots, *, inclusive, label):
    def path_record(path):
        if not isinstance(path, str) or not path or "\0" in path or "\n" in path:
            raise UnsafeSource("invalid mount policy path")
        lexical = os.path.abspath(os.path.expanduser(path))
        return lexical, {lexical, os.path.realpath(lexical)}

    def beneath(path, root):
        return (inclusive or path != root) and os.path.commonpath((path, root)) == root

    source_records = [path_record(path) for path in sources]
    root_records = [path_record(path) for path in writable_roots]
    if not source_records:
        return

    def refuse(source, root):
        raise UnsafeSource(
            f"{label} {source} is {'at or ' if inclusive else ''}beneath a guest-writable directory, {root} "
            "(a writable mount of this or another Lima instance); choose independent mount roots"
        )

    for source_lexical, source_variants in source_records:
        for source_path in source_variants:
            for root_lexical, root_variants in root_records:
                for root in root_variants:
                    if beneath(source_path, root):
                        refuse(source_lexical, root_lexical)

    # A bind mount can expose a descendant of a writable root at an unrelated
    # namespace path, so the writable root's inode need not appear in the
    # source's namespace ancestry. Linux mount coordinates unfold that hidden
    # relationship before the object-identity comparison below.
    mounts = _linux_mountinfo()
    source_coordinates = [[_mount_coordinates(path, mounts) for path in variants]
                          for _, variants in source_records]
    root_coordinates = [[_mount_coordinates(path, mounts) for path in variants]
                        for _, variants in root_records]
    for coordinates in source_coordinates:
        for source_coordinate in coordinates:
            if source_coordinate is None:
                continue
            source_device, source_path = source_coordinate
            for root_variants in root_coordinates:
                for root_coordinate in root_variants:
                    if root_coordinate is None or source_device != root_coordinate[0]:
                        continue
                    root_path = root_coordinate[1]
                    if beneath(source_path, root_path):
                        raise UnsafeSource(
                            f"{label} {source_path} is {'at or ' if inclusive else ''}beneath a guest-writable "
                            f"directory, {root_path} (through a bind mount); choose independent mount roots"
                        )

    # Compare object identities of the resolved roots. A root that no longer
    # exists (a deleted project of a stopped box, Lima's /tmp/lima after a
    # reboot) has no object to alias; the path comparisons above still apply.
    root_identities = []
    for root, _ in root_records:
        try:
            with open_source(os.path.realpath(root)) as (_, root_stat, _):
                root_identities.append((root, identity(root_stat)))
        except UnsafeSource:
            if os.path.lexists(os.path.realpath(root)):
                raise
    for source, _ in source_records:
        with open_source(source) as (_, _, ancestry):
            checked = ancestry if inclusive else ancestry[:-1]
            for root, root_identity in root_identities:
                if root_identity in checked:
                    refuse(source, root)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("command", choices=("snapshot", "snapshot-check", "mount-policy", "mount-capture", "mount-check", "entries", "api-path"))
    parser.add_argument("path")
    parser.add_argument("arguments", nargs="*")
    args = parser.parse_args()
    if args.command == "snapshot":
        if len(args.arguments) % 3:
            raise UnsafeSource("snapshot arguments must be category/source/destination triples")
        snapshot(args.path, list(zip(*[iter(args.arguments)] * 3)))
    elif args.command == "snapshot-check":
        check_snapshot_isolation(args.path, args.arguments)
    elif args.command == "mount-policy":
        with open_source(args.path) as (fd, st, _):
            check_mount_policy(json.loads(read_regular(fd, st)))
    elif args.command == "mount-capture":
        write_private(args.path, json.dumps(mount_identities(args.arguments)).encode())
    elif args.command == "mount-check":
        with open_source(args.path) as (fd, st, _):
            expected = json.loads(read_regular(fd, st))
        actual = mount_identities([item["path"] for item in expected])
        if actual != expected:
            raise UnsafeSource("mount source or ancestor changed after approval")
    else:
        with open_source(os.path.join(args.path, "index.json")) as (fd, st, _):
            entries = json.loads(read_regular(fd, st))
        for entry in entries:
            if args.command == "api-path" and entry["category"] == "api":
                print(entry["snapshot"], end="")
            elif args.command == "entries" and (not args.arguments or entry["category"] == args.arguments[0]):
                if len(args.arguments) > 1 and entry["source"] != args.arguments[1]:
                    continue
                for key in ("kind", "snapshot", "destination"):
                    sys.stdout.buffer.write(entry[key].encode() + b"\0")


if __name__ == "__main__":
    try:
        main()
    except (UnsafeSource, OSError, ValueError) as error:
        print(f"[devbox] unsafe host grant input: {error}", file=sys.stderr)
        sys.exit(1)
