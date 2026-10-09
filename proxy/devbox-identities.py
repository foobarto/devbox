#!/usr/bin/env python3
"""Owner-only provenance for shared goldens and project-owned instances."""

import json
import os
from pathlib import Path
import re
import secrets
import stat
import sys


def main():
    root, kind, operation, name, *payload = sys.argv[1:]
    if kind not in ("golden", "project", "traffic") or operation not in ("check", "write", "remove"):
        raise ValueError("invalid identity operation")
    if not re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9_.-]{0,62}", name):
        raise ValueError("invalid instance name")
    expected = json.loads(payload[0]) if payload else None
    # Open every resolved directory component without following replacement
    # symlinks. All subsequent file operations remain relative to that fd.
    directory = Path(root).expanduser().resolve() / f"{kind}-identities"
    if operation == "remove" and not directory.exists():
        return
    if operation == "write":
        directory.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
        if not directory.exists():
            directory.mkdir(mode=0o700)
    fd = os.open("/", os.O_RDONLY | os.O_DIRECTORY)
    try:
        for part in directory.parts[1:]:
            child = os.open(part, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW, dir_fd=fd)
            os.close(fd)
            fd = child
        info = os.fstat(fd)
        if info.st_uid != os.getuid() or info.st_mode & 0o077:
            raise ValueError("identity directory must be owner-only")
        filename = name + ".json"
        if operation == "remove":
            try:
                os.unlink(filename, dir_fd=fd)
            except FileNotFoundError:
                pass
            return
        if operation == "check":
            source = os.open(filename, os.O_RDONLY | os.O_NOFOLLOW, dir_fd=fd)
            with os.fdopen(source, "rb") as stream:
                info = os.fstat(stream.fileno())
                if not stat.S_ISREG(info.st_mode) or info.st_uid != os.getuid() or info.st_mode & 0o077:
                    raise ValueError("identity record must be an owner-only regular file")
                actual = json.loads(stream.read(4 * 1024 * 1024 + 1))
            if actual != expected:
                raise ValueError("instance provenance does not match")
            return
        temporary = ".identity-" + secrets.token_hex(16)
        try:
            output = os.open(temporary, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW,
                             0o600, dir_fd=fd)
            with os.fdopen(output, "w") as stream:
                json.dump(expected, stream, sort_keys=True)
                stream.write("\n")
                stream.flush()
                os.fsync(stream.fileno())
            os.replace(temporary, filename, src_dir_fd=fd, dst_dir_fd=fd)
            os.fsync(fd)
        finally:
            try:
                os.unlink(temporary, dir_fd=fd)
            except FileNotFoundError:
                pass
    finally:
        os.close(fd)


if __name__ == "__main__":
    try:
        main()
    except FileNotFoundError as error:
        # No record yet (an instance from an earlier version): the caller
        # explains what to do; a raw errno line would only confuse.
        if len(sys.argv) > 3 and sys.argv[3] == "check":
            raise SystemExit(3) from None
        raise SystemExit(f"Devbox identity refused: {error}") from None
    except (OSError, ValueError) as error:
        raise SystemExit(f"Devbox identity refused: {error}") from None
