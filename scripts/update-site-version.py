#!/usr/bin/env python3
"""Update the version marker in the static Pages site without touching other text."""

from __future__ import annotations

import argparse
import re
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
DEFAULT_PAGE = ROOT / "docs" / "index.html"
VERSION = r"v[0-9]+\.[0-9]+\.[0-9]+(?:[-+][0-9A-Za-z.-]+)?"
MARKER = re.compile(
    rf'(<span data-current-version>)(?P<version>{VERSION})(</span>)'
)


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Update the marked Devbox version in docs/index.html."
    )
    parser.add_argument("version", help="Version to display, for example v1.2.3")
    parser.add_argument(
        "--path",
        type=Path,
        default=DEFAULT_PAGE,
        help="HTML file to update (default: docs/index.html)",
    )
    args = parser.parse_args()
    if not re.fullmatch(VERSION, args.version):
        parser.error("version must be a v-prefixed semantic version, for example v1.2.3")
    return args


def main() -> None:
    args = parse_args()
    page = args.path
    content = page.read_text(encoding="utf-8")
    match = MARKER.search(content)
    if not match:
        raise SystemExit(f"no version marker found in {page}")

    old_version = match.group("version")
    if old_version == args.version:
        print(f"unchanged: {args.version}")
        return

    updated, replacements = MARKER.subn(
        rf"\g<1>{args.version}\g<3>", content, count=1
    )
    if replacements != 1:
        raise SystemExit(f"expected one version marker in {page}, found {replacements}")
    page.write_text(updated, encoding="utf-8")
    print(f"updated: {old_version} -> {args.version}")


if __name__ == "__main__":
    main()
