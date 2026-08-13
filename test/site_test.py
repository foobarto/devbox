"""Structural checks for the dependency-free GitHub Pages site."""
from html.parser import HTMLParser
from pathlib import Path
import shutil
import subprocess
import sys
from tempfile import TemporaryDirectory
from unittest import TestCase, main


ROOT = Path(__file__).parents[1]
SITE = ROOT / "docs"
SITE_VERSION_UPDATER = ROOT / "scripts" / "update-site-version.py"


class PageParser(HTMLParser):
    def __init__(self):
        super().__init__()
        self.ids = set()
        self.links = []

    def handle_starttag(self, tag, attrs):
        values = dict(attrs)
        if "id" in values:
            self.ids.add(values["id"])
        if tag in {"a", "link", "script", "img"} and "href" in values:
            self.links.append(values["href"])
        if tag in {"script", "img"} and "src" in values:
            self.links.append(values["src"])


class WebsiteTests(TestCase):
    def test_site_has_the_required_entrypoint_assets_and_navigation_targets(self):
        page = SITE / "index.html"
        self.assertTrue(page.is_file())
        parser = PageParser()
        parser.feed(page.read_text(encoding="utf-8"))
        self.assertTrue({"top", "main", "how", "capabilities", "audit", "flags", "manifest"} <= parser.ids)
        for asset in ("assets/site.css", "assets/site.js", "assets/favicon.svg"):
            self.assertIn(asset, parser.links)
            self.assertTrue((SITE / asset).is_file())

    def test_site_explains_detailed_and_connect_audit_boundaries(self):
        page = (SITE / "index.html").read_text(encoding="utf-8")
        self.assertIn("devbox proxy audit export audit.html", page)
        self.assertIn("GitHub writes are classified as create, modify, delete", page)
        self.assertIn("HTTPS paths, prompts, and bodies remain end-to-end encrypted", page)

    def test_site_marks_the_version_for_automation(self):
        page = (SITE / "index.html").read_text(encoding="utf-8")
        self.assertRegex(
            page,
            r'<span data-current-version>v[0-9]+\.[0-9]+\.[0-9]+(?:[-+][0-9A-Za-z.-]+)?</span>',
        )

    def test_site_version_updater_changes_only_the_marked_version(self):
        with TemporaryDirectory() as temporary_directory:
            page = Path(temporary_directory) / "index.html"
            shutil.copy(SITE / "index.html", page)
            result = subprocess.run(
                [sys.executable, SITE_VERSION_UPDATER, "v9.8.7", "--path", page],
                check=True,
                capture_output=True,
                text=True,
            )
            self.assertIn("updated:", result.stdout)
            self.assertIn(
                "<span data-current-version>v9.8.7</span>", page.read_text(encoding="utf-8")
            )

            unchanged = subprocess.run(
                [sys.executable, SITE_VERSION_UPDATER, "v9.8.7", "--path", page],
                check=True,
                capture_output=True,
                text=True,
            )
            self.assertEqual("unchanged: v9.8.7\n", unchanged.stdout)

    def test_site_version_updater_rejects_duplicate_markers(self):
        with TemporaryDirectory() as temporary_directory:
            page = Path(temporary_directory) / "index.html"
            page.write_text(
                "<span data-current-version>v1.0.0</span>"
                "<span data-current-version>v1.0.0</span>",
                encoding="utf-8",
            )
            result = subprocess.run(
                [sys.executable, SITE_VERSION_UPDATER, "v9.8.7", "--path", page],
                check=False,
                capture_output=True,
                text=True,
            )
            self.assertNotEqual(0, result.returncode)
            self.assertIn("expected one version marker", result.stderr)

    def test_pages_source_contains_the_static_site_and_disables_jekyll(self):
        self.assertTrue((SITE / ".nojekyll").is_file())
        self.assertTrue((SITE / "index.html").is_file())
        self.assertEqual("devbox.foobarto.me\n", (SITE / "CNAME").read_text(encoding="utf-8"))

    def test_version_sync_workflow_updates_and_deploys_only_when_needed(self):
        workflow = (ROOT / ".github/workflows/sync-site-version.yml").read_text(encoding="utf-8")
        self.assertIn('cron: "17 5 * * 1"', workflow)
        self.assertIn("tr -d '[:space:]' < VERSION", workflow)
        self.assertIn("scripts/update-site-version.py", workflow)
        self.assertIn("contents: write", workflow)
        self.assertIn("pages: write", workflow)
        self.assertIn("ref: main", workflow)
        self.assertIn("git diff --quiet -- docs/index.html", workflow)
        self.assertIn("git push origin HEAD:main", workflow)
        self.assertIn('gh api --method POST "repos/${GITHUB_REPOSITORY}/pages/builds"', workflow)


if __name__ == "__main__":
    main()
