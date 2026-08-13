"""Structural checks for the dependency-free GitHub Pages site."""
from html.parser import HTMLParser
from pathlib import Path
from unittest import TestCase, main


ROOT = Path(__file__).parents[1]
SITE = ROOT / "website"


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

    def test_pages_workflow_publishes_only_the_website_directory(self):
        workflow = (ROOT / ".github/workflows/deploy-pages.yml").read_text(encoding="utf-8")
        self.assertIn("actions/configure-pages@v5", workflow)
        self.assertIn("actions/upload-pages-artifact@v4", workflow)
        self.assertIn("actions/deploy-pages@v4", workflow)
        self.assertIn("path: website", workflow)
        self.assertIn("pages: write", workflow)
        self.assertIn("id-token: write", workflow)


if __name__ == "__main__":
    main()
