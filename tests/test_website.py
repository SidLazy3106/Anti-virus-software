"""Tests for Website."""
import shutil
import tempfile
import unittest
from pathlib import Path

from sentinel import webguard


class WebsiteTests(unittest.TestCase):
    """The portfolio site (docs/) must stay in step with the real extension logic."""
    ROOT = Path(__file__).resolve().parent.parent

    def test_site_checker_is_the_extension_checker(self):
        for name in ("analyzer.js", "url_rules.js"):
            self.assertEqual((self.ROOT / "docs" / name).read_bytes(),
                             (self.ROOT / "browser_extension" / name).read_bytes(),
                             f"run tools/sync_extension_rules.py (docs/{name} is out of date)")

    def test_demo_links_on_the_page_give_the_verdicts_the_page_promises(self):
        node = shutil.which("node")
        if not node:
            self.skipTest("Node.js not installed")
        import json
        import re
        import subprocess
        html = (self.ROOT / "docs" / "index.html").read_text(encoding="utf-8")
        urls = re.findall(r'data-u="([^"]+)"', html)
        self.assertGreaterEqual(len(urls), 5)
        script = Path(tempfile.mkdtemp()) / "t.js"
        script.write_text((self.ROOT / "docs" / "url_rules.js").read_text(encoding="utf-8") +
                          (self.ROOT / "docs" / "analyzer.js").read_text(encoding="utf-8") +
                          "\nconsole.log(JSON.stringify(" + json.dumps(urls) + ".map(u => analyzeUrl(u, []))));",
                          encoding="utf-8")
        out = json.loads(subprocess.run([node, str(script)], capture_output=True, text=True, timeout=60).stdout)
        verdicts = {u: v["verdict"] for u, v in zip(urls, out)}
        self.assertEqual(verdicts["https://github.com/login"], "clean")
        for u in urls:
            if u != "https://github.com/login":
                self.assertNotEqual(verdicts[u], "clean", u)
            self.assertEqual(verdicts[u], webguard.analyze_url(u).verdict, u)      # same as the Python engine

    def test_page_is_self_contained_and_leaks_nothing_personal(self):
        html = (self.ROOT / "docs" / "index.html").read_text(encoding="utf-8")
        self.assertNotRegex(html, r"https?://(?!github\.com/login|evil\.s3|www\.w3)[^\"' <]*\.(js|css)")
        self.assertNotIn("C:\\Users", html)
        for img in (self.ROOT / "docs" / "img").glob("*.png"):
            self.assertLess(img.stat().st_size, 400_000, img.name)

    def test_versions_agree_everywhere(self):
        import json
        import tomllib
        from sentinel import config
        project = tomllib.loads((self.ROOT / "pyproject.toml").read_text(encoding="utf-8"))["project"]
        self.assertEqual(project["version"], config.VERSION)
        release = self.ROOT / "docs" / "release.json"
        if release.exists():                                    # written by tools/build_release.py
            info = json.loads(release.read_text(encoding="utf-8"))
            self.assertEqual(info["version"], config.VERSION)
            self.assertRegex(info["sha256"], r"^[0-9a-f]{64}$")

    def test_every_in_page_link_has_a_target_and_every_section_exists(self):
        import re
        html = (self.ROOT / "docs" / "index.html").read_text(encoding="utf-8")
        ids = set(re.findall(r'id="([^"]+)"', html))
        for target in set(re.findall(r'href="#([^"]+)"', html)):
            self.assertIn(target, ids, f"dead in-page link #{target}")
        for section in ("overview", "how", "modes", "dashboard", "features", "trust", "try", "download"):
            self.assertIn(section, ids)
        for src in re.findall(r'<img[^>]+src="([^"]+)"', html):
            self.assertTrue((self.ROOT / "docs" / src).exists(), src)
