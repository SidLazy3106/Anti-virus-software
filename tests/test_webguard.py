"""Tests for WebGuard, UrlEvasion, PublicSuffix, SharedRules."""
import shutil
import tempfile
import unittest
from pathlib import Path

from sentinel import config, webguard
from tests.helpers import URL_CASES


class WebGuardTests(unittest.TestCase):
    def test_legit(self):
        self.assertEqual(webguard.analyze_url("https://www.google.com/search?q=cats").verdict, "clean")
        self.assertEqual(webguard.analyze_url("https://github.com/login").verdict, "clean")

    def test_phishing(self):
        v = webguard.analyze_url("http://paypa1-secure-login.xyz/verify")
        self.assertNotEqual(v.verdict, "clean")

    def test_brand_subdomain(self):
        self.assertNotEqual(webguard.analyze_url("https://paypal.com.account-check.top/").verdict, "clean")

    def test_at_sign(self):
        self.assertNotEqual(webguard.analyze_url("http://192.168.1.1@evil.com/").verdict, "clean")

    def test_ip_login(self):
        self.assertNotEqual(webguard.analyze_url("http://185.1.2.3/login").verdict, "clean")

    def test_punycode_reason(self):
        v = webguard.analyze_url("http://xn--pypal-4ve.com/")
        self.assertTrue(any("Punycode" in r for r in v.reasons))

    def test_blocklist(self):
        self.assertEqual(webguard.analyze_url("http://sentinel-test-bad.test/").verdict, "malicious")


class UrlEvasionTests(unittest.TestCase):
    def test_disguised_ips(self):
        for u in ("http://3232235777/login", "http://0xC0A80001/login", "http://0300.0250.0.1/"):
            v = webguard.analyze_url(u)
            self.assertTrue(any("disguised" in r for r in v.reasons), (u, v.reasons))
        self.assertFalse(any("disguised" in r for r in webguard.analyze_url("http://192.168.1.1/").reasons))

    def test_parse_ipv4(self):
        self.assertEqual(webguard.parse_ipv4("3232235777"), "192.168.1.1")
        self.assertEqual(webguard.parse_ipv4("0xc0a80001"), "192.168.0.1")
        self.assertEqual(webguard.parse_ipv4("1.2.3"), "1.2.0.3")
        self.assertIsNone(webguard.parse_ipv4("example.com"))
        self.assertIsNone(webguard.parse_ipv4("256.1.1.1"))

    def test_unicode_lookalike_becomes_punycode(self):
        v = webguard.analyze_url("http://pаypal-secure-login.xyz/verify")
        self.assertTrue(any("Punycode" in r for r in v.reasons), v.reasons)

    def test_user_content_hosting(self):
        self.assertNotEqual(webguard.analyze_url("https://evil.s3.amazonaws.com/paypal/login").verdict, "clean")
        self.assertNotEqual(webguard.analyze_url("https://paypal-account.web.app/signin").verdict, "clean")
        self.assertEqual(webguard.analyze_url("https://fonts.googleapis.com/css2?family=Inter").verdict, "clean")
        self.assertEqual(webguard.analyze_url("https://storage.googleapis.com/google-fonts/a.woff2").verdict, "clean")

    def test_python_and_browser_extension_agree(self):
        import json
        import subprocess
        node = shutil.which("node")
        if not node:
            self.skipTest("node not installed")
        ext = Path(__file__).resolve().parent.parent / "browser_extension"
        harness = self_dir = Path(tempfile.mkdtemp()) / "h.js"
        harness.write_text(
            "const fs=require('fs');eval(fs.readFileSync(process.argv[2],'utf8')+fs.readFileSync(process.argv[3],'utf8'));"
            "const urls=JSON.parse(fs.readFileSync(process.argv[4],'utf8'));"
            "console.log(JSON.stringify(urls.map(u=>analyzeUrl(u,['sentinel-test-bad.test']))));", encoding="utf-8")
        data = harness.with_name("urls.json")
        data.write_text(json.dumps(URL_CASES), encoding="utf-8")
        out = subprocess.run([node, str(harness), str(ext / "url_rules.js"), str(ext / "analyzer.js"), str(data)],
                             capture_output=True, text=True,
                             encoding="utf-8", timeout=30)
        self.assertEqual(out.returncode, 0, out.stderr)
        for url, jv in zip(URL_CASES, json.loads(out.stdout)):
            pv = webguard.analyze_url(url)
            self.assertEqual((pv.verdict, pv.score, pv.reasons), (jv["verdict"], jv["score"], jv["reasons"]), url)
        shutil.rmtree(self_dir.parent, ignore_errors=True)


class PublicSuffixTests(unittest.TestCase):
    def setUp(self):
        config.ensure_dirs()
        self.f = config.UPDATED_SIGS_DIR / "public_suffix_list.dat"
        body = ["// ===BEGIN ICANN DOMAINS===", "com", "uk", "co.uk", "au", "com.au", "jp", "*.ck", "!www.ck",
                "xn--p1ai"] + [f"filler{i}.test" for i in range(1100)] + [
               "// ===END ICANN DOMAINS===", "// ===BEGIN PRIVATE DOMAINS===", "github.io", "s3.amazonaws.com"]
        self.f.write_text("\n".join(body), encoding="utf-8")
        webguard._psl.cache_clear()

    def tearDown(self):
        self.f.unlink(missing_ok=True)
        webguard._psl.cache_clear()

    def test_registered_domains_follow_the_list(self):
        rd = webguard.registered_domain
        self.assertEqual(rd("a.b.example.co.uk"), "example.co.uk")
        self.assertEqual(rd("shop.example.com.au"), "example.com.au")
        self.assertEqual(rd("login.paypal.com"), "paypal.com")
        self.assertEqual(rd("x.site.foo.ck"), "site.foo.ck")          # wildcard rule *.ck
        self.assertEqual(rd("www.ck"), "www.ck")                       # exception rule !www.ck
        self.assertEqual(rd("a.b.unknown-tld"), "b.unknown-tld")       # no rule: default is the last label
        self.assertEqual(rd("co.uk"), "co.uk")
        # private-section entries are ignored on purpose (shared hosting stays under brand checks)
        self.assertEqual(rd("evil.s3.amazonaws.com"), "amazonaws.com")
        self.assertNotEqual(webguard.analyze_url("https://evil.s3.amazonaws.com/paypal/login").verdict, "clean")

    def test_falls_back_without_the_list(self):
        self.f.unlink()
        webguard._psl.cache_clear()
        self.assertEqual(webguard.registered_domain("a.b.example.co.uk"), "example.co.uk")
        self.assertEqual(webguard.registered_domain("a.example.com"), "example.com")


class SharedRulesTests(unittest.TestCase):
    """The URL rules are written once (url_rules.json) and every consumer is generated from or reads that file."""
    ROOT = Path(__file__).resolve().parent.parent

    @staticmethod
    def _sync_module():
        import importlib.util
        path = SharedRulesTests.ROOT / "tools" / "sync_extension_rules.py"
        spec = importlib.util.spec_from_file_location("sync_extension_rules", path)
        mod = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(mod)
        return mod

    def test_generated_browser_files_are_up_to_date(self):
        stale = self._sync_module().out_of_date()
        self.assertEqual(stale, [], "run: python tools/sync_extension_rules.py")

    def test_python_uses_the_shared_lists(self):
        from sentinel import url_rules
        rules = url_rules.load()
        self.assertEqual(webguard.BRANDS, rules["brands"])
        self.assertEqual(webguard.OFFICIAL, set(rules["official_domains"]))
        self.assertEqual(webguard.RISKY_TLDS, set(rules["risky_tlds"]))
        self.assertEqual(webguard.USER_CONTENT, set(rules["user_content_hosts"]))
        from sentinel.checks import identity
        self.assertEqual(identity.DOUBLE_EXT.pattern, rules["double_extension_pattern"])

    def test_generated_js_carries_the_config_thresholds(self):
        js = (self.ROOT / "browser_extension" / "url_rules.js").read_text(encoding="utf-8")
        self.assertIn(f'"suspicious_at": {config.SUSPICIOUS_THRESHOLD}', js)
        self.assertIn(f'"malicious_at": {config.MALICIOUS_THRESHOLD}', js)
