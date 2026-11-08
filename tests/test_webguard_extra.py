"""More URL-analysis cases: malformed input, brand tricks, the Public Suffix List parser and the bad-domain list."""
import shutil
import tempfile
import unittest
from pathlib import Path
from unittest import mock

from sentinel import config, webguard
from sentinel.verdict import Verdict


def reasons(url):
    return webguard.analyze_url(url).reasons


class MalformedInputTests(unittest.TestCase):
    def test_unparseable_and_hostless_urls_are_suspicious(self):
        v = webguard.analyze_url("http://[::1")
        self.assertEqual((v.verdict, v.reasons), (Verdict.SUSPICIOUS, ["Malformed URL"]))
        v = webguard.analyze_url("http://")
        self.assertEqual((v.verdict, v.reasons), (Verdict.SUSPICIOUS, ["No hostname"]))

    def test_a_missing_scheme_is_assumed_to_be_http(self):
        self.assertIn("Sensitive page served over unencrypted HTTP", reasons("example.org/login/verify"))

    def test_unicode_host_that_cannot_become_punycode_is_still_analysed(self):
        host = "a" * 70 + "é.com"                                          # label too long for IDNA
        self.assertIsInstance(webguard.analyze_url(f"http://{host}/").score, int)


class BrandTrickTests(unittest.TestCase):
    def test_each_brand_rule(self):
        self.assertTrue(any("Excessive number of subdomains" in r for r in reasons("http://a.b.c.d.example.com/")))
        self.assertTrue(any("on an unofficial domain" in r for r in reasons("https://paypal.xyz/")))
        self.assertFalse(any("paypal" in r for r in reasons("https://paypal.org/")))               # exact label, safe TLD
        self.assertTrue(any("Look-alike of 'paypal'" in r for r in reasons("https://paypa1.com/")))
        self.assertTrue(any("one or two letters away from 'paypal'" in r for r in reasons("https://peypal.com/")))
        self.assertTrue(any("used as a subdomain" in r for r in reasons("https://paypal.safe-site.org/")))

    def test_long_urls_and_sensitive_paths(self):
        long_url = "https://example.org/" + "a" * 130
        self.assertIn("Very long URL", reasons(long_url))
        r = reasons("http://example.org/login/verify")
        self.assertTrue(any("Sensitive keywords" in x for x in r))
        self.assertIn("Sensitive page served over unencrypted HTTP", r)


class PublicSuffixParserTests(unittest.TestCase):
    def setUp(self):
        self.old = config.UPDATED_SIGS_DIR / "public_suffix_list.dat"
        self.backup = self.old.read_bytes() if self.old.exists() else None
        webguard._psl.cache_clear()

        def restore():
            if self.backup is None:
                self.old.unlink(missing_ok=True)
            else:
                self.old.write_bytes(self.backup)
            webguard._psl.cache_clear()
        self.addCleanup(restore)
        config.ensure_dirs()

    def write(self, body):
        self.old.write_text(body, encoding="utf-8")
        webguard._psl.cache_clear()
        return webguard._psl()

    def test_sections_wildcards_exceptions_and_bad_idna(self):
        rules = "\n".join(f"tld{i}" for i in range(1100))
        parsed = self.write("// ===BEGIN ICANN DOMAINS===\n" + rules + "\n*.wild\n!www.wild\n" + "a" * 70 + "\n\n// comment\n")
        # no END marker: the whole rest of the file is read
        suffixes, wild, exc = parsed
        self.assertIn("tld5", suffixes)
        self.assertIn("wild", wild)
        self.assertIn("www.wild", exc)
        self.assertIn("a" * 70, suffixes)                                     # IDNA failure keeps the raw rule

    def test_private_section_is_ignored_and_small_lists_are_rejected(self):
        body = ("// ===BEGIN ICANN DOMAINS===\n" + "\n".join(f"t{i}" for i in range(1100)) +
                "\n// ===END ICANN DOMAINS===\nprivate.example\n")
        suffixes, _, _ = self.write(body)
        self.assertNotIn("private.example", suffixes)
        self.assertIsNone(self.write("// ===BEGIN ICANN DOMAINS===\ncom\n"))
        self.old.unlink()
        webguard._psl.cache_clear()
        self.assertIsNone(webguard._psl())                                    # not downloaded yet


class BadDomainListTests(unittest.TestCase):
    def test_lists_are_read_from_bundled_and_downloaded_files(self):
        d = Path(tempfile.mkdtemp())
        self.addCleanup(shutil.rmtree, d, True)
        (d / "bad_domains.txt").write_text("# comment\nEvil.Example\n\nother.test\n")
        webguard._bad_domains.cache_clear()
        self.addCleanup(webguard._bad_domains.cache_clear)
        with mock.patch.object(config, "SIGNATURES_DIR", d), mock.patch.object(config, "UPDATED_SIGS_DIR", d / "none"):
            bad = webguard._bad_domains()
        self.assertEqual(bad, frozenset({"evil.example", "other.test"}))
        webguard._bad_domains.cache_clear()
        with mock.patch.object(config, "SIGNATURES_DIR", d), mock.patch.object(config, "UPDATED_SIGS_DIR", d / "none"):
            v = webguard.analyze_url("https://sub.evil.example/")
        self.assertEqual(v.verdict, Verdict.MALICIOUS)


class IpParsingTests(unittest.TestCase):
    def test_octal_and_malformed_forms(self):
        self.assertEqual(webguard.parse_ipv4("0300.0250.0.1"), "192.168.0.1")
        self.assertIsNone(webguard.parse_ipv4("1.2.3.4.5"))
        self.assertIsNone(webguard.parse_ipv4("999.1.1.1"))
        self.assertIsNone(webguard.parse_ipv4("08.1.1.1"))                    # not valid octal

    def test_levenshtein(self):
        self.assertEqual(webguard.levenshtein("kitten", "sitting"), 3)
        self.assertEqual(webguard.levenshtein("", "abc"), 3)


if __name__ == "__main__":
    unittest.main()
