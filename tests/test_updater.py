"""Tests for Updater."""
import os
import shutil
import unittest

from sentinel import config, webguard


class UpdaterTests(unittest.TestCase):
    GOOD = "# Title: test list\n" + "\n".join(f"bad{i}.example-threat.test" for i in range(20)) + "\n"

    def setUp(self):
        from sentinel import updater
        self.u = updater
        self._fetch, self._env = updater._fetch, {k: os.environ.pop(k, None) for k in ("XSECURE_FEED_KEY",
                                                                                        "SENTINEL_FEED_KEY")}
        shutil.rmtree(config.UPDATED_SIGS_DIR / "feeds", ignore_errors=True)
        (config.UPDATED_SIGS_DIR / "bad_domains.txt").unlink(missing_ok=True)

    def tearDown(self):
        self.u._fetch = self._fetch
        for k, v in self._env.items():
            if v is not None:
                os.environ[k] = v
            else:
                os.environ.pop(k, None)
        shutil.rmtree(config.UPDATED_SIGS_DIR / "feeds", ignore_errors=True)
        (config.UPDATED_SIGS_DIR / "bad_domains.txt").unlink(missing_ok=True)
        from sentinel.webguard import _bad_domains
        _bad_domains.cache_clear()

    def test_parse_domains_accepts_lists_and_hosts_files_and_drops_junk(self):
        text = ("# comment\nevil.example.com\n0.0.0.0 tracker.bad.test  # trailing\n127.0.0.1 localhost\n"
                "<html>\nnot a domain\nxn--pypal-4ve.com\n")
        self.assertEqual(self.u.parse_domains(text), ["evil.example.com", "tracker.bad.test", "xn--pypal-4ve.com"])

    def test_one_failing_feed_never_wipes_the_others(self):
        urls = {url: slug for slug, (_l, url) in self.u.DOMAIN_FEEDS.items()}
        good_slug = "urlhaus"
        self.u._fetch = lambda url, *a, **k: self.GOOD if urls.get(url) == good_slug else "<html>410 Gone</html>"
        r = self.u.update_feeds()
        self.assertIn("20 domains", r["URLhaus malware domains"])
        self.assertIn("failed", r["Phishing Army phishing domains"])
        self.assertIn("skipped", r[self.u.HASH_LABEL])                  # no key: clearly skipped, not "failed"
        self.assertEqual(webguard.analyze_url("http://bad3.example-threat.test/").verdict, "malicious")
        # next run: every feed fails -> the last good list is kept and still used
        self.u._fetch = lambda url, *a, **k: "<html>error</html>"
        r = self.u.update_feeds()
        self.assertEqual(r["Bad-domain list in use"], "20 domains")
        self.assertEqual(webguard.analyze_url("http://bad3.example-threat.test/").verdict, "malicious")

    def test_hash_feed_uses_the_key_and_keeps_old_list_on_bad_answer(self):
        config.ensure_dirs()
        target = config.UPDATED_SIGS_DIR / self.u.HASH_FILE
        target.write_text("a" * 64 + "\n")
        os.environ["XSECURE_FEED_KEY"] = "test-key"
        seen = {}

        def fake(url, data=None, headers=None):
            if url == self.u.HASH_API:
                seen.update(headers or {}, **(data or {}))
                return '{"query_status": "unknown_auth_key"}'
            return self.GOOD
        self.u._fetch = fake
        r = self.u.update_feeds()
        self.assertEqual(seen.get("Auth-Key"), "test-key")
        self.assertEqual(seen.get("query"), "get_recent")
        self.assertIn("failed", r[self.u.HASH_LABEL])
        self.assertEqual(target.read_text(), "a" * 64 + "\n")
        self.u._fetch = lambda url, data=None, headers=None: (
            '{"query_status": "ok", "data": [{"sha256_hash": "' + "B" * 64 + '"}]}' if url == self.u.HASH_API
            else self.GOOD)
        r = self.u.update_feeds()
        self.assertEqual(r[self.u.HASH_LABEL], "1 hashes")
        self.assertEqual(target.read_text(), "b" * 64 + "\n")
        target.unlink()
