"""Updater: the HTTP helper, merging of feed files, the Public Suffix List download and an empty hash feed."""
import os
import shutil
import unittest
from unittest import mock

from sentinel import config, updater, webguard


class FetchTests(unittest.TestCase):
    def test_get_and_post_requests(self):
        response = mock.MagicMock()
        response.__enter__.return_value.read.return_value = "héllo".encode("utf-8")
        with mock.patch.object(updater.urllib.request, "urlopen", return_value=response) as opened:
            self.assertEqual(updater._fetch("https://feed.test/list"), "héllo")
            req = opened.call_args[0][0]
            self.assertIsNone(req.data)
            self.assertIn("X-Secure", req.get_header("User-agent"))
            self.assertEqual(opened.call_args[1]["timeout"], config.FEED_TIMEOUT_SECONDS)
            updater._fetch("https://feed.test/api", {"q": "a b"}, {"Auth-Key": "k"})
            req = opened.call_args[0][0]
            self.assertEqual(req.data, b"q=a+b")
            self.assertEqual(req.get_header("Auth-key"), "k")

    def test_feed_key_prefers_the_new_variable_name(self):
        with mock.patch.dict(os.environ, {"XSECURE_FEED_KEY": "new", "SENTINEL_FEED_KEY": "old"}):
            self.assertEqual(updater.feed_key(), "new")
        with mock.patch.dict(os.environ, {"XSECURE_FEED_KEY": "", "SENTINEL_FEED_KEY": "old"}):
            self.assertEqual(updater.feed_key(), "old")


class UpdateFeedsTests(unittest.TestCase):
    GOOD = "\n".join(f"bad{i}.example-threat.test" for i in range(20)) + "\n"

    def setUp(self):
        self.env = {k: os.environ.pop(k, None) for k in ("XSECURE_FEED_KEY", "SENTINEL_FEED_KEY")}
        for name in ("feeds", "public_suffix_list.dat", "bad_domains.txt", updater.HASH_FILE):
            p = config.UPDATED_SIGS_DIR / name
            shutil.rmtree(p, ignore_errors=True) if p.is_dir() else p.unlink(missing_ok=True)

        def cleanup():
            for k, v in self.env.items():
                if v is not None:
                    os.environ[k] = v
            for name in ("feeds", "public_suffix_list.dat", "bad_domains.txt", updater.HASH_FILE):
                p = config.UPDATED_SIGS_DIR / name
                shutil.rmtree(p, ignore_errors=True) if p.is_dir() else p.unlink(missing_ok=True)
            webguard._bad_domains.cache_clear()
            webguard._psl.cache_clear()
        self.addCleanup(cleanup)

    def test_with_no_successful_feed_the_merged_list_is_left_alone(self):
        with mock.patch.object(updater, "_fetch", side_effect=OSError("offline")):
            report = updater.update_feeds()
        self.assertEqual(report["Bad-domain list in use"], "empty (no feed has succeeded yet)")
        self.assertFalse((config.UPDATED_SIGS_DIR / "bad_domains.txt").exists())
        self.assertTrue(report["Public Suffix List"].startswith("failed"))

    def test_public_suffix_list_is_saved_when_it_looks_real(self):
        psl = "// ===BEGIN ICANN DOMAINS===\n" + "\n".join(f"tld{i}" for i in range(1200)) + "\n// ===END ICANN DOMAINS===\n"

        def fetch(url, *a, **k):
            return psl if url == updater.PSL_URL else self.GOOD
        with mock.patch.object(updater, "_fetch", side_effect=fetch):
            report = updater.update_feeds()
        self.assertEqual(report[updater.PSL_LABEL], "1,200 rules")
        self.assertTrue((config.UPDATED_SIGS_DIR / "public_suffix_list.dat").exists())

    def test_empty_hash_feed_keeps_the_previous_list(self):
        os.environ["XSECURE_FEED_KEY"] = "key"

        def fetch(url, data=None, headers=None):
            if url == updater.HASH_API:
                return '{"query_status": "ok", "data": []}'
            return self.GOOD
        with mock.patch.object(updater, "_fetch", side_effect=fetch):
            report = updater.update_feeds()
        self.assertIn("kept previous list", report[updater.HASH_LABEL])
        self.assertFalse((config.UPDATED_SIGS_DIR / updater.HASH_FILE).exists())

    def test_parse_hashes_rejects_error_status(self):
        with self.assertRaises(ValueError):
            updater.parse_hashes('{"query_status": "unauthorized"}')


if __name__ == "__main__":
    unittest.main()
