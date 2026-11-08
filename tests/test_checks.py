"""Tests for the individual scan checks, the Scanner's injected collaborators and the small helper modules."""
import io
import logging
import os
import shutil
import tempfile
import unittest
import zipfile
from pathlib import Path
from types import SimpleNamespace
from unittest import mock

from sentinel import ads, authenticode, config, logger, platform_utils
from sentinel.checks import Check, FileContext, default_checks
from sentinel.checks import documents, pe, script, streams, yara_check
from sentinel.checks.identity import DisguisedExecutableCheck, DoubleExtensionCheck, RansomwareNameCheck
from sentinel.entropy import shannon_entropy
from sentinel.result import ScanResult
from sentinel.scanner import Scanner, SignatureDB, add_to_allowlist
from sentinel.verdict import Verdict


def tmp_dir(test):
    d = Path(tempfile.mkdtemp())
    test.addCleanup(shutil.rmtree, d, True)
    return d


def ctx_for(path, data=b"", size=None):
    return FileContext(Path(path), len(data) if size is None else size, data, ScanResult(str(path)))


class SmallModulesTests(unittest.TestCase):
    def test_entropy_of_nothing_is_zero(self):
        self.assertEqual(shannon_entropy(b""), 0.0)
        self.assertEqual(shannon_entropy(b"aaaa"), 0.0)
        self.assertAlmostEqual(shannon_entropy(bytes(range(256))), 8.0)

    def test_verdict_from_score_uses_the_configured_thresholds(self):
        self.assertEqual([Verdict.from_score(s) for s in (0, config.SUSPICIOUS_THRESHOLD, config.MALICIOUS_THRESHOLD)],
                         [Verdict.CLEAN, Verdict.SUSPICIOUS, Verdict.MALICIOUS])
        self.assertEqual(f"{Verdict.ERROR}", "error")

    def test_result_scoring_is_capped_and_errors_stay_errors(self):
        r = ScanResult("x")
        r.add(80, "a")
        r.add(80, "b")
        r.finalize()
        self.assertEqual((r.score, r.verdict, r.reasons), (100, Verdict.MALICIOUS, ["a", "b"]))
        e = ScanResult("y", verdict=Verdict.ERROR, score=500)
        e.finalize()
        self.assertEqual((e.score, e.verdict), (100, Verdict.ERROR))

    def test_norm_path_is_absolute_and_case_folded(self):
        self.assertEqual(platform_utils.norm_path("A.TXT"), os.path.normcase(os.path.abspath("A.TXT")))

    def test_logger_falls_back_when_the_log_file_is_unwritable_and_can_be_closed_twice(self):
        logger.close()
        try:
            with mock.patch.object(logging.handlers, "RotatingFileHandler", side_effect=OSError("read-only")):
                log = logger.get()
            self.assertTrue(any(isinstance(h, logging.NullHandler) for h in log.handlers))
            logger.close()
            logger.close()                                  # nothing to release the second time
        finally:
            logger.close()
            logger.get()

    def test_no_streams_off_windows_and_failed_stream_enumeration(self):
        with mock.patch.object(ads, "IS_WIN", False):
            self.assertEqual(ads.list_streams("x"), [])
        fake = SimpleNamespace(FindFirstStreamW=lambda *a: None, FindNextStreamW=None, FindClose=None)
        with mock.patch.object(ads, "_api", return_value=fake):
            self.assertEqual(ads.list_streams("x"), [])
        invalid = SimpleNamespace(FindFirstStreamW=lambda *a: ads._INVALID)
        with mock.patch.object(ads, "_api", return_value=invalid):
            self.assertEqual(ads.list_streams("x"), [])

    def test_stream_enumeration_skips_the_main_stream_and_unnamed_entries(self):
        names = iter([":real:$DATA", "::$DATA", "::x", ""])     # real stream, main stream, empty name, empty entry
        state = {"data": None}

        def find_first(path, level, ref, flags):
            state["data"] = ref._obj
            state["data"].cStreamName = next(names)
            state["data"].StreamSize = 7
            return 5

        def find_next(handle, ref):
            try:
                state["data"].cStreamName = next(names)
            except StopIteration:
                return 0
            return 1
        api = SimpleNamespace(FindFirstStreamW=find_first, FindNextStreamW=find_next, FindClose=lambda h: None)
        with mock.patch.object(ads, "IS_WIN", True), mock.patch.object(ads, "_api", return_value=api):
            self.assertEqual(ads.list_streams("file.txt"), [("real", 7)])

    def test_signature_check_off_windows_and_when_the_api_misbehaves(self):
        with mock.patch.object(authenticode, "IS_WIN", False):
            self.assertFalse(authenticode.has_valid_signature("x.exe"))
        with mock.patch.object(authenticode, "IS_WIN", True), \
                mock.patch.object(authenticode.ctypes, "windll", SimpleNamespace(), create=True):
            self.assertFalse(authenticode.has_valid_signature("x.exe"))        # no wintrust attribute
        results = iter([0, 0])
        fake = SimpleNamespace(wintrust=SimpleNamespace(WinVerifyTrust=lambda *a: next(results)))
        with mock.patch.object(authenticode, "IS_WIN", True), \
                mock.patch.object(authenticode.ctypes, "windll", fake, create=True):
            self.assertTrue(authenticode.has_valid_signature("signed.exe"))


class IdentityCheckTests(unittest.TestCase):
    def test_disguised_executable_double_extension_and_ransom_names(self):
        c = ctx_for("report.pdf", b"MZ\x90\x00")
        self.assertTrue(DisguisedExecutableCheck().applies(c))
        DisguisedExecutableCheck().run(c)
        self.assertIn("disguised", c.result.reasons[0])
        self.assertFalse(DisguisedExecutableCheck().applies(ctx_for("tool.exe", b"MZ")))
        dbl = ctx_for("invoice.pdf.exe", b"x")
        self.assertTrue(DoubleExtensionCheck().applies(dbl))
        recent = ctx_for(r"C:\Users\me\AppData\Roaming\Microsoft\Windows\Recent\notes.docx.lnk", b"x")
        self.assertFalse(DoubleExtensionCheck().applies(recent))               # normal in the Recent folder
        r = ctx_for("HOW_TO_DECRYPT_FILES.txt", b"x")
        self.assertTrue(RansomwareNameCheck().applies(r))
        self.assertTrue(RansomwareNameCheck().applies(ctx_for("a.docx.locked", b"x")))
        for chk, ctx in ((DoubleExtensionCheck(), dbl), (RansomwareNameCheck(), r)):
            chk.run(ctx)
            self.assertTrue(ctx.result.reasons)

    def test_default_checks_are_ordered_and_named(self):
        names = [c.name for c in default_checks(None, lambda p: None)]
        self.assertEqual(names[:4], ["disguised-executable", "double-extension", "ransomware-name", "pe-heuristics"])
        self.assertEqual(len(names), len(set(names)))
        with self.assertRaises(TypeError):
            Check()                                                           # abstract: must be subclassed


class ScriptCheckTests(unittest.TestCase):
    def test_decoding_variants(self):
        text = "IEX (New-Object Net.WebClient)"
        self.assertEqual(script.decode_script(b"\xff\xfe" + text.encode("utf-16-le")[0:]).decode(), text)
        self.assertEqual(script.decode_script(text.encode("utf-16-le")).decode(), text)             # BOM-less LE
        self.assertEqual(script.decode_script(text.encode("utf-16-be")).decode(), text)             # BOM-less BE
        self.assertEqual(script.decode_script(b"plain"), b"plain")
        self.assertEqual(script.decode_encoded_command(b"!!!notbase64!!!"), b"")

    def test_unreadable_script_and_nested_encoded_payload(self):
        d = tmp_dir(self)
        res = ScanResult("x")
        script.script_checks(d / "missing.ps1", res)
        self.assertEqual(res.score, 0)
        import base64
        inner = base64.b64encode("vssadmin delete shadows /all".encode("utf-16-le")).decode()
        f = d / "s.ps1"
        f.write_text(f"powershell -enc {inner}\n")
        c = ctx_for(f, b"x")
        self.assertTrue(script.ScriptCheck().applies(c))
        script.ScriptCheck().run(c)
        self.assertTrue(any("hidden in encoded command" in r for r in c.result.reasons))


class ArchiveCheckTests(unittest.TestCase):
    def setUp(self):
        self.d = tmp_dir(self)

    def zipfile_of(self, name, members):
        p = self.d / name
        with zipfile.ZipFile(p, "w") as z:
            for n, data in members.items():
                z.writestr(n, data)
        return p

    def run_zip(self, p, ext=None):
        res = ScanResult(str(p))
        documents.zip_checks(p, ext or p.suffix.lower(), res)
        return res

    def test_corrupt_archive_is_ignored(self):
        p = self.d / "bad.zip"
        p.write_bytes(b"PK\x03\x04 not really a zip")
        self.assertEqual(self.run_zip(p).score, 0)
        self.assertEqual(self.run_zip(self.d / "gone.zip").score, 0)

    def test_plain_archives(self):
        res = self.run_zip(self.zipfile_of("a.zip", {"readme.txt": "x", "setup.exe": "x", "run.bat": "x"}))
        self.assertIn("Archive contains programs/scripts", res.reasons[0])
        res = self.run_zip(self.zipfile_of("b.zip", {"invoice.pdf.exe": "x"}))
        self.assertIn("disguised program", res.reasons[0])
        self.assertEqual(self.run_zip(self.zipfile_of("c.jar", {"A.class": "x", "evil.exe": "x"})).score, 0)
        self.assertEqual(self.run_zip(self.zipfile_of("d.zip", {"docs/readme.txt": "x"})).score, 0)

    def test_entry_count_zip_bomb_and_password_flags(self):
        p = self.zipfile_of("many.zip", {f"f{i}.txt": "x" for i in range(5)})
        with mock.patch.object(documents, "MAX_ZIP_ENTRIES", 3):
            self.assertIn("unusually large number", self.run_zip(p).reasons[0])
        with mock.patch.object(config, "ZIP_BOMB_TOTAL_BYTES", 2):
            self.assertIn("zip bomb", self.run_zip(p).reasons[0])
        with mock.patch.object(config, "ZIP_BOMB_MIN_BYTES", 1), mock.patch.object(config, "ZIP_BOMB_RATIO", 0):
            self.assertIn("zip bomb", self.run_zip(p).reasons[0])
        raw = bytearray(p.read_bytes())
        for sig in (b"PK\x03\x04", b"PK\x01\x02"):                       # set the "encrypted" flag in every header
            i = raw.find(sig)
            off = 6 if sig == b"PK\x03\x04" else 8
            while i != -1:
                raw[i + off] |= 1
                i = raw.find(sig, i + 1)
        q = self.d / "locked.zip"
        q.write_bytes(bytes(raw))
        self.assertTrue(any("Password-protected" in r for r in self.run_zip(q).reasons))

    def office(self, name, vba=None, rels=None, extra=None):
        members = {"[Content_Types].xml": "x"}
        if vba is not None:
            members["word/vbaProject.bin"] = vba
        if rels is not None:
            members["word/_rels/document.xml.rels"] = rels
        members.update(extra or {})
        return self.zipfile_of(name, members)

    def test_office_macros(self):
        vba = b"Sub AutoOpen()\nShell cmd.exe\nEnd Sub"
        res = self.run_zip(self.office("m.docm", vba=vba))
        self.assertEqual(len(res.reasons), 3)
        res = self.run_zip(self.office("hidden.docx", vba=b"harmless"))
        self.assertEqual(res.reasons, ["Macros hidden inside a macro-free file type"])
        self.assertEqual(self.run_zip(self.office("clean.docx")).score, 0)

    def test_remote_template_and_unreadable_members(self):
        rels = b'<Relationship Type=".../attachedTemplate" Target="http://evil.test/t.dotm" TargetMode="External"/>'
        res = self.run_zip(self.office("t.docx", rels=rels))
        self.assertIn("remote template", res.reasons[0])
        p = self.office("t2.docx", rels=b"x", vba=b"AutoOpen")
        with mock.patch.object(zipfile.ZipFile, "read", side_effect=RuntimeError("encrypted member")):
            self.assertEqual(self.run_zip(p).reasons, ["Macros hidden inside a macro-free file type"])
        big = self.office("big.docx", vba=b"x" * 10)
        with mock.patch.object(config, "ZIP_MEMBER_READ_CAP", 1):
            self.run_zip(big)                                                   # member larger than the cap: skipped

    def test_legacy_office_macros(self):
        res = ScanResult("x")
        documents.ole_checks(b"no macros here", res)
        self.assertEqual(res.score, 0)
        documents.ole_checks(b"..VBA..Document_Open..Shell..", res)
        self.assertEqual(len(res.reasons), 3)
        res2 = ScanResult("y")
        documents.ole_checks(b"_VBA_PROJECT only", res2)
        self.assertEqual(res2.reasons, ["Legacy Office document contains VBA macros"])

    def test_applies_rules(self):
        zip_ctx = ctx_for("a.zip", b"PK\x03\x04rest")
        self.assertTrue(documents.ArchiveCheck().applies(zip_ctx))
        self.assertFalse(documents.ArchiveCheck().applies(ctx_for("a.txt", b"PK\x03\x04rest")))
        huge = ctx_for("a.zip", b"PK\x03\x04", size=config.MAX_HEURISTIC_SIZE + 1)
        self.assertFalse(documents.ArchiveCheck().applies(huge))
        ole = ctx_for("a.doc", documents.OLE_MAGIC + b"x")
        self.assertTrue(documents.LegacyOfficeCheck().applies(ole))
        p = self.zipfile_of("run.zip", {"x.exe": "x"})
        c = ctx_for(p, b"PK\x03\x04")
        documents.ArchiveCheck().run(c)
        self.assertTrue(c.result.reasons)
        o = ctx_for("o.doc", documents.OLE_MAGIC + b"VBA")
        documents.LegacyOfficeCheck().run(o)
        self.assertTrue(o.result.reasons)


class FakePE:
    """Minimal stand-in for pefile.PE."""
    closed = False

    def __init__(self, sections=(), imports=None):
        self.sections = list(sections)
        if imports is not None:
            self.DIRECTORY_ENTRY_IMPORT = imports

    def close(self):
        FakePE.closed = True


def section(name, chars=0, raw=0, entropy=0.0):
    return SimpleNamespace(Name=name.encode().ljust(8, b"\x00"), Characteristics=chars, SizeOfRawData=raw,
                           get_entropy=lambda: entropy)


def imp(name):
    return SimpleNamespace(name=name.encode() if name else None)


class PeCheckTests(unittest.TestCase):
    def run_pe(self, fake=None, error=None, ext=".dll", sample=b"MZ"):
        res = ScanResult("x")
        if error:
            pef = SimpleNamespace(PE=mock.Mock(side_effect=error))
        else:
            pef = SimpleNamespace(PE=lambda *a, **k: fake)
        with mock.patch.object(pe, "pefile", pef):
            pe.pe_checks(Path("x.dll"), sample, ext, res)
        return res

    def test_high_entropy_executable_without_pefile(self):
        res = ScanResult("x")
        with mock.patch.object(pe, "pefile", None):
            pe.pe_checks(Path("x.exe"), os.urandom(4096), ".exe", res)
        self.assertEqual(res.reasons, ["Very high entropy (packed or encrypted)"])
        res = ScanResult("y")
        with mock.patch.object(pe, "pefile", None):
            pe.pe_checks(Path("x.dll"), os.urandom(4096), ".dll", res)               # only .exe-like files get this
        self.assertEqual(res.score, 0)

    def test_unparseable_pe_is_skipped_quietly(self):
        self.assertEqual(self.run_pe(error=ValueError("bad header")).score, 0)

    def test_section_and_import_heuristics(self):
        wx = 0x20000000 | 0x80000000
        fake = FakePE(
            [section(".text", wx), section("UPX0", 0, 5000, 7.9), section(".tiny", 0, 100, 7.9)],
            imports=[SimpleNamespace(imports=[imp("CreateRemoteThread"), imp("WriteProcessMemory"), imp(None), imp("Other")])])
        res = self.run_pe(fake)
        self.assertEqual(len(res.reasons), 4)
        self.assertTrue(FakePE.closed)
        capped = [r for r in res.reasons if "injection" in r]
        self.assertTrue(capped)
        self.assertEqual(res.score, 15 + 10 + 10 + 25)                              # import points are capped at 25

    def test_clean_pe_and_missing_import_table(self):
        res = self.run_pe(FakePE([section(".text", 0x20000000, 5000, 5.0)]))
        self.assertEqual(res.score, 0)

    def test_padding_detection(self):
        d = tmp_dir(self)
        f = d / "padded.exe"
        f.write_bytes(b"MZ" + b"\x00" * 5000)
        res = ScanResult("x")
        pe.padding_check(f, f.stat().st_size, res)
        self.assertIn("padded with filler", res.reasons[0])
        res = ScanResult("y")
        pe.padding_check(d / "missing.exe", 10, res)                                # unreadable: ignored
        busy = d / "busy.exe"
        busy.write_bytes(os.urandom(4096))
        pe.padding_check(busy, 4096, res)
        empty = d / "empty.exe"
        empty.write_bytes(b"")
        pe.padding_check(empty, 0, res)
        self.assertEqual(res.score, 0)

    def test_check_object_adds_padding_check_for_oversized_files(self):
        d = tmp_dir(self)
        f = d / "huge.exe"
        f.write_bytes(b"MZ" + b"\x00" * 4000)
        chk = pe.PeHeuristicsCheck()
        with mock.patch.object(config, "MAX_HEURISTIC_SIZE", 1000):          # make a 4 KB file count as "oversized"
            c = FileContext(f, f.stat().st_size, b"MZ" + b"\x00" * 100, ScanResult(str(f)))
            self.assertTrue(chk.applies(c))
            with mock.patch.object(pe, "pefile", None):
                chk.run(c)
            self.assertTrue(any("padded" in r for r in c.result.reasons))
            small = FileContext(f, 900, b"MZ", ScanResult(str(f)))
            with mock.patch.object(pe, "pefile", None):
                chk.run(small)
            self.assertEqual(small.result.reasons, [])


class YaraCheckTests(unittest.TestCase):
    class Err(Exception):
        pass

    def fake_yara(self, compile_error=None):
        err = self.Err
        comp = mock.Mock(side_effect=compile_error) if compile_error else mock.Mock(return_value="rules")
        return SimpleNamespace(Error=err, compile=comp)

    def test_rules_load_only_when_everything_is_present(self):
        with mock.patch.object(yara_check, "yara", None):
            self.assertIsNone(yara_check.load_rules())
        d = tmp_dir(self)
        with mock.patch.object(yara_check, "yara", self.fake_yara()):
            with mock.patch.object(config, "RULES_DIR", d / "absent"):
                self.assertIsNone(yara_check.load_rules())
            with mock.patch.object(config, "RULES_DIR", d):
                self.assertIsNone(yara_check.load_rules())                       # no .yar files
                (d / "r.yar").write_text("rule x { condition: true }")
                self.assertEqual(yara_check.load_rules(), "rules")
        with mock.patch.object(yara_check, "yara", self.fake_yara(self.Err("syntax"))), \
                mock.patch.object(config, "RULES_DIR", d):
            self.assertIsNone(yara_check.load_rules(log=True))
            self.assertIsNone(yara_check.load_rules(log=False))

    def test_matching_and_failures(self):
        rules = mock.Mock()
        rules.match.return_value = [SimpleNamespace(rule="Evil")]
        chk = yara_check.YaraCheck(rules)
        c = ctx_for("f.bin", b"x")
        self.assertTrue(chk.applies(c))
        self.assertFalse(yara_check.YaraCheck(None).applies(c))
        self.assertFalse(chk.applies(ctx_for("f.bin", b"x", size=config.MAX_HEURISTIC_SIZE + 1)))
        with mock.patch.object(yara_check, "yara", self.fake_yara()):
            chk.run(c)
            self.assertEqual(c.result.reasons, ["YARA rule matched: Evil"])
            rules.match.side_effect = self.Err("scan failed")
            chk.run(ctx_for("g.bin", b"x"))                                        # logged, never raised


class StreamCheckTests(unittest.TestCase):
    def test_stream_decisions(self):
        d = tmp_dir(self)
        f = d / "host.txt"
        f.write_text("x")
        scanned = []

        def scan(path):
            scanned.append(path)
            return ScanResult(path, Verdict.SUSPICIOUS, 30, "h", ["bad content", "more", "extra"])
        chk = streams.AlternateStreamCheck(scan, lambda p: [("evil.exe", 10), ("gone", 5)], enabled=True)
        self.assertTrue(chk.applies(ctx_for(f, b"x")))
        self.assertFalse(chk.applies(ctx_for(d / "host.txt:inner", b"x")))        # never recurse into a stream
        self.assertFalse(streams.AlternateStreamCheck(scan, lambda p: [], enabled=False).applies(ctx_for(f, b"x")))
        res = ScanResult(str(f))
        stream_file = Path(f"{f}:evil.exe")
        real_open = open

        def fake_open(path, mode="r", *a, **k):
            if str(path).endswith(":evil.exe"):
                return io.BytesIO(b"MZ\x90\x00")
            if str(path).endswith(":gone"):
                raise OSError("no such stream")
            return real_open(path, mode, *a, **k)
        with mock.patch("builtins.open", fake_open):
            chk.run(FileContext(f, 1, b"x", res))
        self.assertEqual(len(res.reasons), 1)
        self.assertIn("hidden program", res.reasons[0])
        self.assertIn("bad content; more", res.reasons[0])
        self.assertEqual(scanned, [str(stream_file)])

    def test_weak_streams_and_error_results_are_not_reported(self):
        res = ScanResult("x")
        chk = streams.AlternateStreamCheck(lambda p: ScanResult(p, Verdict.ERROR, 99), lambda p: [], enabled=True)
        with mock.patch("builtins.open", lambda *a, **k: io.BytesIO(b"text")):
            chk._check_stream(Path("f"), "s", res)
        self.assertEqual(res.score, 0)
        chk2 = streams.AlternateStreamCheck(lambda p: ScanResult(p, Verdict.SUSPICIOUS, 25), lambda p: [], enabled=True)
        with mock.patch("builtins.open", lambda *a, **k: io.BytesIO(b"text")):
            chk2._check_stream(Path("f"), "s", res)
        self.assertIn("hidden risky content", res.reasons[0])
        self.assertNotIn("(", res.reasons[0])                                      # no detail when the stream has none


class ScannerDesignTests(unittest.TestCase):
    """The Scanner's collaborators are injected, so it can be driven without Windows, YARA or real signatures."""

    def setUp(self):
        self.d = tmp_dir(self)
        self.f = self.d / "prog.exe"
        self.f.write_bytes(b"MZ" + b"\x00" * 200)

    class AddPoints(Check):
        def __init__(self, pts, structural=False, applies=True):
            self.pts, self.structural, self._applies = pts, structural, applies

        def applies(self, ctx):
            return self._applies

        def run(self, ctx):
            ctx.result.add(self.pts, f"added {self.pts}")

    def scanner(self, checks, verifier=lambda p: False, **kw):
        return Scanner(db=SignatureDB(dirs=[]), log=False, checks=checks, signature_verifier=verifier,
                       allowlist=set(), **kw)

    def test_custom_checks_run_in_order_and_skip_when_they_do_not_apply(self):
        sc = self.scanner([self.AddPoints(10), self.AddPoints(99, applies=False), self.AddPoints(30)])
        r = sc.scan_file(self.f)
        self.assertEqual((r.score, r.reasons, r.verdict), (40, ["added 10", "added 30"], Verdict.SUSPICIOUS))
        self.assertIsNone(sc.rules)                                               # no YARA work when checks are injected

    def test_valid_signature_offsets_only_structural_points(self):
        calls = []
        sc = self.scanner([self.AddPoints(40, structural=True), self.AddPoints(10)],
                          verifier=lambda p: calls.append(p) or True)
        r = sc.scan_file(self.f)
        self.assertEqual(r.score, 20)                                              # 50 minus the capped discount of 30
        self.assertIn("risk lowered by 30", r.reasons[-1])                         # capped by SIGNATURE_MAX_DISCOUNT
        self.assertEqual(len(calls), 1)

    def test_signature_is_never_consulted_for_non_programs_or_hard_hits(self):
        calls = []
        verifier = lambda p: calls.append(p) or True  # noqa: E731
        doc = self.d / "doc.txt"
        doc.write_text("plain text")
        self.scanner([self.AddPoints(60, structural=True)], verifier).scan_file(doc)
        known = self.d / "known.exe"
        known.write_bytes(b"MZ-known")
        import hashlib
        db = SignatureDB(dirs=[])
        db.hashes[hashlib.sha256(b"MZ-known").hexdigest()] = "Test malware"
        sc = Scanner(db=db, log=False, checks=[self.AddPoints(40, structural=True)], signature_verifier=verifier,
                     allowlist=set())
        r = sc.scan_file(known)
        self.assertEqual(r.verdict, Verdict.MALICIOUS)
        self.assertIn("Test malware", r.reasons[0])
        self.assertEqual(calls, [])

    def test_allowlist_wins_unless_the_hash_is_known_bad(self):
        import hashlib
        digest = hashlib.sha256(self.f.read_bytes()).hexdigest()
        sc = Scanner(db=SignatureDB(dirs=[]), log=False, checks=[self.AddPoints(80)], allowlist={digest})
        self.assertEqual(sc.scan_file(self.f).verdict, Verdict.CLEAN)
        db = SignatureDB(dirs=[])
        db.hashes[digest] = "bad"
        sc = Scanner(db=db, log=False, checks=[], allowlist={digest})
        self.assertEqual(sc.scan_file(self.f).verdict, Verdict.MALICIOUS)

    def test_eicar_marker_is_a_hard_hit(self):
        # The real EICAR file is blocked by the host antivirus, so feed the scanner its hash and sample directly.
        small = self.d / "tiny.txt"
        small.write_text("x")
        from sentinel import scanner as scanner_module
        with mock.patch.object(scanner_module, "_hash_and_sample", return_value=("0" * 64, scanner_module.EICAR_MARKER)):
            r = self.scanner([]).scan_file(small)
        self.assertEqual((r.verdict, r.reasons), (Verdict.MALICIOUS, ["EICAR antivirus test file"]))

    def test_unreadable_file_is_an_error_result(self):
        r = self.scanner([]).scan_file(self.d / "missing.bin")
        self.assertEqual(r.verdict, Verdict.ERROR)
        self.assertIn("Could not read file", r.reasons[0])

    def test_logging_flag(self):
        sc = Scanner(db=SignatureDB(dirs=[]), log=True, checks=[self.AddPoints(80)], allowlist=set())
        with mock.patch("sentinel.scanner.logger.get") as get:
            sc.scan_file(self.f)
        get.return_value.warning.assert_called_once()

    def test_default_scanner_has_all_standard_checks_and_reads_the_allowlist_file(self):
        sc = Scanner(log=False)
        self.assertGreaterEqual(len(sc.checks), 9)
        self.assertIsInstance(sc.allow, set)
        add_to_allowlist("AB" * 32, "unit test")
        self.assertIn("ab" * 32, Scanner._load_allowlist())
        with mock.patch.object(config, "ALLOWLIST_FILE", self.d / "nope.txt"):
            self.assertEqual(Scanner._load_allowlist(), set())
        notes = self.d / "list.txt"
        notes.write_text("# comment\nshort\n" + "cd" * 32 + " note\n\n")
        with mock.patch.object(config, "ALLOWLIST_FILE", notes):
            self.assertEqual(Scanner._load_allowlist(), {"cd" * 32})

    def test_signature_db_loading(self):
        sigs = self.d / "sigs"
        sigs.mkdir()
        (sigs / "hashes_a.txt").write_text("# c\n" + "AA" * 32 + " Evil.A\n" + "bb" * 32 + "\nnot-a-hash x\n" + "g" * 64 + "\n")
        (sigs / "hashes_b.txt").write_bytes(b"\xff\xfe")
        db = SignatureDB(dirs=[sigs, self.d / "absent"])
        self.assertEqual(db.hashes, {"aa" * 32: "Evil.A", "bb" * 32: "Known malware hash"})
        with mock.patch.object(Path, "read_text", side_effect=OSError("denied")):
            self.assertEqual(SignatureDB(dirs=[sigs]).hashes, {})

    def test_scan_tree_skips_quarantine_links_and_cancels(self):
        root = self.d / "tree"
        (root / "sub").mkdir(parents=True)
        (root / "a.txt").write_text("a")
        (root / "sub" / "b.txt").write_text("b")
        sc = self.scanner([])
        self.assertEqual(len(list(sc.scan_tree(root))), 2)
        self.assertEqual(len(list(sc.scan_tree(root / "a.txt"))), 1)
        import threading
        ev = threading.Event()
        ev.set()
        self.assertEqual(list(sc.scan_tree(root, cancel=ev)), [])
        with mock.patch.object(os.path, "islink", return_value=True):
            self.assertEqual(list(sc.scan_tree(root)), [])
        quarantine_like = Path(config.QUARANTINE_DIR)
        quarantine_like.mkdir(parents=True, exist_ok=True)
        (quarantine_like / "item.qz").write_text("x")
        self.assertEqual([r.path for r in sc.scan_tree(config.DATA_DIR) if r.path.endswith("item.qz")], [])


if __name__ == "__main__":
    unittest.main()
