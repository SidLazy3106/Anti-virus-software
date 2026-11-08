"""Tests for Engine."""
import os
import shutil
import sys
import tempfile
import unittest
from pathlib import Path

from sentinel import config


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
