"""Engine internals: file enumeration edge cases, the result cache, workers and the parallel/serial scan loops."""
import ctypes
import os
import shutil
import stat
import tempfile
import threading
import time
import unittest
from concurrent.futures import Future
from concurrent.futures.process import BrokenProcessPool
from pathlib import Path
from types import SimpleNamespace
from unittest import mock

from sentinel import config, engine
from sentinel.result import ScanResult
from sentinel.verdict import Verdict
from sentinel.winconst import FILE_ATTRIBUTE_OFFLINE


class StatsAndJunctionTests(unittest.TestCase):
    def test_elapsed_uses_now_until_finished(self):
        s = engine.ScanStats(started=time.time() - 5)
        self.assertGreaterEqual(s.elapsed, 5)
        s.finished = s.started + 2
        self.assertEqual(s.elapsed, 2)

    def test_is_junction_fallbacks(self):
        entry = SimpleNamespace(path="x")                                      # no is_junction() (old Python)
        with mock.patch.object(engine, "IS_WIN", False):
            self.assertFalse(engine._is_junction(entry))
        with mock.patch.object(engine, "IS_WIN", True):
            with mock.patch.object(engine.os, "lstat", return_value=SimpleNamespace(
                    st_reparse_tag=engine.IO_REPARSE_TAG_MOUNT_POINT)):
                self.assertTrue(engine._is_junction(entry))
            with mock.patch.object(engine.os, "lstat", side_effect=OSError("gone")):
                self.assertFalse(engine._is_junction(entry))
        modern = SimpleNamespace(path="x", is_junction=lambda: True)
        self.assertTrue(engine._is_junction(modern))


class FakeEntry:
    def __init__(self, path, *, symlink=False, is_dir=False, is_file=True, attrs=0, mode=stat.S_IFREG, stat_error=False,
                 size=3):
        self.path, self.name = path, os.path.basename(path)
        self._sl, self._d, self._f, self._attrs, self._mode, self._err, self._size = symlink, is_dir, is_file, attrs, mode, stat_error, size

    def is_symlink(self):
        return self._sl

    def is_junction(self):
        return False

    def is_dir(self, follow_symlinks=True):
        return self._d

    def is_file(self, follow_symlinks=True):
        return self._f

    def stat(self, follow_symlinks=True):
        if self._err:
            raise OSError("vanished")
        return SimpleNamespace(st_size=self._size, st_mtime_ns=7, st_file_attributes=self._attrs, st_mode=self._mode)


class FakeScandir:
    """Context-manager iterator over fake entries; may raise OSError mid-listing."""
    def __init__(self, entries, fail_after=None):
        self.entries, self.fail_after, self.i = entries, fail_after, 0

    def __enter__(self):
        return self

    def __exit__(self, *a):
        return False

    def __iter__(self):
        return self

    def __next__(self):
        if self.fail_after is not None and self.i >= self.fail_after:
            raise OSError("listing broke")
        if self.i >= len(self.entries):
            raise StopIteration
        self.i += 1
        return self.entries[self.i - 1]


class IterFilesTests(unittest.TestCase):
    def setUp(self):
        self.d = Path(tempfile.mkdtemp())
        self.addCleanup(shutil.rmtree, self.d, True)

    def test_single_file_roots_and_duplicates(self):
        f = self.d / "one.txt"
        f.write_text("x")
        stats = engine.ScanStats()
        got = list(engine.iter_files([f, f, self.d / "nested"], stats=stats))
        self.assertEqual([os.path.basename(p) for p, _, _ in got], ["one.txt"])
        with mock.patch.object(engine.os, "stat", side_effect=OSError("locked")):
            list(engine.iter_files([f], stats=stats))
        self.assertEqual(stats.errors, 1)

    def test_a_file_root_is_not_listed_again_by_its_folder(self):
        f = self.d / "one.txt"
        f.write_text("x")
        (self.d / "two.txt").write_text("y")
        got = sorted(os.path.basename(p) for p, _, _ in engine.iter_files([f, self.d]))
        self.assertEqual(got, ["one.txt", "two.txt"])

    def test_excluded_and_nested_roots_are_skipped(self):
        (self.d / "sub").mkdir()
        (self.d / "sub" / "a.txt").write_text("x")
        self.assertEqual(list(engine.iter_files([self.d / "sub"], exclude=[self.d])), [])

    def test_unreadable_directories_are_counted(self):
        stats = engine.ScanStats()
        with mock.patch.object(engine.os, "scandir", side_effect=OSError("denied")):
            self.assertEqual(list(engine.iter_files([self.d], stats=stats)), [])
        self.assertEqual(stats.dirs_denied, 1)
        stats = engine.ScanStats()
        with mock.patch.object(engine.os, "scandir", return_value=FakeScandir([], fail_after=0)):
            self.assertEqual(list(engine.iter_files([self.d], stats=stats)), [])
        self.assertEqual(stats.dirs_denied, 1)

    def test_every_kind_of_entry(self):
        base = str(self.d)
        entries = [
            FakeEntry(base + r"\link", symlink=True),
            FakeEntry(base + r"\subdir", is_dir=True, is_file=False),
            FakeEntry(base + r"\pagefile.sys"),
            FakeEntry(base + r"\cloud.docx", attrs=FILE_ATTRIBUTE_OFFLINE),
            FakeEntry(base + r"\device", is_file=False),
            FakeEntry(base + r"\fifo", mode=stat.S_IFIFO),
            FakeEntry(base + r"\locked.bin", stat_error=True),
            FakeEntry(base + r"\good.txt"),
        ]
        stats = engine.ScanStats()
        listings = {os.path.normcase(os.path.abspath(base)): FakeScandir(entries), }
        sub = os.path.normcase(os.path.abspath(base + r"\subdir"))

        def scandir(path):
            return listings.get(os.path.normcase(os.path.abspath(path))) or FakeScandir([])
        with mock.patch.object(engine.os, "scandir", side_effect=scandir):
            got = list(engine.iter_files([base], exclude=[sub], stats=stats))     # the sub directory is excluded
        self.assertEqual([os.path.basename(p) for p, _, _ in got], ["good.txt"])
        self.assertEqual((stats.skipped, stats.errors), (2, 1))

    def test_subdirectories_are_walked(self):
        base = str(self.d)
        entries = [FakeEntry(base + r"\subdir", is_dir=True, is_file=False)]
        inner = [FakeEntry(base + r"\subdir\x.txt")]
        by_dir = {os.path.normcase(os.path.abspath(base)): entries,
                  os.path.normcase(os.path.abspath(base + r"\subdir")): inner}
        with mock.patch.object(engine.os, "scandir", side_effect=lambda p: FakeScandir(by_dir[os.path.normcase(os.path.abspath(p))])):
            got = [os.path.basename(p) for p, _, _ in engine.iter_files([base])]
        self.assertEqual(got, ["x.txt"])


class PlanTests(unittest.TestCase):
    def test_fixed_drives_on_other_platforms(self):
        with mock.patch.object(engine, "IS_WIN", False):
            self.assertEqual(engine.fixed_drives(), ["/"])

    def test_only_fixed_drives_are_listed(self):
        k32 = SimpleNamespace(GetLogicalDrives=lambda: 0b1101,                         # A:, C:, D:
                              GetDriveTypeW=lambda root: {"A:\\": 2, "C:\\": 3, "D:\\": 5}[root.value])
        with mock.patch.object(engine, "IS_WIN", True),                 mock.patch.object(ctypes, "windll", SimpleNamespace(kernel32=k32), create=True):
            self.assertEqual(engine.fixed_drives(), ["C:\\"])

    def test_priority_locations_skip_missing_and_duplicate_folders(self):
        d = tempfile.mkdtemp()
        self.addCleanup(shutil.rmtree, d, True)
        env = {"APPDATA": d, "LOCALAPPDATA": d, "TEMP": os.path.join(d, "missing")}
        with mock.patch.dict(os.environ, env):
            got = engine.priority_locations()
        self.assertEqual(sum(os.path.normcase(p) == os.path.normcase(d) for p in got), 1)
        self.assertNotIn(os.path.join(d, "missing"), got)

    def test_default_excludes_without_systemroot(self):
        with mock.patch.dict(os.environ, {}, clear=False):
            os.environ.pop("SystemRoot", None)
            self.assertEqual(engine.default_excludes(), [str(config.DATA_DIR)])
        self.assertGreaterEqual(len(engine.default_excludes()), 1)

    def test_env_path(self):
        with mock.patch.dict(os.environ, {"XS_TEST_VAR": "base"}):
            self.assertEqual(engine._env_path("XS_TEST_VAR", "a", "b"), os.path.join("base", "a", "b"))
        self.assertIsNone(engine._env_path("XS_DEFINITELY_UNSET"))


class FingerprintTests(unittest.TestCase):
    def test_changes_with_allowlist_and_survives_a_packaged_build(self):
        a = engine.rules_fingerprint()
        self.assertEqual(a, engine.rules_fingerprint())
        with mock.patch.object(Path, "read_bytes", side_effect=OSError("no .py files in a frozen build")):
            frozen = engine.rules_fingerprint()
        self.assertNotEqual(a, frozen)


class ScanCacheTests(unittest.TestCase):
    def setUp(self):
        self.d = Path(tempfile.mkdtemp())
        self.addCleanup(shutil.rmtree, self.d, True)
        self.cache = engine.ScanCache(self.d / "c.sqlite", fingerprint="fp")
        self.addCleanup(self.cache.db.close)

    def test_round_trip_and_invalidation(self):
        r = ScanResult("C:/a.exe", Verdict.SUSPICIOUS, 40, "h", ["why"])
        self.cache.put(r, 10, 99)
        self.cache.flush()
        hit = self.cache.get("C:/a.exe", 10, 99)
        self.assertEqual((hit.verdict, hit.score, hit.reasons), (Verdict.SUSPICIOUS, 40, ["why"]))
        self.assertIsNone(self.cache.get("C:/a.exe", 11, 99))                  # size changed
        self.assertIsNone(self.cache.get("C:/a.exe", 10, 100))                 # modified
        self.assertIsNone(self.cache.get("C:/never.exe", 1, 1))
        self.cache.fp = "other"
        self.assertIsNone(self.cache.get("C:/a.exe", 10, 99))                  # rules changed

    def test_old_entries_expire_and_errors_are_not_cached(self):
        self.cache.put(ScanResult("C:/e.exe", Verdict.ERROR), 1, 1)
        self.assertEqual(self.cache._pending, [])
        self.cache.put(ScanResult("C:/old.exe", Verdict.CLEAN), 1, 1)
        self.cache.flush()
        with mock.patch.object(engine.time, "time", return_value=time.time() + config.CACHE_MAX_AGE_SECONDS + 10):
            self.assertIsNone(self.cache.get("C:/old.exe", 1, 1))

    def test_batches_are_flushed_automatically_and_close_flushes_the_rest(self):
        with mock.patch.object(config, "CACHE_FLUSH_EVERY", 2):
            self.cache.put(ScanResult("C:/1", Verdict.CLEAN), 1, 1)
            self.assertEqual(len(self.cache._pending), 1)
            self.cache.put(ScanResult("C:/2", Verdict.CLEAN), 1, 1)
            self.assertEqual(self.cache._pending, [])
        self.cache.put(ScanResult("C:/3", Verdict.CLEAN), 1, 1)
        self.cache.close()
        again = engine.ScanCache(self.d / "c.sqlite", fingerprint="fp")
        self.addCleanup(again.db.close)
        self.assertIsNotNone(again.get("C:/3", 1, 1))


class WorkerTests(unittest.TestCase):
    def test_priority_helpers_and_worker_scanning(self):
        engine._lower_priority()                                               # real call: must not raise
        with mock.patch.object(engine, "_lower_priority") as lower:
            engine._init_worker(False)
            lower.assert_not_called()
        with mock.patch.object(engine, "IS_WIN", False), mock.patch.object(engine.os, "nice", create=True) as nice:
            engine._lower_priority()
            nice.assert_called_once_with(10)
        with mock.patch.object(engine, "IS_WIN", False), \
                mock.patch.object(engine.os, "nice", create=True, side_effect=OSError("not allowed")):
            engine._lower_priority()                                           # logged, never raised
        d = Path(tempfile.mkdtemp())
        self.addCleanup(shutil.rmtree, d, True)
        f = d / "x.txt"
        f.write_text("hi")
        old = engine._worker_scanner
        self.addCleanup(setattr, engine, "_worker_scanner", old)
        with mock.patch.object(engine, "_lower_priority") as lower:
            engine._init_worker(True)
            lower.assert_called_once()
        self.assertEqual(engine._scan_in_worker(str(f)).verdict, Verdict.CLEAN)

    def test_default_workers_leaves_a_core_free(self):
        with mock.patch.object(engine.os, "cpu_count", return_value=None):
            self.assertEqual(engine.default_workers(), 1)
        with mock.patch.object(engine.os, "cpu_count", return_value=64):
            self.assertEqual(engine.default_workers(), config.MAX_SCAN_WORKERS)


class FakePool:
    """Stands in for ProcessPoolExecutor so the parallel loop can be driven deterministically in-process."""
    mode = "ok"
    on_submit = None                 # called on every submit (lets a test cancel at exactly the right moment)

    def __init__(self, max_workers=None, initializer=None, initargs=()):
        pass

    def submit(self, fn, path):
        if FakePool.on_submit:
            FakePool.on_submit()
        if FakePool.mode == "submit_broken":
            raise BrokenProcessPool("dead pool")
        f = Future()
        if FakePool.mode == "hang":
            return f                 # never completes
        if FakePool.mode == "result_broken":
            f.set_exception(BrokenProcessPool("worker died"))
        elif FakePool.mode == "result_error":
            f.set_exception(ValueError("boom"))
        else:
            from sentinel.scanner import Scanner
            f.set_result(Scanner(log=False).scan_file(path))
        return f

    def shutdown(self, wait=True, cancel_futures=False):
        pass


class ScanLoopTests(unittest.TestCase):
    def setUp(self):
        self.d = Path(tempfile.mkdtemp())
        self.addCleanup(shutil.rmtree, self.d, True)
        for i in range(6):
            (self.d / f"f{i}.txt").write_text(f"file {i}")
        self.cache_path = self.d.parent / (self.d.name + ".sqlite")
        self.addCleanup(lambda: [Path(str(self.cache_path) + s).unlink(missing_ok=True) for s in ("", "-wal", "-shm")])
        FakePool.mode, FakePool.on_submit = "ok", None
        patcher = mock.patch.object(engine, "ProcessPoolExecutor", FakePool)
        patcher.start()
        self.addCleanup(patcher.stop)

    def scan(self, **kw):
        eng = engine.ScanEngine(workers=2, use_cache=kw.pop("use_cache", False), **kw)
        return eng, list(eng.scan([self.d], **({"cancel": kw.get("cancel")} if kw.get("cancel") else {})))

    def test_parallel_results_are_collected(self):
        eng, results = self.scan()
        self.assertEqual(len(results), 6)
        self.assertEqual(eng.stats.files, 6)

    def test_cache_hits_are_served_without_the_pool(self):
        engine.ScanEngine(workers=2, cache_path=self.cache_path).scan
        first = engine.ScanEngine(workers=1, cache_path=self.cache_path)
        list(first.scan([self.d]))
        eng = engine.ScanEngine(workers=2, cache_path=self.cache_path)
        list(eng.scan([self.d]))
        self.assertEqual(eng.stats.cached, 6)

    def test_a_dead_pool_at_submit_falls_back_to_this_process(self):
        FakePool.mode = "submit_broken"
        eng, results = self.scan()
        self.assertEqual(len(results), 6)
        self.assertEqual(eng.stats.errors, 0)

    def test_a_worker_dying_mid_scan_falls_back_to_this_process(self):
        FakePool.mode = "result_broken"
        eng, results = self.scan()
        self.assertEqual({r.verdict for r in results}, {Verdict.CLEAN})
        self.assertEqual(len(results), 6)

    def test_a_worker_exception_becomes_an_error_result_not_a_lost_file(self):
        FakePool.mode = "result_error"
        eng, results = self.scan()
        self.assertEqual({r.verdict for r in results}, {Verdict.ERROR})
        self.assertEqual(eng.stats.errors, 6)
        self.assertIn("Scan failed: boom", results[0].reasons[0])

    def test_cancelling_midway_stops_early(self):
        ev = threading.Event()
        for i in range(60):
            (self.d / f"more{i}.txt").write_text(str(i))
        eng = engine.ScanEngine(workers=2, use_cache=False)
        seen = 0
        for _ in eng.scan([self.d], cancel=ev):
            seen += 1
            ev.set()
        self.assertLess(seen, 66)

    def test_cancelling_with_work_still_in_flight_cancels_the_futures(self):
        ev = threading.Event()
        FakePool.mode, FakePool.on_submit = "hang", ev.set
        eng = engine.ScanEngine(workers=2, use_cache=False)
        self.assertEqual(list(eng.scan([self.d], cancel=ev)), [])

    def test_serial_mode_cancel_and_threat_logging(self):
        (self.d / "bad.ps1").write_text("vssadmin delete shadows /all\nSet-MpPreference -DisableRealtimeMonitoring $true")
        eng = engine.ScanEngine(workers=1, use_cache=False)
        list(eng.scan([self.d]))
        self.assertEqual(eng.stats.threats, 1)
        ev = threading.Event()
        count = 0
        for _ in eng.scan([self.d], cancel=ev):
            count += 1
            ev.set()
        self.assertEqual(count, 1)


if __name__ == "__main__":
    unittest.main()
