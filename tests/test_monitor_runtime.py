"""Tests for real-time protection: alerts, ransomware guard, watcher handler, scan loop and process inspection."""
import shutil
import tempfile
import unittest
from pathlib import Path
from types import SimpleNamespace
from unittest import mock

from sentinel import config, monitor
from sentinel.result import ScanResult
from sentinel.verdict import Verdict


class AlertTests(unittest.TestCase):
    def test_text_form_and_timestamp(self):
        a = monitor.Alert("file", "high", "bad.exe found", "details", time=0.0)
        self.assertGreater(a.time, 0)                       # filled in when not given
        self.assertIn("HIGH", str(a))
        self.assertIn("file: bad.exe found", str(a))


class RansomwareGuardTests(unittest.TestCase):
    def setUp(self):
        self.d = Path(tempfile.mkdtemp())
        self.addCleanup(shutil.rmtree, self.d, True)
        self.alerts = []
        self.guard = monitor.RansomwareGuard(self.alerts.append)

    def test_canaries_are_created_hidden_recreated_and_removed(self):
        legacy = self.d / config.LEGACY_CANARY_NAMES[0]
        legacy.write_text("old decoy")
        self.guard.create_canaries([self.d])
        self.assertFalse(legacy.exists())                                      # pre-rename decoy cleaned up
        names = {Path(c).name for c in self.guard.canaries}
        self.assertEqual(names, set(config.CANARY_NAMES))
        self.guard.create_canaries([self.d])                                   # existing (hidden) files are rewritten
        self.assertEqual(len(self.guard.canaries), 2)
        self.guard.remove_canaries()
        self.assertEqual(self.guard.canaries, set())
        self.assertFalse(any((self.d / n).exists() for n in config.CANARY_NAMES))

    def test_canaries_on_a_non_windows_platform_skip_the_attribute_calls(self):
        with mock.patch.object(monitor, "IS_WIN", False):
            self.guard.create_canaries([self.d])
        self.assertEqual(len(self.guard.canaries), 2)

    def test_unwritable_folder_and_vanished_canary_are_tolerated(self):
        self.guard.create_canaries([self.d / "does-not-exist"])
        self.assertEqual(self.guard.canaries, set())
        self.guard.canaries.add(str(self.d / "gone.docx"))
        self.guard.remove_canaries()                                           # missing file: no error

    def test_legacy_decoy_that_cannot_be_deleted_is_ignored(self):
        with mock.patch.object(Path, "unlink", side_effect=OSError("locked")):
            self.guard.create_canaries([self.d])
        self.assertEqual(len(self.guard.canaries), 2)

    def test_touching_a_canary_is_critical(self):
        self.guard.create_canaries([self.d])
        canary = self.d / config.CANARY_NAMES[0]
        self.guard.event(str(canary), "modified")
        self.guard.event(str(canary), "deleted")
        self.assertEqual([a.severity for a in self.alerts], ["critical", "critical"])
        self.assertIn("Canary file modified", self.alerts[0].message)

    def test_high_change_rate_warns_once_per_cooldown(self):
        guard = monitor.RansomwareGuard(self.alerts.append, window=5.0, limit=3)
        # every event reads the clock once; the alert-building Alert() reads it too
        with mock.patch.object(monitor.time, "time", return_value=100.0):
            for _ in range(4):
                guard.event(r"C:\data\a.txt", "modified")
        warnings = [a for a in self.alerts if a.severity == "warning"]
        self.assertEqual(len(warnings), 1)                                     # 3rd event alerts, 4th is in cooldown
        self.assertIn("unusual rate", warnings[0].message)

    def test_old_events_leave_the_window_and_other_kinds_are_ignored(self):
        guard = monitor.RansomwareGuard(self.alerts.append, window=5.0, limit=2)
        with mock.patch.object(monitor.time, "time", side_effect=[1.0, 100.0]):
            guard.event("a.txt", "modified")
            guard.event("b.txt", "modified")                # the first event is long outside the window
        guard.event("c.txt", "created")
        self.assertEqual(self.alerts, [])
        self.assertEqual(len(guard.events), 1)


class HandlerTests(unittest.TestCase):
    def test_file_events_are_forwarded_and_directories_ignored(self):
        mon = mock.MagicMock()
        h = monitor._Handler(mon)
        f = SimpleNamespace(is_directory=False, src_path="a", dest_path="b")
        d = SimpleNamespace(is_directory=True, src_path="dir", dest_path="dir2")
        for ev in (f, d):
            h.on_created(ev)
            h.on_modified(ev)
            h.on_moved(ev)
            h.on_deleted(ev)
        mon.enqueue.assert_has_calls([mock.call("a", "created"), mock.call("a", "modified"), mock.call("b", "created")])
        self.assertEqual(mon.enqueue.call_count, 3)
        mon.guard.event.assert_has_calls([mock.call("a", "moved"), mock.call("a", "deleted")])
        self.assertEqual(mon.guard.event.call_count, 2)


class RealtimeMonitorTests(unittest.TestCase):
    def setUp(self):
        self.d = Path(tempfile.mkdtemp())
        self.addCleanup(shutil.rmtree, self.d, True)
        self.alerts = []
        self.scanner = mock.MagicMock()

    def make(self, **kw):
        return monitor.RealtimeMonitor(self.scanner, [self.d], self.alerts.append, **kw)

    def test_enqueue_skips_canaries_and_partial_downloads(self):
        mon = self.make(canaries=True)
        mon.guard.create_canaries([self.d])
        mon.enqueue(str(self.d / config.CANARY_NAMES[0]), "modified")
        mon.enqueue(str(self.d / "movie.crdownload"), "created")
        mon.enqueue(str(self.d / "real.exe"), "created")
        self.assertEqual(mon._q.qsize(), 1)
        mon.guard.remove_canaries()

    def test_start_requires_watchdog_and_stop_cleans_up(self):
        with mock.patch.object(monitor, "Observer", None):
            with self.assertRaises(RuntimeError):
                self.make().start()
        obs = mock.MagicMock()
        mon = self.make(canaries=True)
        with mock.patch.object(monitor, "Observer", return_value=obs):
            mon.start()
            obs.schedule.assert_called_once()
            obs.start.assert_called_once()
            self.assertTrue(mon.guard.canaries)
            mon.stop()
        obs.stop.assert_called_once()
        self.assertFalse(mon.guard.canaries)
        self.make().stop()                                  # stopping a never-started monitor is harmless
        with mock.patch.object(monitor, "Observer", return_value=mock.MagicMock()):
            plain = self.make()                             # no canaries requested: none are created
            plain.start()
            self.assertEqual(plain.guard.canaries, set())
            plain.stop()

    def test_wait_stable(self):
        f = self.d / "f.bin"
        f.write_bytes(b"x")
        with mock.patch.object(monitor.time, "sleep"):
            self.assertTrue(self.make()._wait_stable(str(f)))
            self.assertFalse(self.make()._wait_stable(str(self.d / "missing")))
            sizes = iter(range(100))
            with mock.patch.object(monitor.os.path, "getsize", side_effect=lambda p: next(sizes)):
                self.assertFalse(self.make()._wait_stable(str(f), tries=3))          # keeps growing

    def _drive(self, mon, paths, results):
        """Run the worker loop over `paths` (files are 'stable'), stopping when the queue is empty."""
        for p in paths:
            mon._q.put(str(p))
        it = iter(results)
        real_get = mon._q.get

        def get(timeout=None):
            item = real_get(timeout=timeout)
            if mon._q.empty():
                mon._stop.set()                      # last item handed out: the loop ends after processing it
            return item
        mon._q.get = get
        self.scanner.scan_file.side_effect = lambda path: next(it)
        with mock.patch.object(mon, "_wait_stable", return_value=True):
            mon._run()

    def test_worker_alerts_on_flagged_files_and_skips_vanished_ones(self):
        bad, odd, same = self.d / "bad.exe", self.d / "odd.js", self.d / "same.txt"
        for f in (bad, odd, same):
            f.write_text("x")
        res = [ScanResult(str(bad), Verdict.MALICIOUS, 90, "h", ["r1"]),
               ScanResult(str(odd), Verdict.SUSPICIOUS, 40, "h", ["r2"]), ScanResult(str(same), Verdict.CLEAN)]
        mon = self.make()
        self._drive(mon, [bad, odd, self.d / "missing.bin", same], res)
        self.assertEqual([a.severity for a in self.alerts], ["high", "warning"])

    def test_unchanged_file_is_not_rescanned(self):
        f = self.d / "same.txt"
        f.write_text("x")
        mon = self.make()
        mon._seen[str(f)] = (f.stat().st_mtime_ns, f.stat().st_size)
        self._drive(mon, [f], [])
        self.scanner.scan_file.assert_not_called()

    def test_unstable_files_are_skipped_and_an_idle_queue_keeps_waiting(self):
        mon = self.make()
        mon._q.put(str(self.d / "growing.bin"))
        calls = {"n": 0}
        real_get = mon._q.get

        def get(timeout=None):
            calls["n"] += 1
            if calls["n"] > 2:
                mon._stop.set()
            return real_get(timeout=0.01)                    # 1st call: item; later calls: queue.Empty
        mon._q.get = get
        with mock.patch.object(mon, "_wait_stable", return_value=False):
            mon._run()
        self.scanner.scan_file.assert_not_called()

    def test_auto_quarantine_success_and_failure(self):
        bad = self.d / "bad.exe"
        bad.write_text("x")
        res = ScanResult(str(bad), Verdict.MALICIOUS, 90, "h", ["r"])
        for error, expected in ((None, "(quarantined)"), (OSError("busy"), "quarantine failed: busy")):
            self.alerts.clear()
            mon = self.make(auto_quarantine=True)
            with mock.patch.object(monitor.quarantine, "quarantine_file", side_effect=error):
                self._drive(mon, [bad], [res])
            self.assertIn(expected, self.alerts[0].message)


class FakeProc:
    def __init__(self, name, ppid=1, exe="", cmdline=None, pid=10):
        self.pid = pid
        self.info = {"pid": pid, "name": name, "ppid": ppid, "exe": exe, "cmdline": cmdline or [], "create_time": 1.0}


class ProcessInspectionTests(unittest.TestCase):
    def setUp(self):
        self.alerts = []
        self.scanner = mock.MagicMock()
        self.w = monitor.ProcessWatcher(self.alerts.append, scanner=self.scanner)
        self.psutil = mock.MagicMock()
        self.psutil.Error = Exception
        patcher = mock.patch.object(monitor, "psutil", self.psutil)
        patcher.start()
        self.addCleanup(patcher.stop)

    def parent(self, name):
        self.psutil.Process.return_value.name.return_value = name

    def test_start_needs_psutil_then_stop_sets_the_flag(self):
        with mock.patch.object(monitor, "psutil", None):
            with self.assertRaises(RuntimeError):
                monitor.ProcessWatcher(lambda a: None).start()
        self.psutil.process_iter.return_value = []
        with mock.patch.object(monitor.threading, "Thread") as thread:
            self.w.start()
            thread.return_value.start.assert_called_once()
        self.w.stop()
        self.assertTrue(self.w._stop.is_set())

    def test_run_survives_a_process_that_cannot_be_inspected(self):
        self.psutil.process_iter.return_value = [FakeProc("x.exe")]
        self.w._inspect = mock.MagicMock(side_effect=OSError("denied"))

        class OneLoop:
            n = 0

            def wait(self, _t):
                OneLoop.n += 1
                return OneLoop.n > 1
        self.w._stop = OneLoop()
        self.w._run()
        self.assertIn((10, 1.0), self.w._known)

    def test_office_spawning_a_shell_is_flagged(self):
        self.parent("WINWORD.EXE")
        self.w._inspect(FakeProc("powershell.exe", cmdline=["powershell", "-w", "hidden"]))
        self.assertEqual(self.alerts[0].severity, "high")
        self.assertIn("common malware chain", self.alerts[0].message)

    def test_encoded_powershell_is_flagged(self):
        self.parent("explorer.exe")
        self.w._inspect(FakeProc("pwsh.exe", cmdline=["pwsh", "-enc", "A" * 40]))
        self.assertTrue(any("encoded command" in a.message for a in self.alerts))

    def test_process_without_a_parent_or_name_is_handled(self):
        self.w._inspect(FakeProc(None, ppid=0))
        self.assertEqual(self.alerts, [])

    def test_program_from_a_risky_folder_is_scanned_once(self):
        d = Path(tempfile.mkdtemp())
        self.addCleanup(shutil.rmtree, d, True)
        risky = d / "Downloads"
        risky.mkdir()
        exe = risky / "tool.exe"
        exe.write_text("x")
        self.parent("explorer.exe")
        for verdict, severity in ((Verdict.MALICIOUS, "high"), (Verdict.SUSPICIOUS, "warning"), (Verdict.CLEAN, None)):
            self.alerts.clear()
            self.w._scanned.clear()
            self.scanner.scan_file.return_value = ScanResult(str(exe), verdict, 50, "h", ["why"])
            self.w._inspect(FakeProc("tool.exe", exe=str(exe)))
            self.assertEqual([a.severity for a in self.alerts], ["info"] + ([severity] if severity else []))
        self.scanner.scan_file.reset_mock()
        self.w._inspect(FakeProc("tool.exe", exe=str(exe)))                           # same exe again: not rescanned
        self.assertEqual(self.scanner.scan_file.call_count, 0)

    def test_without_a_scanner_only_the_info_alert_is_raised(self):
        w = monitor.ProcessWatcher(self.alerts.append)
        self.parent("explorer.exe")
        w._inspect(FakeProc("a.exe", exe=r"c:\users\x\downloads\a.exe"))
        self.assertEqual([a.severity for a in self.alerts], ["info"])

    def test_stem_helper(self):
        self.assertEqual((monitor._stem("PowerShell.EXE"), monitor._stem(None), monitor._stem("tool")),
                         ("powershell", "", "tool"))


if __name__ == "__main__":
    unittest.main()
