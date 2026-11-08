"""Tests for ProcessWatcher, Monitor."""
import unittest


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
