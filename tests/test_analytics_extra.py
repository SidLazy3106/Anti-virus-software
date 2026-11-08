"""Performance analytics: consent, storage, measuring with a fake system, comparison and the honesty notes."""
import threading
import unittest
from types import SimpleNamespace
from unittest import mock

from sentinel import analytics, config


class FakePsutil:
    def __init__(self, disk=True):
        self.n = 0
        self.disk = disk

    def cpu_percent(self, interval=None):
        self.n += 1
        return 10.0 + self.n

    def virtual_memory(self):
        return SimpleNamespace(percent=50.0)

    def pids(self):
        return [1, 2, 3]

    def disk_io_counters(self):
        if not self.disk:
            return None
        self.n += 1
        return SimpleNamespace(read_bytes=self.n * 1048576, write_bytes=0)


class StorageTests(unittest.TestCase):
    def setUp(self):
        config.ensure_dirs()
        self.path = analytics._path()
        self.backup = self.path.read_bytes() if self.path.exists() else None

        def restore():
            if self.backup is None:
                self.path.unlink(missing_ok=True)
            else:
                self.path.write_bytes(self.backup)
        self.addCleanup(restore)
        self.path.unlink(missing_ok=True)

    def test_defaults_consent_and_clearing(self):
        self.assertFalse(analytics.has_consent())
        analytics.set_consent(True)
        self.assertTrue(analytics.has_consent())
        analytics._save({"consent": True, "sessions": [{"id": "1"}]})
        self.assertEqual(analytics.sessions(), [{"id": "1"}])
        analytics.clear_sessions()
        self.assertEqual(analytics.sessions(), [])
        self.assertTrue(analytics.has_consent())                       # clearing data keeps the choice

    def test_damaged_or_unexpected_files_fall_back_to_defaults(self):
        self.path.write_text("[1, 2]")                                  # valid JSON, wrong shape
        self.assertEqual(analytics._load(), {"consent": False, "sessions": []})
        self.path.write_text("{broken")
        self.assertEqual(analytics._load(), {"consent": False, "sessions": []})


class MeasureTests(unittest.TestCase):
    def setUp(self):
        self.path = analytics._path()
        self.backup = self.path.read_bytes() if self.path.exists() else None

        def restore():
            if self.backup is None:
                self.path.unlink(missing_ok=True)
            else:
                self.path.write_bytes(self.backup)
        self.addCleanup(restore)
        self.path.unlink(missing_ok=True)
        self.live = {"on_ac": True, "battery_pct": 80, "ram_available": 1}
        for target, value in (("psutil", FakePsutil()), ):
            patcher = mock.patch.object(analytics, target, value)
            patcher.start()
            self.addCleanup(patcher.stop)
        patcher = mock.patch.object(analytics.hardware, "live_status", side_effect=lambda: dict(self.live))
        patcher.start()
        self.addCleanup(patcher.stop)

    class NeverCancelled(threading.Event):
        def wait(self, timeout=None):
            return False

    def test_without_psutil_nothing_is_measured(self):
        with mock.patch.object(analytics, "psutil", None):
            self.assertIsNone(analytics.measure("x", None, seconds=1))

    def test_full_session_is_stored_with_stats_and_plan(self):
        seen = []
        import sentinel.optimizer as opt
        with mock.patch.object(opt, "active_plan", return_value=("guid", "Balanced")):
            sess = analytics.measure("baseline", None, seconds=3, cancel=self.NeverCancelled(),
                                     on_sample=lambda i, n, c, r: seen.append((i, n)))
        self.assertEqual(seen, [(1, 3), (2, 3), (3, 3)])
        self.assertEqual(sess["metrics"]["cpu_avg"]["n"], 3)
        self.assertEqual(sess["metrics"]["procs"]["mean"], 3)
        self.assertEqual(sess["conditions"], {"on_ac": True, "battery_pct": 80, "power_plan": "Balanced"})
        self.assertIsNotNone(sess["metrics"]["disk"])
        self.assertEqual(analytics.sessions()[-1]["id"], sess["id"])

    def test_missing_disk_counters_and_unreadable_power_plan(self):
        analytics.psutil.disk = False
        import sentinel.optimizer as opt
        with mock.patch.object(opt, "active_plan", side_effect=OSError("powercfg missing")):
            sess = analytics.measure("custom", "gaming", seconds=2, cancel=self.NeverCancelled())
        self.assertIsNone(sess["metrics"]["disk"])
        self.assertEqual(sess["conditions"]["power_plan"], "")
        self.assertEqual(sess["profile"], "gaming")

    def test_cancelled_early_returns_nothing_and_stores_nothing(self):
        ev = threading.Event()
        ev.set()
        self.assertIsNone(analytics.measure("x", None, seconds=30, cancel=ev))
        self.assertEqual(analytics.sessions(), [])

    def test_only_the_latest_200_sessions_are_kept(self):
        analytics._save({"consent": True, "sessions": [{"id": str(i)} for i in range(250)]})
        analytics.measure("x", None, seconds=1, cancel=self.NeverCancelled())
        self.assertEqual(len(analytics.sessions()), 200)

    def test_timer_latency_is_non_negative(self):
        self.assertGreaterEqual(analytics.timer_latency_ms(), 0.0)


class ComparisonTests(unittest.TestCase):
    def sess(self, hw, label, profile, mean, duration=30, n=30):
        return {"hw_id": hw, "label": label, "profile": profile, "duration": duration,
                "metrics": {"cpu_avg": {"mean": mean, "n": n}}}

    def test_runs_are_grouped_per_series_and_only_for_this_hardware(self):
        hid = analytics.hardware_id()
        runs = [self.sess(hid, "baseline", None, 20), self.sess(hid, "baseline", None, 30),
                self.sess(hid, "mode", "gaming", 15), self.sess(hid, "mode", None, 40),
                self.sess("other-pc", "baseline", None, 99), {"hw_id": hid, "label": "mode", "metrics": {}}]
        self.assertEqual(len(analytics.comparable(runs)), 5)
        series = analytics.by_series("cpu_avg", runs)
        self.assertEqual(set(series), {"baseline", "gaming", "custom"})
        self.assertEqual(series["baseline"]["mean"], 25)
        self.assertEqual(series["baseline"]["spread"], (20, 30))
        self.assertEqual((series["baseline"]["count"], series["baseline"]["n_total"], series["baseline"]["seconds"]), (2, 60, 60))
        self.assertEqual(analytics.by_series("ram_avg", runs), {})

    def test_stored_sessions_are_used_by_default(self):
        with mock.patch.object(analytics, "sessions", return_value=[]):
            self.assertEqual(analytics.comparable(), [])

    def test_confidence_notes_never_overclaim(self):
        self.assertIn("variability across runs unknown", analytics.confidence_note({"count": 1}))
        self.assertEqual(analytics.confidence_note({"count": 3, "spread": (1.0, 2.55)}), "3 runs, means ranged 1.0-2.5")

    def test_stats_ignore_missing_values_and_there_are_no_invented_benchmarks(self):
        self.assertIsNone(analytics.stats([None]))
        s = analytics.stats([1, None, 3])
        self.assertEqual((s["mean"], s["n"], s["min"], s["max"]), (2, 2, 1, 3))
        self.assertEqual(analytics.stats([5])["std"], 0.0)
        self.assertIsNone(analytics.external_benchmarks("RTX 4060"))


if __name__ == "__main__":
    unittest.main()
