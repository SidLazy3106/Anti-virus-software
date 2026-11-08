"""Tests for HardwareAndScan."""
import tempfile
import unittest
from unittest import mock
from pathlib import Path

from sentinel import config


class HardwareAndScanTests(unittest.TestCase):
    """Note: real scans ask every window for its title; with the GUI tests' Tk window alive and the main thread
    blocked in the scan, that call can wait forever, so those two tests stub the window lookup.
    Hardware cache, hardware-specific recommendations, scan modes, and the analytics honesty rules."""

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

    @mock.patch("sentinel.optimizer.measure._windowed_pids", return_value=set())   # see note in the class docstring
    def test_scan_modes_report_progress_and_never_change_anything(self, _pids):
        events = []
        a = self.opt.scan("quick", progress=lambda e, n, p: events.append((e, n)))
        self.assertFalse(a.cancelled)
        self.assertIn(("done", "Memory and CPU"), events)
        self.assertNotIn("Hardware details", a.completed)               # quick doesn't do the heavy parts
        self.assertTrue(all(r.category in self.opt.CATEGORIES for r in a.recommendations))
        self.assertNotIn("Old temp files", a.completed)

    @mock.patch("sentinel.optimizer.measure._windowed_pids", return_value=set())   # see note in the class docstring
    def test_scan_can_be_cancelled_and_duplicates_are_refused(self, _pids):
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
        from sentinel.optimizer import power  # collaborators are looked up on their module, so patch them there
        opt = self.opt
        plan = {"g": (opt.PLAN_BALANCED, "Balanced")}
        real = (power.active_plan, power.set_active_plan, power.list_power_plans)
        power.active_plan = lambda: plan["g"]
        power.list_power_plans = lambda: [(opt.PLAN_BALANCED, "Balanced", False), (opt.PLAN_HIGH, "High", False)]

        def setter(guid):
            plan["g"] = (guid, "x")
            return opt.ApplyResult(True, "ok")
        power.set_active_plan = setter
        hist = opt.History(Path(tempfile.mkdtemp()) / "h.json")
        try:
            self.assertTrue(opt.apply_profile("gaming", hist).ok)
            self.assertEqual(opt.get_state()["original_plan"]["guid"], opt.PLAN_BALANCED)
            n = len(hist.pending())
            self.assertTrue(opt.apply_profile("gaming", hist).ok)       # already active: no duplicate change
            self.assertEqual(len(hist.pending()), n)
            opt.apply_profile("balanced", hist)
            self.assertEqual(opt.get_state()["original_plan"]["guid"], opt.PLAN_BALANCED)   # not overwritten
            power.set_active_plan = lambda guid: opt.ApplyResult(False, "Windows did not accept the change.")
            before = len(hist.pending())
            self.assertFalse(opt.apply_profile("gaming", hist).ok)      # failure: nothing recorded as applied
            self.assertEqual(len(hist.pending()), before)
        finally:
            power.active_plan, power.set_active_plan, power.list_power_plans = real

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
