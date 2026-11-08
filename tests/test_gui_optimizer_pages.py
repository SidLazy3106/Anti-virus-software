"""The PC optimizer and Performance Analytics pages of the real window, with the system measurements, power-plan
changes and registry switches replaced by fakes so nothing on this PC is ever modified."""
import time
import tkinter as tk
import unittest
from types import SimpleNamespace
from unittest import mock

from sentinel import analytics, hardware, optimizer, ui_kit as ui
from sentinel.optimizer.models import Analysis, ApplyResult, Recommendation, Snapshot, StartupItem
from tests.gui_support import AppTestCase


def rec(key="startup:hkcu_run:App", kind="startup", category="Startup Applications", risk="low", actionable=True,
        target=None, **kw):
    base = dict(key=key, kind=kind, title="Startup: App", uses="Running now", benefit="Faster start", risk=risk,
                action="Stop it starting", actionable=actionable, target=target or {"source": "hkcu_run", "name": "App"},
                category=category, issue="Starts at sign-in", why="Slows sign-in", component="Startup entry",
                side_effects="None", restore="Restore re-enables it", original="Enabled")
    base.update(kw)
    return Recommendation(**base)


def analysis(recs=(), **kw):
    snap = Snapshot(cpu=10, ram_total=16 << 30, ram_used=8 << 30, ram_pct=50, process_count=200, power_plan="Balanced")
    item = StartupItem("App", "app.exe", "hkcu_run", True, False, True)
    base = dict(snapshot=snap, startup=[item], groups=[], temp_files=0, temp_bytes=0, recommendations=list(recs),
                protected_startup=2, kind="standard", duration=3.2)
    base.update(kw)
    return Analysis(**base)


def find_buttons(widget, text):
    found = []
    for child in widget.winfo_children():
        if isinstance(child, ui.Btn) and child.text == text:
            found.append(child)
        found += find_buttons(child, text)
    return found


PROFILE = {"cpu": {"name": "Ryzen 7", "cores": 8, "threads": 16, "max_mhz": 4500},
           "gpus": [{"name": "RTX 4060", "vram": 8 << 30, "vram_approx": True, "refresh_hz": 144}, {"name": "iGPU"}],
           "ram": {"total": 16 << 30, "modules": 2, "speed_mhz": 3200},
           "disks": [{"name": "NVMe", "type": "SSD", "size": 512 << 30}, {"size": None}],
           "os": "Windows 11", "form_factor": "laptop", "from_cache": True, "changed": False}


class OptimizerLayoutTests(AppTestCase):
    def setUp(self):
        self.app.hw_loaded = self.app.hw_loading = False
        self.app._opt_tick_on = False

    def test_load_colours(self):
        a = self.app
        self.assertEqual([a._load_color(x) for x in (10, 70, 95)],
                         [ui.T["success"], ui.T["warning"], ui.T["danger"]])

    def test_entering_the_page_loads_hardware_and_starts_the_live_gauges(self):
        a = self.app
        with mock.patch.object(hardware, "get_profile", return_value=PROFILE), \
                mock.patch.object(optimizer, "available_plans", return_value=[]), \
                mock.patch.object(optimizer, "current_profile", return_value=None):
            a._show_page("optimizer")
            self.assertTrue(self.settle(lambda: a.hw_loaded))
            self.assertIn("Ryzen 7", a.hw_vals["cpu"].cget("text"))
            self.assertTrue(a._opt_tick_on)
            a._opt_enter()                                                      # already loaded, tick already on
            a._show_page("home")
            self.assertTrue(self.settle(lambda: not a._opt_tick_on, timeout=5))

    def test_without_psutil_the_page_says_so(self):
        a = self.app
        with mock.patch.object(optimizer, "psutil", None), mock.patch.object(a.toast, "show") as toast:
            a._opt_enter()
            a._opt_live()
        self.assertIn("Install psutil", toast.call_args[0][0])

    def test_live_gauges_survive_an_unreadable_disk(self):
        a = self.app
        fake = SimpleNamespace(cpu_percent=lambda x: 90.0, virtual_memory=lambda: SimpleNamespace(percent=30.0),
                               disk_usage=mock.Mock(side_effect=OSError("no disk")))
        with mock.patch.object(optimizer, "psutil", fake):
            a._opt_live()
        fake.disk_usage = lambda p: SimpleNamespace(percent=50.0)
        with mock.patch.object(optimizer, "psutil", fake):
            a._opt_live()

    def test_hardware_panel_variants(self):
        a = self.app
        with mock.patch.object(hardware, "live_status", return_value={"ram_available": 4 << 30, "battery_pct": 55, "on_ac": False}):
            a._show_hardware(PROFILE)
        self.assertIn("8 cores / 16 threads, up to 4.5 GHz", a.hw_vals["cpu"].cget("text"))
        self.assertIn("RTX 4060 (8.0 GB+)", a.hw_vals["gpu"].cget("text"))
        self.assertIn("2 module(s), 3200 MHz", a.hw_vals["ram"].cget("text"))
        self.assertIn("battery 55% (on battery)", a.hw_vals["misc"].cget("text"))
        self.assertIn("Refresh rate: 144 Hz", a.hw_vals["misc"].cget("text"))
        self.assertIn("saved profile", a.hw_note.cget("text"))
        bare = {"cpu": {}, "gpus": [], "ram": {}, "disks": [], "form_factor": None, "changed": True}
        with mock.patch.object(hardware, "live_status", return_value={"ram_available": None, "battery_pct": 80, "on_ac": True}):
            a._show_hardware(bare)
        self.assertEqual(a.hw_vals["cpu"].cget("text"), "Not available")
        self.assertIn("plugged in", a.hw_vals["misc"].cget("text"))
        self.assertIn("hardware change detected", a.hw_note.cget("text"))
        with mock.patch.object(hardware, "live_status", return_value={"ram_available": None, "battery_pct": None, "on_ac": None}):
            a._show_hardware({"cpu": {"name": "X", "cores": 2}, "ram": {"total": 1 << 30}})
        self.assertIn("2 cores / ? threads", a.hw_vals["cpu"].cget("text"))
        self.assertIn("no battery", a.hw_vals["misc"].cget("text"))

    def test_history_summary(self):
        a = self.app
        a.opt_history.add("x", "Changed a thing", {}, {}, {})
        a._opt_report_default()
        self.assertIn("can be restored", a.opt_report.cget("text"))
        self.assertIn("Changed a thing", a.opt_hist_lbl.cget("text"))
        for entry in a.opt_history.pending():
            a.opt_history.mark_restored(entry["id"])
        a._opt_report_default()
        self.assertIn("(restored)", a.opt_hist_lbl.cget("text"))

    def test_buttons_move_to_a_second_row_when_the_window_is_narrow(self):
        a = self.app
        a._show_page("optimizer")
        a.update()
        btns = a.btn_opt_cancel.master                                         # the frame that owns the button row
        with mock.patch.object(btns, "winfo_width", return_value=80):
            btns.event_generate("<Configure>")
            a.update()
            btns.event_generate("<Configure>")                                  # already moved: nothing to do
            a.update()
        btns.event_generate("<Configure>")                                      # wide again: back to one row
        a.update()
        a._show_page("home")


class RecommendationsTests(AppTestCase):
    def setUp(self):
        a = self.app
        a.opt_busy = False
        a.opt_analysis = None
        a.opt_sig = {c: None for c in a.opt_sig}
        a._show_page("optimizer")
        optimizer._save_state({})
        FakeScan.calls.clear()

    def test_scan_guards(self):
        a = self.app
        with mock.patch.object(a.toast, "show") as toast:
            a.opt_busy = True
            a._opt_scan("quick")
            self.assertIn("already running", toast.call_args[0][0])
            a.opt_busy = False
            with mock.patch.object(optimizer, "psutil", None):
                a._opt_scan("quick")
            self.assertIn("Install psutil", toast.call_args[0][0])

    def run_scan(self, kind="standard", analysis_obj=None, error=None):
        a = self.app
        FakeScan.analysis, FakeScan.error = analysis_obj or analysis([rec()]), error
        with mock.patch.object(optimizer, "scan", FakeScan.scan), mock.patch.object(hardware, "live_status", return_value={}):
            a._opt_scan(kind)
            self.assertTrue(self.settle(lambda: not a.opt_busy))

    def test_a_full_scan_shows_progress_then_the_recommendations(self):
        a = self.app
        self.run_scan("deep", analysis([rec(), rec(key="hw:disk", category="Storage", kind="info", risk="high", actionable=False)],
                                        disk_mb_s=2.5, hardware=PROFILE, kind="deep"))
        self.assertIn("Deep scan complete", a.opt_title.cget("text"))
        self.assertIn("disk 2.5 MB/s", a.opt_sub.cget("text"))
        self.assertIn("2 found", a.opt_count.cget("text"))
        self.assertTrue(a.hw_loaded)
        self.assertEqual(len(a.opt_chips), 1)
        a._opt_scan_tick()

    def test_cancelled_and_clean_results(self):
        a = self.app
        self.run_scan("quick", analysis([], cancelled=True))
        self.assertEqual(a.opt_title.cget("text"), "Scan cancelled")
        self.run_scan("quick", analysis([]))
        self.assertEqual(a.opt_title.cget("text"), "Your PC looks well tuned")

    def test_scan_failures_reach_the_user(self):
        a = self.app
        self.run_scan("quick", error=optimizer.ScanBusy("busy"))
        self.assertIn("already running", a.opt_sub.cget("text"))
        self.run_scan("quick", error=RuntimeError("boom"))
        self.assertIn("RuntimeError: boom", a.opt_sub.cget("text"))
        self.assertFalse(a.opt_busy)

    def test_cancel_and_stale_progress(self):
        a = self.app
        a.opt_busy = True
        a.opt_cancel_ev = __import__("threading").Event()
        a._opt_cancel()
        self.assertTrue(a.opt_cancel_ev.is_set())
        a._opt_progress("done", "Old", None, object())                         # belongs to an earlier scan: ignored
        self.assertNotIn("Old", a.opt_chips)
        a._opt_progress("start", "New", None, a.opt_cancel_ev)
        a._opt_progress("done", "New", None, a.opt_cancel_ev)
        self.assertIn("New", a.opt_chips)
        a.opt_busy = False
        a._opt_cancel()                                                         # nothing running: no effect
        a.opt_chips.clear()

    def test_skipped_and_unknown_categories(self):
        a = self.app
        odd = rec(key="odd", category="")
        skipped = rec(key="skip-me")
        optimizer._save_state({"skipped": ["skip-me"]})
        vis = a._opt_visible(analysis([odd, skipped]))
        self.assertEqual([r.key for r in vis["Hardware-Specific Recommendations"]], ["odd"])
        self.assertNotIn("skip-me", [r.key for v in vis.values() for r in v])

    def test_rendering_cards_and_the_details_toggle(self):
        a = self.app
        a.opt_analysis = analysis([rec(), rec(key="m", category="RAM", kind="memory", risk="medium", actionable=False),
                                   rec(key="h", category="Storage", kind="info", risk="high", actionable=False)])
        a._opt_render(a.opt_analysis, partial=True)
        a._opt_render(a.opt_analysis, partial=False)
        sec = a.opt_sections["Startup Applications"]
        sec.set_open(True)
        self.assertTrue(self.settle(lambda: sec.body.winfo_ismapped(), timeout=5))
        more = find_buttons(sec.body, "Learn more")[0]
        more._invoke()
        self.assertTrue(self.settle(lambda: more.text == "Hide details" and more.master.winfo_ismapped()))
        more._invoke()
        self.assertEqual(more.text, "Learn more")
        self.assertEqual(find_buttons(sec.body, "Apply")[0].text, "Apply")
        self.assertEqual(find_buttons(a.opt_sections["RAM"].body, "Apply"), [])             # manual step: no Apply button
        self.assertIn("3 found", a.opt_count.cget("text"))
        a._opt_render(analysis([]), partial=True)
        a._opt_render(analysis([]), partial=False)

    def test_skip_and_show_skipped_again(self):
        a = self.app
        r = rec()
        a.opt_analysis = analysis([r])
        a._opt_skip(r)
        a._opt_skip(r)                                                           # already skipped: not added twice
        self.assertEqual(optimizer.get_state()["skipped"], [r.key])
        self.assertIn("0 found", a.opt_count.cget("text"))
        a._opt_unskip()
        self.assertIn("1 found", a.opt_count.cget("text"))
        with mock.patch.object(a.toast, "show") as toast:
            a._opt_unskip()
            self.assertIn("Nothing has been skipped", toast.call_args[0][0])
        a.opt_analysis = None
        a._opt_skip(r)
        a._opt_unskip()

    def test_apply_guards_and_profile_recommendations(self):
        a = self.app
        with mock.patch.object(a.toast, "show") as toast:
            a._opt_apply_rec(rec(actionable=False))
            a.opt_analysis = None
            a._opt_apply_rec(rec())
            self.assertEqual(toast.call_count, 2)
        a.opt_analysis = analysis([rec()])
        with mock.patch.object(a, "_activate_profile") as activate:
            a._opt_apply_rec(rec(kind="profile", target={"profile": "balanced"}))
            activate.assert_called_once_with("balanced")
        with mock.patch("sentinel.gui.recommendations.messagebox.askyesno", return_value=False), \
                mock.patch.object(optimizer, "apply_startup_disable") as apply:
            a._opt_apply_rec(rec())
            apply.assert_not_called()

    def apply(self, r, asked=True, **patches):
        a = self.app
        a.opt_analysis = analysis([r])
        a.opt_baseline = Snapshot(cpu=50, ram_total=100, ram_used=80)
        with mock.patch("sentinel.gui.recommendations.messagebox.askyesno", return_value=asked), \
                mock.patch.object(optimizer, "take_snapshot", return_value=Snapshot(cpu=10, ram_total=100, ram_used=20)):
            with mock.patch.multiple(optimizer, **patches):
                a._opt_apply_rec(r)
                self.assertTrue(self.settle(lambda: "Applied" in a.opt_report.cget("text")))

    def test_applying_a_startup_change(self):
        a = self.app
        self.apply(rec(), apply_startup_disable=lambda it, hist: ApplyResult(True, "App will no longer start"))
        text = a.opt_report.cget("text")
        self.assertIn("Applied 1 · Errors 0", text)
        self.assertIn("next sign-in", text)
        self.assertIn("Measured change", text)
        self.apply(rec(key="startup:hkcu_run:Gone", target={"source": "hkcu_run", "name": "Gone"}),
                   apply_startup_disable=lambda it, hist: ApplyResult(True, "x"))
        self.assertIn("no longer exists", a.opt_report.cget("text"))

    def test_applying_a_temp_cleanup(self):
        a = self.app
        r = rec(key="temp", kind="temp", category="Storage", target={})
        self.apply(r, clean_temp=lambda: (3, 3000, 1))
        self.assertIn("Deleted 3 old temp files", a.opt_report.cget("text"))
        self.assertIn("1 in use", a.opt_report.cget("text"))
        a.opt_baseline = None
        a.opt_analysis = None
        a._opt_show_applied({"applied": [], "errors": [("k", "denied")], "compare": ""})
        self.assertIn("Not applied: denied", a.opt_report.cget("text"))

    def test_restoring_previous_settings(self):
        a = self.app
        for entry in a.opt_history.pending():
            a.opt_history.mark_restored(entry["id"])
        with mock.patch.object(a.toast, "show") as toast:
            a._opt_restore()
            self.assertIn("nothing to restore", toast.call_args[0][0])
        a.opt_history.add("x", "Disabled startup item", {}, {}, {})
        with mock.patch("sentinel.gui.recommendations.messagebox.askyesno", return_value=False), \
                mock.patch.object(optimizer, "undo_all") as undo:
            a._opt_restore()
            undo.assert_not_called()
        with mock.patch("sentinel.gui.recommendations.messagebox.askyesno", return_value=True), \
                mock.patch.object(optimizer, "undo_all", return_value=[("a", ApplyResult(True, "ok"))]):
            a._opt_restore()
        self.assertIn("Restored 1 change(s)", a.opt_report.cget("text"))
        with mock.patch("sentinel.gui.recommendations.messagebox.askyesno", return_value=True), \
                mock.patch.object(optimizer, "undo_all", return_value=[("a", ApplyResult(True, "ok")), ("b", ApplyResult(False, "locked"))]):
            a.opt_history.add("x", "Another", {}, {}, {})
            a._opt_restore()
        self.assertIn("could not restore 1", a.opt_report.cget("text"))
        for entry in a.opt_history.pending():
            a.opt_history.mark_restored(entry["id"])


class FakeScan:
    analysis = None
    error = None
    calls = []

    @classmethod
    def scan(cls, kind, progress=None, cancel=None):
        cls.calls.append(kind)
        if progress:
            progress("start", "Memory and CPU", None)
            progress("done", "Memory and CPU", cls.analysis)
        if cls.error:
            raise cls.error
        return cls.analysis


class ModeSwitcherTests(AppTestCase):
    def setUp(self):
        a = self.app
        a._mode = None
        a.reduced_motion = False
        a._show_page("optimizer")
        self.state = {"current": "balanced", "apply": ApplyResult(True, "done")}
        self.plans = [(optimizer.PLAN_BALANCED, "Balanced", True), (optimizer.PLAN_HIGH, "High", False),
                      (optimizer.PLAN_SAVER, "Saver", False)]

        def apply_profile(key, history):
            if self.state["apply"].ok:
                self.state["current"] = key
            return self.state["apply"]
        patches = [mock.patch.object(optimizer, "available_plans", side_effect=lambda: list(self.plans)),
                   mock.patch.object(optimizer, "current_profile", side_effect=lambda: self.state["current"]),
                   mock.patch.object(optimizer, "profile_support", side_effect=self.support),
                   mock.patch.object(optimizer, "active_plan", return_value=(optimizer.PLAN_BALANCED, "Balanced")),
                   mock.patch.object(optimizer, "apply_profile", side_effect=apply_profile),
                   mock.patch.object(hardware, "live_status", return_value={"on_ac": True}),
                   mock.patch.object(type(a), "EXPAND_MS", 40), mock.patch.object(type(a), "GRAPH_MS", 80),
                   mock.patch.object(type(a), "SHRINK_MS", 40)]
        for p in patches:
            p.start()
            self.addCleanup(p.stop)

    def support(self, key, plans=None):
        guids = {g for g, _, _ in (self.plans if plans is None else plans)}
        ok = optimizer.PROFILES[key]["plan"] in guids
        return ok, "" if ok else "This power plan isn't available on this PC."

    def test_refreshing_profile_cards(self):
        a = self.app
        self.plans = [(optimizer.PLAN_BALANCED, "Balanced", True)]               # High and Saver are not available
        a._refresh_profiles()
        self.assertEqual(a.prof_cards["balanced"][1].cget("text"), "Active")
        self.assertEqual(a.prof_cards["gaming"][1].cget("text"), "Not supported on this PC")
        self.plans.append((optimizer.PLAN_HIGH, "High", False))
        a._refresh_profiles()
        self.assertEqual(a.prof_cards["gaming"][1].cget("text"), "Click to activate")
        self.state["current"] = None
        a._refresh_profiles()
        self.assertIn("custom power plan", a.mode_now.cget("text"))
        with mock.patch.object(analytics, "by_series", return_value={"gaming": {"mean": 12.0, "count": 2}}):
            a._refresh_profiles()
        self.assertIn("Measured CPU avg 12% (2 run(s))", a.prof_metric["gaming"].cget("text"))

    def test_activation_guards(self):
        a = self.app
        with mock.patch.object(a.toast, "show") as toast:
            self.plans = []
            a._activate_profile("gaming")
            self.assertIn("isn't available", toast.call_args[0][0])
            self.plans = [(optimizer.PLAN_BALANCED, "Balanced", True), (optimizer.PLAN_HIGH, "High", False)]
            a._mode = {"phase": "busy"}
            a._activate_profile("gaming")                                         # a switch is already in progress
            a._mode = None
            a._activate_profile("balanced")                                       # already the current profile
            self.assertIn("already active", toast.call_args[0][0])
        with mock.patch("sentinel.gui.modes.messagebox.askyesno", return_value=False) as ask, \
                mock.patch.object(a, "_mode_animate") as animate:
            a._activate_profile("gaming")
            ask.assert_called_once()
            animate.assert_not_called()

    def test_battery_warning_is_part_of_the_question(self):
        a = self.app
        with mock.patch.object(hardware, "live_status", return_value={"on_ac": False}), \
                mock.patch("sentinel.gui.modes.messagebox.askyesno", return_value=False) as ask:
            a._activate_profile("gaming")
        self.assertIn("on battery", ask.call_args[0][1])

    def test_plain_switch_without_animation(self):
        a = self.app
        a.reduced_motion = True
        with mock.patch("sentinel.gui.modes.messagebox.askyesno", return_value=True), \
                mock.patch.object(a.toast, "show") as toast:
            a._activate_profile("gaming")
            self.assertTrue(self.settle(lambda: a._mode is None and toast.called))
        self.assertIn("is active", toast.call_args[0][0])
        self.assertEqual(self.state["current"], "gaming")

    def test_plain_switch_that_fails_or_is_not_confirmed(self):
        a = self.app
        a.reduced_motion = True
        self.state["apply"] = ApplyResult(False, "Windows refused")
        with mock.patch("sentinel.gui.modes.messagebox.askyesno", return_value=True), \
                mock.patch.object(a.toast, "show") as toast:
            a._activate_profile("gaming")
            self.assertTrue(self.settle(lambda: a._mode is None and toast.called))
        self.assertIn("Windows refused", toast.call_args[0][0])
        self.state["apply"] = ApplyResult(True, "ok")
        with mock.patch.object(a.toast, "show") as toast:
            a._mode = {"plain": True}
            a._mode_result("gaming", ApplyResult(True, "ok"), False)
            self.assertIn("did not confirm", toast.call_args[0][0])
            a._mode = {"plain": True}
            a._mode_result("gaming", ApplyResult(False, "no"), False)
            self.assertIn("Your previous settings were kept", toast.call_args[0][0])

    def animate(self, key="gaming", cancel_in=None):
        a = self.app
        a.update()
        with mock.patch("sentinel.gui.modes.messagebox.askyesno", return_value=True), \
                mock.patch.object(a.toast, "show") as toast:
            a._activate_profile(key)
            self.assertIsNotNone(a._mode)
            if cancel_in:
                self.assertTrue(self.settle(lambda: a._mode is not None and a._mode["phase"] == cancel_in, timeout=5))
                a._mode_cancel()
            self.assertTrue(self.settle(lambda: a._mode is None, timeout=20))
        return toast

    def test_full_animated_switch(self):
        toast = self.animate("eco")
        self.assertEqual(self.state["current"], "eco")
        self.assertIn("Verified with Windows", toast.call_args[0][0])

    def test_animated_switch_every_profile_without_pillow(self):
        with mock.patch("sentinel.gui.modes.aa.available", return_value=False), mock.patch("sentinel.mode_art.aa.available", return_value=False):
            toast = self.animate("workspace")
        self.assertIn("is active", toast.call_args[0][0])

    def test_failed_animated_switch_keeps_the_card_up_longer_and_reports_failure(self):
        self.state["apply"] = ApplyResult(False, "Windows refused")
        with mock.patch.object(optimizer, "profile_support", return_value=(True, "")):
            toast = self.animate("gaming")
        self.assertIn("Windows refused", toast.call_args[0][0])
        self.assertEqual(self.state["current"], "balanced")

    def test_cancelling_during_the_animation_changes_nothing(self):
        with mock.patch.object(type(self.app), "GRAPH_MS", 4000):                # a graph phase long enough to catch
            toast = self.animate("gaming", cancel_in="graph")
        self.assertIn("Cancelled", toast.call_args[0][0])
        self.assertEqual(self.state["current"], "balanced")

    def test_cancel_by_clicking_the_corner_and_ignored_clicks(self):
        a = self.app
        with mock.patch("sentinel.gui.modes.messagebox.askyesno", return_value=True), mock.patch.object(a.toast, "show"):
            a._activate_profile("gaming")
            m = a._mode
            a._mode_click(SimpleNamespace(x=0, y=500))                            # not in the cancel corner
            self.assertFalse(m["cancel"])
            a._mode_click(SimpleNamespace(x=10000, y=2))                          # top-right corner
            self.assertTrue(m["cancel"])
            self.assertTrue(self.settle(lambda: a._mode is None, timeout=20))
        a._mode_click(SimpleNamespace(x=1, y=1))                                  # no mode active
        a._mode_cancel()
        a._mode_step()

    def test_result_text_without_an_icon_font(self):
        from sentinel.ui_kit import theme
        with mock.patch.object(theme, "ICON_FONT", None):
            toast = self.animate("eco")
        self.assertIn("is active", toast.call_args[0][0])

    def test_drawing_errors_never_leave_the_overlay_stuck(self):
        a = self.app
        with mock.patch.object(type(a), "_mode_draw", side_effect=[tk.TclError("closing"), RuntimeError("bug")] + [None] * 500):
            self.animate("eco")


class AnalyticsPageTests(AppTestCase):
    def setUp(self):
        a = self.app
        analytics._save({"consent": False, "sessions": []})
        a.an_busy = False
        a._show_page("analytics")

    def session(self, hw=None, label="baseline", profile=None, mean=20.0, on_ac=True, key="cpu_avg", t=None):
        std = {"mean": mean, "std": 1.0, "min": mean, "max": mean, "n": 30}
        return {"id": str(t or time.time()), "label": label, "profile": profile, "time": t or time.time(), "duration": 30.0,
                "hw_id": hw or analytics.hardware_id(), "conditions": {"on_ac": on_ac},
                "series": {"cpu": [1.0] * 30}, "metrics": {key: std}}

    def test_entering_shows_consent_and_the_no_benchmark_notice(self):
        a = self.app
        analytics.set_consent(True)
        a._an_enter()
        self.assertIn("Not available", a.an_ext.cget("text"))
        a.hw_profile = {"cpu": {"name": "Ryzen"}}
        a._an_enter()
        self.assertIn("Ryzen", a.an_ext.cget("text"))
        with mock.patch.object(analytics, "external_benchmarks", return_value={"source": "x"}):
            a._an_enter()
        self.assertIn("source", a.an_ext.cget("text"))
        a.hw_profile = None

    def test_consent_and_duration(self):
        a = self.app
        with mock.patch.object(a.toast, "show") as toast:
            a._an_consent(True)
            self.assertTrue(analytics.has_consent())
            a._an_consent(False)
            self.assertIn("Measurements are off", toast.call_args[0][0])
        a.an_secs = 30
        a._an_cycle()
        a._an_cycle()
        a._an_cycle()
        self.assertEqual((a.an_secs, a.btn_an_dur.text), (30, "30 s"))

    def test_measuring_guards(self):
        a = self.app
        with mock.patch.object(a.toast, "show") as toast:
            a._an_measure("baseline")
            self.assertIn("Turn on", toast.call_args[0][0])
            analytics.set_consent(True)
            with mock.patch.object(optimizer, "psutil", None):
                a._an_measure("baseline")
            self.assertIn("Install psutil", toast.call_args[0][0])
            a.an_busy = True
            a._an_measure("baseline")
            a._an_cancel()
            a.an_busy = False
            a._an_cancel()

    def run_measure(self, result, kind="mode", cancel_first=False):
        a = self.app
        analytics.set_consent(True)

        def fake_measure(label, profile, secs, ev, tick):
            tick(1, 2, 12.0, 34.0)
            if cancel_first:
                ev.set()
            return result
        with mock.patch.object(analytics, "measure", side_effect=fake_measure), \
                mock.patch.object(optimizer, "current_profile", return_value="gaming"), \
                mock.patch.object(optimizer, "available_plans", return_value=[]):
            a._an_measure(kind)
            self.assertTrue(self.settle(lambda: not a.an_busy))

    def test_a_finished_measurement_is_summarised(self):
        a = self.app
        sess = self.session(label="mode", profile="gaming")
        self.run_measure(sess)
        self.assertIn("Saved: 30 s, 30 samples", a.an_status.cget("text"))
        self.run_measure(sess, kind="baseline", cancel_first=True)
        self.assertIn("(stopped early)", a.an_status.cget("text"))

    def test_a_too_short_measurement_is_not_saved(self):
        a = self.app
        self.run_measure(None, cancel_first=True)
        self.assertIn("is not saved", a.an_status.cget("text"))

    def test_clearing_measurements(self):
        a = self.app
        with mock.patch.object(a.toast, "show") as toast:
            a._an_clear()
            self.assertIn("No measurements stored", toast.call_args[0][0])
        analytics._save({"consent": True, "sessions": [self.session()]})
        with mock.patch("sentinel.gui.analytics.messagebox.askyesno", return_value=False):
            a._an_clear()
        self.assertEqual(len(analytics.sessions()), 1)
        with mock.patch("sentinel.gui.analytics.messagebox.askyesno", return_value=True), \
                mock.patch.object(optimizer, "available_plans", return_value=[]):
            a._an_clear()
        self.assertEqual(analytics.sessions(), [])

    def test_charts_for_every_metric(self):
        a = self.app
        now = time.time()
        sessions = [self.session(t=now - 100), self.session(label="mode", profile="gaming", mean=35.0, on_ac=False, t=now - 50),
                    self.session(label="mode", profile=None, mean=40.0, t=now - 20),
                    self.session(hw="another-pc", mean=99.0, t=now - 10)]
        analytics._save({"consent": True, "sessions": sessions})
        with mock.patch.object(optimizer, "available_plans", return_value=[]):
            for key, *_ in analytics.METRICS:
                a._an_select(key)
        a._an_select("cpu_avg")
        text = a.an_detail.cget("text")
        self.assertIn("plugged in and some on battery", text)
        self.assertIn("1 run(s) from different hardware are hidden", text)
        self.assertIn("Baseline: mean 20.0", text)
        self.assertEqual(a.an_chips["cpu_avg"].style, "primary")
        analytics._save({"consent": True, "sessions": []})
        a._an_refresh()
        self.assertIn("Record a baseline", a.an_detail.cget("text"))
        a._an_select("fps")
        self.assertIn("Not available", a.an_detail.cget("text"))



class TextHelperTests(unittest.TestCase):
    def test_relative_times(self):
        from sentinel.gui.text import ago
        now = time.time()
        self.assertEqual(ago(now - 5), "just now")
        self.assertEqual(ago(now - 300), "5 min ago")
        self.assertEqual(ago(now - 7200), "2 h ago")
        self.assertEqual(ago(now - 3 * 86400), "3 d ago")


if __name__ == "__main__":
    unittest.main()
