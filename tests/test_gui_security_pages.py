"""The security-side pages of the real window: Home, Scan, Quarantine, Real-time shield, Web guard, Health check,
plus the window shell (navigation, message queue, closing). Slow or system-changing collaborators are faked."""
import os
import queue
import time
import unittest
from types import SimpleNamespace
from unittest import mock

from sentinel import config, quarantine, schedule
from sentinel.monitor import Alert
from sentinel.result import ScanResult
from sentinel.sysaudit import AuditReport, Finding
from sentinel.verdict import Verdict
from tests.gui_support import AppTestCase

BAD_SCRIPT = "vssadmin delete shadows /all\nSet-MpPreference -DisableRealtimeMonitoring $true\n"


class HomeTests(AppTestCase):
    def setUp(self):
        a = self.app
        a.threat_count, a.last_scan, a.rt_active, a.last_score, a.scanning = 0, None, False, None, False

    def test_each_hero_state_and_its_action(self):
        a = self.app
        title, *_rest = a._next_step()
        self.assertEqual(title, "Run your first scan")
        a.threat_count = 1
        self.assertEqual(a._next_step()[0], "Action needed")
        self.assertIn("1 threat found. Review and remove it", a._next_step()[1])
        a.threat_count = 3
        self.assertIn("3 threats found. Review and remove them", a._next_step()[1])
        a.threat_count, a.last_scan = 0, {"time": time.time(), "files": 5, "threats": 0}
        self.assertEqual(a._next_step()[0], "Turn on the real-time shield")
        a.rt_active = True
        self.assertEqual(a._next_step()[0], "Check your PC's health")
        a.last_score = 90
        self.assertEqual(a._next_step()[0], "You're protected")

    def test_protection_level_is_bounded(self):
        a = self.app
        self.assertEqual(a._protection_level(), 20)
        a.rt_active, a.last_scan, a.last_score = True, {"time": time.time()}, 100
        self.assertEqual(a._protection_level(), 100)
        a.last_scan = {"time": time.time() - 30 * 86400}
        self.assertEqual(a._protection_level(), 80)
        a.threat_count, a.rt_active, a.last_score = 5, False, None
        self.assertEqual(a._protection_level(), 5)

    def test_refresh_shows_every_tile_state(self):
        a = self.app
        a._refresh_home()
        self.assertEqual(a.tile["scan"][0].cget("text"), "Not scanned yet")
        self.assertEqual(a.tile["audit"][0].cget("text"), "Not checked")
        self.assertEqual(a.tile["rt"][0].cget("text"), "Off")
        a.last_scan, a.threat_count, a.rt_active, a.last_score = {"time": time.time(), "files": 1, "threats": 2}, 2, True, 40
        a._refresh_home()
        self.assertEqual(a.tile["scan"][0].cget("text"), "2 threat(s)")
        self.assertEqual(a.tile["rt"][0].cget("text"), "Active")
        self.assertEqual(a.tile["audit"][0].cget("text"), "40 / 100")
        a.threat_count, a.last_score = 0, 60
        a._refresh_home()
        self.assertEqual(a.tile["scan"][0].cget("text"), "No threats")
        self.assertEqual(a.tile["audit"][0].cget("text"), "60 / 100")
        a.last_score = 95
        a._refresh_home()
        a.scanning = True                                                   # no status pill change while a scan runs
        a._refresh_home()

    def test_status_pill_follows_the_state(self):
        a = self.app
        with mock.patch.object(a, "_set_pill") as pill:
            a.threat_count = 1
            a._refresh_home()
            a.threat_count, a.rt_active = 0, True
            a._refresh_home()
            a.rt_active = False
            a._refresh_home()
        self.assertEqual([c.args[0] for c in pill.call_args_list], ["Action needed", "Protected", "Limited protection"])

    def test_tips_rotate_only_while_home_is_showing(self):
        a = self.app
        first = a.tip_title.cget("text")
        a._next_tip()
        self.assertNotEqual(a.tip_title.cget("text"), first)
        a.current_page = "home"
        with mock.patch.object(a, "after") as after:
            a._rotate_tip()
            idx = a.tip_index
            a.current_page = "scan"
            a._rotate_tip()
        self.assertEqual(a.tip_index, idx)
        self.assertEqual(after.call_count, 2)
        a.current_page = "home"

    def test_navigation_helpers(self):
        a = self.app
        with mock.patch.object(a, "_run_audit") as audit:
            a._go_audit()
            audit.assert_called_once()
        a._go_scan()
        self.assertEqual(a.current_page, "scan")
        with mock.patch.object(a, "_start_scan") as start:
            a._quick_scan_nav()
            start.assert_called_once()
        self.assertEqual(a.scan_mode.get(), "quick")
        a._show_page("home")
        self.assertEqual(a.page_title.cget("text"), "Home")
        a._hero_action = mock.Mock()                                        # never start a real scan of this PC
        a._hero_action()
        a.rt_active = True
        a._update_side()
        self.assertIn("on", a.side_status.cget("text"))
        a.rt_active = False
        a._update_side()


class ScanPageTests(AppTestCase):
    def setUp(self):
        a = self.app
        a.cancel.set()                                                      # stop anything an earlier test left running
        self.settle(lambda: not a.scanning, timeout=20)
        a.scanning = False
        a.cancel.clear()
        a.scan_tv.delete(*a.scan_tv.get_children())
        a.results.clear()
        a.threat_count = 0
        a._show_page("scan")

    def scan_folder(self, with_threat=True):
        d = self.temp_dir()
        (d / "clean.txt").write_text("hello")
        if with_threat:
            (d / "bad.ps1").write_text(BAD_SCRIPT)
        a = self.app
        a._set_scan_mode("custom")
        a.scan_path.set(str(d))
        a._start_scan()
        self.assertTrue(self.settle(lambda: not a.scanning), "scan did not finish")
        return d

    def test_scan_modes(self):
        a = self.app
        a._set_scan_mode("full")
        self.assertEqual(a.scan_path.get(), a.MODE_TEXT["full"])
        a._set_scan_mode("custom")
        self.assertEqual(a.scan_path.get(), "")
        a.scan_path.set("C:/my/folder")
        a._set_scan_mode("custom")
        self.assertEqual(a.scan_path.get(), "C:/my/folder")
        a.scanning = True
        a._set_scan_mode("quick")                                              # ignored while scanning
        self.assertEqual(a.scan_mode.get(), "custom")
        a.scanning = False
        a._set_scan_mode("quick")

    def test_browse(self):
        a = self.app
        with mock.patch("sentinel.gui.scan.filedialog.askdirectory", return_value="C:/picked"):
            a._browse()
        self.assertEqual(a.scan_path.get(), "C:/picked")
        with mock.patch("sentinel.gui.scan.filedialog.askdirectory", return_value=""):
            a._browse()
        self.assertEqual(a.scan_path.get(), "C:/picked")

    def test_real_scan_lists_the_threat_and_updates_the_window(self):
        a = self.app
        self.scan_folder()
        self.assertEqual(a.threat_count, 1)
        self.assertIn("1 thing(s) need your attention", a.scan_status.get())
        self.assertEqual(a.stat_vars["threats"].get(), "1")
        self.assertIsNotNone(a.last_scan)
        iid = a.scan_tv.get_children()[0]
        a.scan_tv.selection_set(iid)
        a._on_pick_result()
        self.assertIn("Why:", a.detail.cget("text"))
        a.scan_tv.selection_set()
        a._on_pick_result()
        self.assertEqual(a.detail.cget("text"), "")

    def test_clean_scan_and_missing_folder(self):
        a = self.app
        self.scan_folder(with_threat=False)
        self.assertIn("no threats found", a.scan_status.get())
        a._set_scan_mode("custom")
        a.scan_path.set(r"C:\definitely\not\here")
        with mock.patch("sentinel.gui.scan.messagebox.showerror") as err:
            a._start_scan()
        err.assert_called_once()
        self.assertFalse(a.scanning)

    def test_second_scan_request_and_cancel(self):
        a = self.app
        a.scanning = True
        with mock.patch.object(a.toast, "show") as toast:
            a._start_scan()
        self.assertIn("already running", toast.call_args[0][0])
        a._cancel_scan()
        self.assertTrue(a.cancel.is_set())
        a.scanning = False
        a.cancel.clear()

    def test_quick_and_full_scans_use_their_plans(self):
        a = self.app
        d = self.temp_dir()
        (d / "ok.txt").write_text("x")
        for mode, plan in (("quick", "quick_scan_plan"), ("full", "full_scan_plan")):
            a._set_scan_mode(mode)
            with mock.patch(f"sentinel.engine.{plan}", return_value=([str(d)], [])):
                a._start_scan()
                self.assertTrue(self.settle(lambda: not a.scanning))
            self.assertIn("files checked", a.scan_status.get())

    def test_a_crashing_scan_is_reported_not_left_hanging(self):
        a = self.app
        a._set_scan_mode("custom")
        a.scan_path.set(str(self.temp_dir()))
        with mock.patch("sentinel.engine.ScanEngine.scan", side_effect=RuntimeError("boom")):
            a._start_scan()
            self.assertTrue(self.settle(lambda: not a.scanning))
        self.assertIn("Scan failed: RuntimeError: boom", a.scan_status.get())

    def test_cancelled_scan_message(self):
        a = self.app
        st = SimpleNamespace(files=7, cached=0, errors=2, dirs_denied=1, elapsed=3.0)
        a.msgs.put(("scan_done", (st, 2, True)))
        self.settle(lambda: "Stopped after 7 files" in a.scan_status.get())
        self.assertIn("Stopped after 7 files", a.scan_status.get())
        self.assertIn("couldn't be read", a.scan_status.get())

    def test_quarantine_selected(self):
        a = self.app
        d = self.scan_folder()
        with mock.patch.object(a.toast, "show") as toast:
            a._quarantine_selected()                                          # nothing selected
            self.assertIn("Select one or more", toast.call_args[0][0])
            iid = a.scan_tv.get_children()[0]
            a.scan_tv.selection_set(iid)
            with mock.patch("sentinel.gui.scan.messagebox.showerror") as err, \
                    mock.patch.object(quarantine, "quarantine_file", side_effect=OSError("in use")):
                a._quarantine_selected()
            err.assert_called_once()
            self.assertEqual(len(a.scan_tv.get_children()), 1)
            a.scan_tv.selection_set(iid)
            a._quarantine_selected()
        self.assertFalse((d / "bad.ps1").exists())
        self.assertEqual(a.scan_tv.get_children(), ())
        self.assertIn("No threats left", a.empty_lbl.cget("text"))
        for item in quarantine.list_items():
            quarantine.delete(item["id"])

    def test_mark_as_safe(self):
        a = self.app
        self.scan_folder()
        iid = a.scan_tv.get_children()[0]
        with mock.patch.object(a.toast, "show") as toast:
            a.scan_tv.selection_set()
            a._trust_selected()
            self.assertIn("Select one or more", toast.call_args[0][0])
            a.scan_tv.selection_set(iid)
            with mock.patch("sentinel.gui.scan.messagebox.askyesno", return_value=False):
                a._trust_selected()
            self.assertEqual(len(a.scan_tv.get_children()), 1)
            with mock.patch("sentinel.gui.scan.messagebox.askyesno", return_value=True), \
                    mock.patch("sentinel.gui.scan.add_to_allowlist") as allow:
                a._trust_selected()
            allow.assert_called_once()
        self.assertEqual(a.scan_tv.get_children(), ())
        a.scanner.allow.clear()

    def test_after_result_change_while_scanning_keeps_quiet(self):
        a = self.app
        a.scanning = True
        a.empty_lbl.configure(text="")
        a._after_result_change()
        self.assertEqual(a.empty_lbl.cget("text"), "")
        a.scanning = False


class ScheduleControlsTests(AppTestCase):
    def test_showing_the_schedule_and_last_result(self):
        a = self.app
        a.last_scan = None
        a._sched_show("Quick scan, next run later", {"time": time.time(), "files": 1234, "threats": 2})
        self.assertIn("1,234 files, 2 flagged", a.sched_lbl.cget("text"))
        self.assertEqual(a.last_scan["files"], 1234)
        a._sched_show("Off", None)
        self.assertEqual(a.sched_lbl.cget("text"), "Off")
        a.last_scan = {"time": time.time() + 100, "files": 1, "threats": 0}
        a._sched_show("Off", {"time": 1.0, "files": 5, "threats": 0})            # older than the last manual scan
        self.assertEqual(a.last_scan["files"], 1)
        a.last_scan = None

    def test_refresh_reads_the_schedule_in_the_background(self):
        a = self.app
        with mock.patch.object(schedule, "describe", return_value="Quick scan"), \
                mock.patch.object(schedule, "last_result", return_value=None):
            a._sched_refresh()
            self.assertTrue(self.settle(lambda: a.sched_lbl.cget("text") == "Quick scan"))

    def test_turning_the_schedule_on(self):
        a = self.app
        with mock.patch.object(a.toast, "show") as toast:
            a.sched_time.set("noon")
            a._sched_on()
            self.assertIn("24-hour time", toast.call_args[0][0])
            a.sched_time.set("09:30")
            with mock.patch("sentinel.gui.scan.messagebox.askyesno", return_value=False), \
                    mock.patch.object(schedule, "create") as create:
                a._sched_on()
                create.assert_not_called()
            with mock.patch("sentinel.gui.scan.messagebox.askyesno", return_value=True), \
                    mock.patch.object(schedule, "create", return_value=(True, "Scheduled.")) as create:
                a._sched_on()
                self.assertTrue(self.settle(lambda: create.called and toast.call_args[0][0] == "Scheduled."))

    def test_turning_the_schedule_off(self):
        a = self.app
        with mock.patch.object(a.toast, "show") as toast, mock.patch.object(schedule, "remove", return_value=(False, "denied")):
            a._sched_off()
            self.assertTrue(self.settle(lambda: toast.called and toast.call_args[0][1] == "danger"))


class QuarantinePageTests(AppTestCase):
    def setUp(self):
        for item in quarantine.list_items():
            quarantine.delete(item["id"])

    def make_item(self, name="bad.bin"):
        d = self.temp_dir()
        f = d / name
        f.write_bytes(b"payload" * 20)
        return f, quarantine.quarantine_file(f, "test reason", "sha")

    def test_list_restore_and_delete(self):
        a = self.app
        a._show_page("quarantine")
        self.assertIn("Nothing in quarantine", a.q_empty.cget("text"))
        f, qid = self.make_item()
        a._refresh_q()
        self.assertEqual(a.q_tv.get_children(), (qid,))
        a.q_tv.selection_set()
        with mock.patch.object(a.toast, "show") as toast:
            a._restore_q()
            a._delete_q()
            self.assertEqual(toast.call_count, 2)
            a.q_tv.selection_set(qid)
            with mock.patch("sentinel.gui.quarantine.messagebox.askyesno", return_value=False):
                a._restore_q()
                a._delete_q()
            self.assertTrue(quarantine.list_items())
            with mock.patch("sentinel.gui.quarantine.messagebox.askyesno", return_value=True):
                a._restore_q()
        self.assertTrue(f.exists())
        self.assertEqual(quarantine.list_items(), [])
        f2, qid2 = self.make_item("two.bin")
        a._refresh_q()
        a.q_tv.selection_set(qid2)
        with mock.patch("sentinel.gui.quarantine.messagebox.askyesno", return_value=True):
            a._delete_q()
        self.assertEqual(quarantine.list_items(), [])

    def test_errors_are_shown_not_raised(self):
        a = self.app
        f, qid = self.make_item()
        a._refresh_q()
        a.q_tv.selection_set(qid)
        with mock.patch("sentinel.gui.quarantine.messagebox.askyesno", return_value=True), \
                mock.patch("sentinel.gui.quarantine.messagebox.showerror") as err:
            with mock.patch.object(quarantine, "restore", side_effect=OSError("cannot restore")):
                a._restore_q()
            a.q_tv.selection_set(qid)                                            # the list is rebuilt after each action
            with mock.patch.object(quarantine, "delete", side_effect=OSError("cannot delete")):
                a._delete_q()
        self.assertEqual(err.call_count, 2)
        quarantine.delete(qid)


class FakeMonitor:
    instances = []

    def __init__(self, scanner, paths, emit, auto_q, canary):
        self.args = (paths, auto_q, canary)
        self.stopped = False
        self.emit = emit
        FakeMonitor.instances.append(self)

    def start(self):
        if getattr(FakeMonitor, "fail", False):
            raise RuntimeError("needs watchdog")

    def stop(self):
        self.stopped = True


class FakeWatcher:
    def __init__(self, emit, scanner=None):
        self.stopped = False

    def start(self):
        pass

    def stop(self):
        self.stopped = True


class RealtimePageTests(AppTestCase):
    def setUp(self):
        FakeMonitor.fail = False
        FakeMonitor.instances.clear()
        patches = [mock.patch("sentinel.gui.realtime.RealtimeMonitor", FakeMonitor),
                   mock.patch("sentinel.gui.realtime.ProcessWatcher", FakeWatcher)]
        for p in patches:
            p.start()
            self.addCleanup(p.stop)
        self.app.monitor = self.app.procwatch = None
        self.app.rt_active = False

    def test_switching_the_shield_on_and_off(self):
        a = self.app
        folder = self.temp_dir()
        a.rt_paths.set(f"{folder}{os.pathsep}{folder / 'missing'}")
        a._on_rt_switch(True)
        self.assertTrue(a.rt_active)
        self.assertEqual(FakeMonitor.instances[0].args[0], [str(folder)])
        self.assertEqual(a.rt_title.cget("text"), "Real-time shield is on")
        a._on_rt_switch(True)                                                    # already on: nothing changes
        self.assertEqual(len(FakeMonitor.instances), 1)
        a._on_rt_switch(False)
        self.assertFalse(a.rt_active)
        self.assertTrue(FakeMonitor.instances[0].stopped)
        self.assertEqual(a.rt_title.cget("text"), "Real-time shield is off")
        FakeMonitor.instances[0].emit("an alert")
        self.settle(lambda: a.msgs.empty())

    def test_no_valid_folder_and_missing_dependency(self):
        a = self.app
        a.rt_paths.set(str(self.temp_dir() / "nope"))
        with mock.patch("sentinel.gui.realtime.messagebox.showerror") as err:
            a._on_rt_switch(True)
        err.assert_called_once()
        self.assertFalse(a.rt_active)
        self.assertFalse(a.rt_switch.value if hasattr(a.rt_switch, "value") else False)
        a.rt_paths.set(str(self.temp_dir()))
        FakeMonitor.fail = True
        with mock.patch("sentinel.gui.realtime.messagebox.showerror") as err:
            a._on_rt_switch(True)
        self.assertIn("needs watchdog", err.call_args[0][1])
        self.assertIsNone(a.monitor)


class WebPageTests(AppTestCase):
    def test_check_url_verdict_cards(self):
        a = self.app
        with mock.patch.object(a.toast, "show") as toast:
            a.url_var.set("  ")
            a._check_url()
            self.assertIn("Paste a link", toast.call_args[0][0])
        a.url_var.set("http://paypa1-secure-login.xyz/verify")
        a._check_url()
        self.assertIn("Dangerous", a.url_verdict.cget("text"))
        a.url_var.set("https://github.com/login")
        a._check_url()
        self.assertEqual(a.url_verdict.cget("text"), "Looks safe")
        self.assertIn("No risk signals", a.url_reasons.cget("text"))
        a.url_var.set("http://example.xyz/login/verify")
        a._check_url()
        self.assertEqual(a.url_verdict.cget("text"), "Be careful")
        self.assertIn("Risk score", a.url_score.cget("text"))
        with mock.patch("sentinel.webguard.analyze_url", return_value=SimpleNamespace(verdict="weird", score=1, reasons=["r"])):
            a._check_url()
        self.assertEqual(a.url_verdict.cget("text"), "Be careful")


class AuditPageTests(AppTestCase):
    def run_audit(self, report):
        a = self.app
        with mock.patch("sentinel.sysaudit.run_audit", return_value=report):
            a._run_audit()
            self.assertTrue(self.settle(lambda: not a.audit_running))

    def test_good_medium_and_bad_scores(self):
        a = self.app
        f = Finding("high", "Network", "Port open", "port 3389", "close it")
        self.run_audit(AuditReport(90, [f]))
        self.assertEqual(a.audit_title.cget("text"), "Your PC is in good shape")
        self.assertEqual(a.last_score, 90)
        iid = a.audit_tv.get_children()[0]
        a.audit_tv.selection_set(iid)
        a._on_pick_finding()
        self.assertIn("Fix: close it", a.audit_detail.cget("text"))
        a.audit_tv.selection_set()
        a._on_pick_finding()
        self.assertEqual(a.audit_detail.cget("text"), "")
        self.run_audit(AuditReport(60, [Finding("low", "x", "y")]))
        self.assertEqual(a.audit_title.cget("text"), "A few things need attention")
        a.audit_tv.selection_set(a.audit_tv.get_children()[0])
        a._on_pick_finding()
        self.run_audit(AuditReport(10, []))
        self.assertEqual(a.audit_title.cget("text"), "Your PC needs attention")
        self.assertEqual(a.audit_empty.cget("text"), "No problems found.")

    def test_a_second_request_while_running_is_ignored(self):
        a = self.app
        a.audit_running = True
        with mock.patch("sentinel.sysaudit.run_audit") as audit:
            a._run_audit()
        audit.assert_not_called()
        a.audit_running = False


class ShellAndQueueTests(AppTestCase):
    def test_every_page_can_be_shown(self):
        a = self.app
        for key in a.pages:
            a._show_page(key)
            self.assertEqual(a.current_page, key)
        a._show_page("home")

    def test_drain_handles_alerts_calls_and_failures(self):
        a = self.app
        with mock.patch.object(a, "bell") as bell, mock.patch.object(a.toast, "show") as toast:
            quiet = Alert("file", "info", "fyi")
            loud = Alert("ransomware", "critical", "ransomware!", "more")
            a.msgs.put(("alert", quiet))
            a.msgs.put(("alert", loud))
            ran = []
            a.msgs.put(("call", lambda: ran.append(1)))
            a.msgs.put(("scan_failed", "disk error"))
            a.msgs.put(("opt_scan_failed", "optimizer down"))
            self.assertTrue(self.settle(lambda: a.msgs.empty() and ran))
            self.assertTrue(self.settle(lambda: bell.called))
        self.assertEqual(toast.call_args[0][0], "ransomware!")
        self.assertIn("Scan failed: disk error", a.scan_status.get())
        a.scanning = False

    def test_scan_progress_hits_and_a_clean_finish(self):
        a = self.app
        res = ScanResult("C:/x/" + "a" * 100, Verdict.SUSPICIOUS, 50, "h", ["why"])
        a.scan_tv.delete(*a.scan_tv.get_children())
        a.threat_count = 0
        a.msgs.put(("scan_hit", res))
        a.msgs.put(("scan_progress", (10, 2, res.path)))
        self.assertTrue(self.settle(lambda: a.threat_count == 1 and "Checking: ..." in a.scan_status.get()))
        a.scan_tv.delete(*a.scan_tv.get_children())
        a.results.clear()
        a.threat_count = 0
        st = SimpleNamespace(files=3, cached=1, errors=0, dirs_denied=0, elapsed=1.0)
        a.msgs.put(("scan_done", (st, 1, False)))
        self.assertTrue(self.settle(lambda: "no threats found" in a.scan_status.get()))
        a.scanning = True
        a.scan_started = time.time()
        self.settle()
        a.scanning = False

    def test_closing_stops_background_work_and_survives_errors(self):
        from sentinel.gui import App
        a = self.app
        mon, watch = mock.MagicMock(), mock.MagicMock()
        watch.stop.side_effect = RuntimeError("stuck")
        a.monitor, a.procwatch = mon, watch
        a._mode = {"cancel": False}
        with mock.patch.object(App, "destroy") as destroy:
            a._close()
        mon.stop.assert_called_once()
        self.assertTrue(a._mode["cancel"])
        self.assertTrue(a.cancel.is_set())
        destroy.assert_called_once()
        a.monitor = a.procwatch = a._mode = None
        a.cancel.clear()
        a.opt_cancel_ev.clear()

    def test_run_builds_the_app_and_enters_the_main_loop(self):
        from sentinel import gui
        fake = mock.MagicMock()
        with mock.patch("sentinel.gui.app.App", return_value=fake):
            gui.run()
        fake.mainloop.assert_called_once()

    def test_queue_is_the_only_way_workers_talk_to_the_ui(self):
        self.assertIsInstance(self.app.msgs, queue.Queue)
        self.assertTrue(config.DATA_DIR.exists())


if __name__ == "__main__":
    unittest.main()
