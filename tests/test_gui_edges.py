"""Remaining window edge cases: unknown queue messages, closing a half-built window, failed shield start, odd results."""
import threading
import unittest
from types import SimpleNamespace
from unittest import mock

from sentinel import config, engine, optimizer
from sentinel.optimizer.models import ApplyResult
from tests.gui_support import AppTestCase
from tests.test_gui_optimizer_pages import analysis, rec


class WindowEdgeTests(AppTestCase):
    def test_unknown_queue_messages_are_ignored(self):
        a = self.app
        a.msgs.put(("something-new", None))
        self.assertTrue(self.settle(lambda: a.msgs.empty()))

    def test_closing_a_window_that_never_ran_analytics_or_modes(self):
        from sentinel.gui import App
        fake = SimpleNamespace(cancel=threading.Event(), opt_cancel_ev=threading.Event(), _mode=None, monitor=None,
                               procwatch=None, destroy=mock.Mock())
        App._close(fake)
        fake.destroy.assert_called_once()
        self.assertTrue(fake.cancel.is_set())

    def test_shield_that_fails_before_the_monitor_exists(self):
        a = self.app
        a.monitor = a.procwatch = None
        a.rt_paths.set(str(self.temp_dir()))
        with mock.patch("sentinel.gui.realtime.RealtimeMonitor", side_effect=RuntimeError("no watchdog")), \
                mock.patch("sentinel.gui.realtime.messagebox.showerror") as err:
            a._on_rt_switch(True)
        self.assertIn("no watchdog", err.call_args[0][1])
        self.assertIsNone(a.monitor)

    def test_applying_a_recommendation_of_an_unknown_kind_still_reports(self):
        a = self.app
        a._show_page("optimizer")
        r = rec(key="odd", kind="odd-kind", target={})
        a.opt_analysis = analysis([r])
        a.opt_baseline = None
        with mock.patch("sentinel.gui.recommendations.messagebox.askyesno", return_value=True):
            a._opt_apply_rec(r)
            self.assertTrue(self.settle(lambda: "Applied 0" in a.opt_report.cget("text")))

    def test_profile_result_without_an_overlay(self):
        a = self.app
        a._mode = None
        with mock.patch.object(a.toast, "show") as toast, \
                mock.patch.object(optimizer, "available_plans", return_value=[]), \
                mock.patch.object(optimizer, "current_profile", return_value=None):
            a._mode_result("gaming", ApplyResult(True, "Power plan changed."), True)
        self.assertEqual(toast.call_args[0][0], "Power plan changed.")


class FingerprintEdgeTests(unittest.TestCase):
    def test_missing_rule_folder_is_skipped(self):
        with mock.patch.object(config, "RULES_DIR", config.DATA_DIR / "no-such-rules-folder"):
            self.assertIsInstance(engine.rules_fingerprint(), str)


if __name__ == "__main__":
    unittest.main()
