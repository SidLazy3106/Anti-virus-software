"""Start-up and shutdown behaviour: one window at a time, graceful failures, and the last-resort error report."""
import contextlib
import io
import unittest
from types import SimpleNamespace
from unittest import mock

from sentinel import cli, config, fatal, gui, single_instance
from sentinel.winconst import ERROR_ALREADY_EXISTS


def fake_windll(handle=7, last_error=0, hwnd=0):
    k32 = SimpleNamespace(CreateMutexW=mock.Mock(return_value=handle), GetLastError=lambda: last_error,
                          CloseHandle=mock.Mock())
    user32 = SimpleNamespace(FindWindowW=mock.Mock(return_value=hwnd), ShowWindow=mock.Mock(),
                             SetForegroundWindow=mock.Mock(), MessageBoxW=mock.Mock())
    return SimpleNamespace(kernel32=k32, user32=user32)


class SingleInstanceTests(unittest.TestCase):
    def tearDown(self):
        single_instance._handle = None

    def test_first_instance_wins_and_releases_the_lock(self):
        win = fake_windll()
        with mock.patch.object(single_instance, "IS_WIN", True), mock.patch.object(single_instance.ctypes, "windll", win, create=True):
            self.assertTrue(single_instance.acquire())
            single_instance.release()
            win.kernel32.CloseHandle.assert_called_once_with(7)
            single_instance.release()                                         # nothing left to release
            self.assertEqual(win.kernel32.CloseHandle.call_count, 1)

    def test_second_instance_is_refused_and_closes_its_handle(self):
        win = fake_windll(last_error=ERROR_ALREADY_EXISTS)
        with mock.patch.object(single_instance, "IS_WIN", True), mock.patch.object(single_instance.ctypes, "windll", win, create=True):
            self.assertFalse(single_instance.acquire())
        win.kernel32.CloseHandle.assert_called_once()

    def test_never_locks_the_user_out_when_the_mutex_cannot_be_created_or_off_windows(self):
        with mock.patch.object(single_instance, "IS_WIN", True), \
                mock.patch.object(single_instance.ctypes, "windll", fake_windll(handle=0), create=True):
            self.assertTrue(single_instance.acquire())
        with mock.patch.object(single_instance, "IS_WIN", False):
            self.assertTrue(single_instance.acquire())
            self.assertFalse(single_instance.focus_existing())

    def test_bringing_the_running_window_forward(self):
        win = fake_windll(hwnd=99)
        with mock.patch.object(single_instance, "IS_WIN", True), mock.patch.object(single_instance.ctypes, "windll", win, create=True):
            self.assertTrue(single_instance.focus_existing())
            win.user32.SetForegroundWindow.assert_called_once_with(99)
            win.user32.FindWindowW.return_value = 0
            self.assertFalse(single_instance.focus_existing())

    def test_real_mutex_round_trip_on_this_machine(self):
        self.assertTrue(single_instance.acquire(r"Local\X-Secure-Test-Mutex"))
        self.assertFalse(single_instance.acquire(r"Local\X-Secure-Test-Mutex"))
        single_instance.release()
        self.assertTrue(single_instance.acquire(r"Local\X-Secure-Test-Mutex"))
        single_instance.release()


class RunTests(unittest.TestCase):
    def test_second_launch_focuses_the_first_window_and_exits_quietly(self):
        with mock.patch.object(single_instance, "acquire", return_value=False), \
                mock.patch.object(single_instance, "focus_existing") as focus, \
                mock.patch("sentinel.gui.app.App") as app:
            self.assertEqual(gui.run(), 0)
        focus.assert_called_once()
        app.assert_not_called()

    def test_window_that_cannot_open_is_reported_and_the_lock_released(self):
        with mock.patch.object(single_instance, "acquire", return_value=True), \
                mock.patch.object(single_instance, "release") as release, \
                mock.patch("sentinel.gui.app.App", side_effect=RuntimeError("no display")), \
                mock.patch.object(fatal, "report") as report:
            self.assertEqual(gui.run(), 1)
        self.assertIn("no display", report.call_args[0][0])
        release.assert_called_once()

    def test_normal_run_returns_zero_and_the_gui_command_passes_it_on(self):
        app = mock.MagicMock()
        with mock.patch.object(single_instance, "acquire", return_value=True), \
                mock.patch.object(single_instance, "release"), mock.patch("sentinel.gui.app.App", return_value=app):
            self.assertEqual(gui.run(), 0)
        app.mainloop.assert_called_once()
        with mock.patch("sentinel.gui.run", return_value=0):
            self.assertEqual(cli.cmd_gui(None), 0)


class FatalAndSafeMainTests(unittest.TestCase):
    def test_report_uses_a_message_box_only_for_the_windowed_build(self):
        win = fake_windll()
        with mock.patch.object(fatal, "IS_WIN", True), mock.patch.object(fatal.sys, "frozen", True, create=True), \
                mock.patch.object(fatal.sys, "stderr", None), mock.patch.object(fatal.ctypes, "windll", win, create=True):
            fatal.report("Something broke")
        text = win.user32.MessageBoxW.call_args[0][1]
        self.assertIn("Something broke", text)
        self.assertIn(str(config.LOG_FILE), text)
        err = io.StringIO()
        with contextlib.redirect_stderr(err):
            fatal.report("From a terminal")
        self.assertIn("From a terminal", err.getvalue())

    def test_safe_main_passes_results_and_survives_failures(self):
        with mock.patch.object(cli, "main", return_value=3):
            self.assertEqual(cli.safe_main([]), 3)
        with mock.patch.object(cli, "main", side_effect=KeyboardInterrupt):
            self.assertEqual(cli.safe_main([]), 130)
        with mock.patch.object(cli, "main", side_effect=ValueError("bad state")), mock.patch.object(fatal, "report") as report:
            self.assertEqual(cli.safe_main([]), 1)
        self.assertIn("ValueError: bad state", report.call_args[0][0])


if __name__ == "__main__":
    unittest.main()
