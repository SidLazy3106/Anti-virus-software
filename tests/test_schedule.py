"""Tests for the scheduler wrapper."""
import sys
import unittest
from pathlib import Path



class ScheduleTests(unittest.TestCase):
    """Task Scheduler is simulated: these tests never register a real task."""

    def setUp(self):
        from sentinel import schedule
        self.s = schedule
        self.calls, self.tasks = [], {}
        self._real = schedule._schtasks
        import subprocess

        def fake(*args):
            self.calls.append(args)
            if args[0] == "/Create":
                self.tasks[args[2]] = args[4]
                return subprocess.CompletedProcess(args, 0, "SUCCESS", "")
            if args[0] == "/Query":
                if args[2] not in self.tasks:
                    return subprocess.CompletedProcess(args, 1, "", "ERROR: not found")
                return subprocess.CompletedProcess(args, 0, f"TaskName: \\{args[2]}\nNext Run Time: 11/8/2026 3:30:00 AM\n"
                                                            f"Task To Run: {self.tasks[args[2]]}\n", "")
            if args[0] == "/Delete":
                self.tasks.pop(args[2], None)
            return subprocess.CompletedProcess(args, 0, "SUCCESS", "")
        schedule._schtasks = fake
        self.addCleanup(setattr, schedule, "_schtasks", self._real)

    def test_daily_and_weekly_tasks_are_built_and_verified(self):
        ok, msg = self.s.create("3:30")
        self.assertTrue(ok, msg)
        args = self.calls[0]
        self.assertEqual(args[args.index("/ST") + 1], "03:30")
        self.assertEqual(args[args.index("/SC") + 1], "DAILY")
        self.assertIn("quickscan --scheduled", args[args.index("/TR") + 1])
        self.assertIn("every day at 03:30", msg)
        self.assertTrue(self.s.describe().startswith("Quick scan, next run"))
        ok, msg = self.s.create("22:05", "fullscan", "fri")
        args = self.calls[-2]
        self.assertEqual((args[args.index("/SC") + 1], args[args.index("/D") + 1]), ("WEEKLY", "FRI"))
        self.assertTrue(self.s.describe().startswith("Full PC scan"))

    def test_bad_input_is_rejected_before_touching_task_scheduler(self):
        for at, kind, day in (("25:00", "quickscan", None), ("noon", "quickscan", None), ("10:00", "rm", None),
                              ("10:00", "quickscan", "funday")):
            ok, _ = self.s.create(at, kind, day)
            self.assertFalse(ok)
        self.assertEqual(self.calls, [])

    def test_off_removes_the_task(self):
        self.s.create("10:00")
        self.assertTrue(self.s.remove()[0])
        self.assertEqual(self.s.describe(), "Off")
        self.assertTrue(self.s.remove()[0])                    # already off: still fine

    def test_task_command_is_quoted_and_windowless(self):
        cmd = self.s.task_command("quickscan")
        self.assertTrue(cmd.startswith('"'))
        self.assertIn('main.py" quickscan --scheduled', cmd)
        if Path(sys.executable).with_name("pythonw.exe").exists():
            self.assertIn("pythonw.exe", cmd)

    def test_unattended_result_is_saved_and_alert_only_when_needed(self):
        shown = []
        import ctypes
        real = ctypes.windll.user32.MessageBoxW if sys.platform == "win32" else None
        if real is None:
            self.skipTest("Windows only")
        ctypes.windll.user32.MessageBoxW = lambda *a: shown.append(a) or 1
        try:
            st = type("S", (), {"files": 10, "cached": 2, "threats": 0, "elapsed": 1.25})()
            self.s.save_result("quickscan", st, [])
            self.s.notify(0)
            self.assertEqual(shown, [])
            self.s.notify(2)
            self.assertEqual(len(shown), 1)
            self.assertIn("2 item(s)", shown[0][1])
        finally:
            ctypes.windll.user32.MessageBoxW = real
        self.assertEqual(self.s.last_result()["files"], 10)
