"""Scheduler and native-host edge cases: failure messages, frozen builds, notifications and protocol corner cases."""
import ctypes
import io
import json
import os
import struct
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path
from types import SimpleNamespace
from unittest import mock

from sentinel import config, nativehost, schedule


def done(code=0, out="", err=""):
    return subprocess.CompletedProcess([], code, out, err)


class SchedulerFailureTests(unittest.TestCase):
    def test_schtasks_wrapper_hides_the_console_and_sets_a_timeout(self):
        with mock.patch.object(schedule.subprocess, "run", return_value=done()) as run:
            schedule._schtasks("/Query")
        self.assertEqual(run.call_args[0][0], ["schtasks", "/Query"])
        self.assertEqual(run.call_args[1]["timeout"], config.SCHEDULER_TIMEOUT_SECONDS)

    def test_task_command_for_a_packaged_build(self):
        d = Path(tempfile.mkdtemp())
        exe = d / "X-Secure.exe"
        exe.write_text("x")
        with mock.patch.object(schedule.sys, "frozen", True, create=True), mock.patch.object(schedule.sys, "executable", str(d / "other.exe")):
            self.assertEqual(schedule.task_command("fullscan"), f'"{exe}" fullscan --scheduled')
            exe.unlink()
            self.assertEqual(schedule.task_command(), f'"{d / "other.exe"}" quickscan --scheduled')

    def test_over_long_install_paths_are_refused(self):
        with mock.patch.object(schedule, "task_command", return_value="x" * (config.SCHEDULER_MAX_COMMAND_CHARS + 1)):
            ok, msg = schedule.create("10:00")
        self.assertFalse(ok)
        self.assertIn("too long", msg)

    def test_task_scheduler_refusals(self):
        with mock.patch.object(schedule, "_schtasks", return_value=done(1, "", "ERROR: Access is denied")):
            self.assertEqual(schedule.create("10:00"), (False, "ERROR: Access is denied"))
        with mock.patch.object(schedule, "_schtasks", return_value=done(1, "", "")):
            self.assertEqual(schedule.create("10:00"), (False, "Task Scheduler refused the task."))
        with mock.patch.object(schedule, "_schtasks", return_value=done(0)), mock.patch.object(schedule, "query", return_value=None):
            self.assertEqual(schedule.create("10:00"), (False, "Task Scheduler did not keep the task."))

    def test_query_ignores_lines_without_a_colon_and_describe_handles_na(self):
        text = "garbage line\nNext Run Time: N/A\nTask To Run: x quickscan\nNext Run Time: later\n"
        with mock.patch.object(schedule, "_schtasks", return_value=done(0, text)):
            info = schedule.query()
        self.assertEqual(info["Next Run Time"], "N/A")                       # first occurrence wins
        with mock.patch.object(schedule, "query", return_value=info):
            self.assertEqual(schedule.describe(), "Quick scan")
        with mock.patch.object(schedule, "query", return_value=None):
            self.assertEqual(schedule.describe(), "Off")

    def test_remove_and_run_now(self):
        with mock.patch.object(schedule, "query", return_value=None):
            self.assertEqual(schedule.remove(), (True, "No scheduled scan was set."))
        with mock.patch.object(schedule, "query", return_value={}), \
                mock.patch.object(schedule, "_schtasks", return_value=done(1, "", "cannot delete")):
            self.assertEqual(schedule.remove(), (False, "cannot delete"))
        with mock.patch.object(schedule, "_schtasks", return_value=done(0, "started")):
            self.assertEqual(schedule.run_now(), (True, "started"))
        with mock.patch.object(schedule, "_schtasks", return_value=done(1, "", "no such task")):
            self.assertEqual(schedule.run_now(), (False, "no such task"))

    def test_results_round_trip_and_bad_files_read_as_none(self):
        stats = SimpleNamespace(files=3, cached=1, threats=0, elapsed=1.234)
        schedule.save_result("quickscan", stats, [{"path": "x"}] * 300)
        got = schedule.last_result()
        self.assertEqual((got["files"], len(got["flagged"]), got["seconds"]), (3, 200, 1.2))
        schedule.result_file().write_text("{not json")
        self.assertIsNone(schedule.last_result())
        schedule.result_file().unlink()
        self.assertIsNone(schedule.last_result())

    def test_notify_only_on_windows_and_only_when_something_was_found(self):
        box = mock.Mock()
        fake = SimpleNamespace(user32=SimpleNamespace(MessageBoxW=box))
        with mock.patch.object(schedule, "IS_WIN", True), mock.patch.object(ctypes, "windll", fake, create=True):
            schedule.notify(0)
            box.assert_not_called()
            schedule.notify(3)
        self.assertIn("flagged 3 item(s)", box.call_args[0][1])
        with mock.patch.object(schedule, "IS_WIN", False):
            schedule.notify(5)
        self.assertEqual(box.call_count, 1)


class ProtocolTests(unittest.TestCase):
    def frame(self, obj):
        data = json.dumps(obj).encode()
        return struct.pack("<I", len(data)) + data

    def test_truncated_and_oversized_messages(self):
        self.assertIsNone(nativehost.read_message(io.BytesIO(struct.pack("<I", 50) + b"short")))
        self.assertIsNone(nativehost.read_message(io.BytesIO(b"")))
        with self.assertRaises(ValueError):
            nativehost.read_message(io.BytesIO(struct.pack("<I", nativehost.MAX_MESSAGE + 1)))

    def test_serve_reports_bad_messages_and_survives_handler_crashes(self):
        out = io.BytesIO()
        self.assertEqual(nativehost.serve(io.BytesIO(struct.pack("<I", 3) + b"{x}"), out), 1)
        self.assertIn(b"bad message", out.getvalue())
        out = io.BytesIO()
        stream = io.BytesIO(self.frame({"type": "ping"}) + self.frame({"type": "scan", "path": "x"}))
        with mock.patch.object(nativehost, "handle", side_effect=[{"ok": True}, RuntimeError("scanner exploded")]):
            self.assertEqual(nativehost.serve(stream, out), 0)
        replies = out.getvalue()
        self.assertIn(b"RuntimeError: scanner exploded", replies)

    def test_serve_switches_the_console_to_binary_mode_on_windows(self):
        fake_msvcrt = SimpleNamespace(setmode=mock.Mock())
        fake_stdin = SimpleNamespace(fileno=lambda: 0, buffer=io.BytesIO(b""))
        fake_stdout = SimpleNamespace(fileno=lambda: 1, buffer=io.BytesIO())
        with mock.patch.dict(sys.modules, {"msvcrt": fake_msvcrt}), mock.patch.object(nativehost, "IS_WIN", True), \
                mock.patch.object(nativehost.sys, "stdin", fake_stdin), mock.patch.object(nativehost.sys, "stdout", fake_stdout):
            self.assertEqual(nativehost.serve(), 0)
        self.assertEqual(fake_msvcrt.setmode.call_count, 2)
        self.assertEqual(fake_msvcrt.setmode.call_args[0][1], os.O_BINARY)

    def test_handle_edge_cases(self):
        self.assertEqual(nativehost.handle([])["error"], "bad request")
        self.assertEqual(nativehost.handle({"type": "scan", "path": ""})["error"], "no path given")
        self.assertEqual(nativehost.handle({"type": "scan", "path": "relative.txt"})["error"], "path must be absolute")
        with mock.patch.object(Path, "is_file", side_effect=OSError("denied")):
            self.assertEqual(nativehost.handle({"type": "scan", "path": os.path.abspath("x")})["error"], "denied")
        self.assertIn("unknown request type", nativehost.handle({"type": "format c:"})["error"])

    def test_launcher_for_a_packaged_build(self):
        d = Path(tempfile.mkdtemp())
        cli = d / "x-secure-cli.exe"
        cli.write_text("x")
        with mock.patch.object(nativehost.sys, "frozen", True, create=True), mock.patch.object(nativehost.sys, "executable", str(d / "X-Secure.exe")):
            self.assertIn(str(cli), nativehost.launcher_text())
            cli.unlink()
            self.assertIn("X-Secure.exe", nativehost.launcher_text())

    def test_uninstall_ignores_browsers_that_were_never_registered(self):
        self.assertEqual(nativehost.uninstall(reg_base=r"Software\XSecureTest\Nowhere"), [])


if __name__ == "__main__":
    unittest.main()
