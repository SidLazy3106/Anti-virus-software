"""Tests for the command-line interface (sentinel/cli.py): every sub-command, with collaborators replaced by fakes."""
import contextlib
import io
import shutil
import tempfile
import unittest
from pathlib import Path
from types import SimpleNamespace
from unittest import mock

from sentinel import cli, engine
from sentinel.result import ScanResult
from sentinel.verdict import Verdict


def run(argv):
    """Run the CLI, returning (exit code, stdout, stderr)."""
    out, err = io.StringIO(), io.StringIO()
    with contextlib.redirect_stdout(out), contextlib.redirect_stderr(err):
        code = cli.main(argv)
    return code, out.getvalue(), err.getvalue()


def flagged(path="C:/bad.exe", verdict=Verdict.MALICIOUS):
    return ScanResult(path=path, verdict=verdict, score=90, sha256="ab" * 32, reasons=["reason one", "reason two"])


class FakeEngine:
    def __init__(self, results, stats=None):
        self.workers = 2
        self.stats = stats or engine.ScanStats(files=len(results), threats=len(results), started=1.0, finished=2.0)
        self._results = results

    def scan(self, roots, exclude):
        yield from self._results


class ParserAndConsoleTests(unittest.TestCase):
    def test_every_command_has_a_handler_and_no_command_means_gui(self):
        parser = cli.build_parser()
        for argv in (["gui"], ["scan", "x"], ["quickscan"], ["fullscan"], ["audit"], ["url", "u"], ["monitor", "p"],
                     ["update"], ["allow", "t"], ["schedule", "show"], ["nativehost", "status"], ["benchmark"]):
            self.assertIn(parser.parse_args(argv).cmd, cli.HANDLERS)
        self.assertIsNone(parser.parse_args([]).cmd)
        self.assertIs(cli.HANDLERS[None], cli.cmd_gui)

    def test_safe_console_handles_tty_pipe_missing_and_failing_streams(self):
        calls = []

        class Stream:
            def __init__(self, tty, fail=False):
                self.tty, self.fail = tty, fail

            def isatty(self):
                return self.tty

            def reconfigure(self, **kw):
                if self.fail:
                    raise ValueError("closed")
                calls.append(kw)

        with mock.patch.object(cli.sys, "stdout", Stream(False)), mock.patch.object(cli.sys, "stderr", Stream(True)):
            cli.safe_console()
        self.assertEqual(calls, [{"encoding": "utf-8", "errors": "replace"}, {"errors": "replace"}])
        with mock.patch.object(cli.sys, "stdout", Stream(True, fail=True)), \
                mock.patch.object(cli.sys, "stderr", object()):          # no reconfigure() at all
            cli.safe_console()                                              # must not raise


class ScanCommandTests(unittest.TestCase):
    def setUp(self):
        self.d = Path(tempfile.mkdtemp())
        self.addCleanup(shutil.rmtree, self.d, True)

    def test_scan_missing_path_is_exit_code_2(self):
        code, _out, err = run(["scan", str(self.d / "nope")])
        self.assertEqual(code, 2)
        self.assertIn("Path not found", err)

    def test_scan_real_folder_reports_a_threat_with_exit_code_1(self):
        (self.d / "clean.txt").write_text("hello")
        # ransomware-style commands: scores far above the "malicious" threshold without being a real virus
        (self.d / "bad.ps1").write_text("vssadmin delete shadows /all\nSet-MpPreference -DisableRealtimeMonitoring $true\n")
        code, out, _err = run(["scan", str(self.d), "--workers", "1", "--no-cache"])
        self.assertEqual(code, 1)
        self.assertIn("MALICIOUS", out)
        self.assertIn("files checked", out)

    def test_clean_folder_is_exit_code_0(self):
        (self.d / "a.txt").write_text("hello")
        code, out, _ = run(["scan", str(self.d), "--workers", "1", "--no-cache"])
        self.assertEqual(code, 0)
        self.assertIn("0 flagged", out)

    def test_flagged_results_quarantine_and_scheduled_summary(self):
        eng = FakeEngine([flagged(), flagged("C:/odd.js", Verdict.SUSPICIOUS)],
                         engine.ScanStats(files=2, threats=2, errors=1, dirs_denied=1, skipped=1, started=1, finished=3))
        with mock.patch("sentinel.engine.ScanEngine", return_value=eng), \
                mock.patch("sentinel.quarantine.quarantine_file") as q, \
                mock.patch("sentinel.schedule.save_result") as save, mock.patch("sentinel.schedule.notify") as notify:
            args = cli.build_parser().parse_args(["quickscan", "--quarantine", "--scheduled"])
            buf = io.StringIO()
            with contextlib.redirect_stdout(buf):
                code = cli.run_scan(["C:/"], [], args)
            out = buf.getvalue()
        self.assertEqual(code, 1)
        q.assert_called_once()                                    # only the MALICIOUS one is quarantined
        self.assertIn("> quarantined", out)
        self.assertIn("unreadable file(s)", out)
        save.assert_called_once()
        notify.assert_called_once_with(2)

    def test_quarantine_failure_is_reported_and_scanning_continues(self):
        eng = FakeEngine([flagged()])
        args = cli.build_parser().parse_args(["scan", "x", "--quarantine"])
        buf = io.StringIO()
        with mock.patch("sentinel.engine.ScanEngine", return_value=eng), \
                mock.patch("sentinel.quarantine.quarantine_file", side_effect=OSError("in use")), \
                contextlib.redirect_stdout(buf):
            self.assertEqual(cli.run_scan(["x"], [], args), 1)
        self.assertIn("quarantine failed: in use", buf.getvalue())

    def test_progress_line_and_ctrl_c(self):
        eng = FakeEngine([flagged()])
        args = cli.build_parser().parse_args(["scan", "x"])
        err = io.StringIO()
        with mock.patch("sentinel.engine.ScanEngine", return_value=eng), \
                mock.patch.object(cli, "PROGRESS_EVERY_SECONDS", -1), \
                contextlib.redirect_stdout(io.StringIO()), contextlib.redirect_stderr(err):
            cli.run_scan(["x"], [], args)
        self.assertIn("files checked", err.getvalue())

        class Interrupted(FakeEngine):
            def scan(self, roots, exclude):
                raise KeyboardInterrupt
                yield  # pragma: no cover

        out = io.StringIO()
        with mock.patch("sentinel.engine.ScanEngine", return_value=Interrupted([])), contextlib.redirect_stdout(out):
            self.assertEqual(cli.run_scan(["x"], [], args), 0)
        self.assertIn("Scan cancelled", out.getvalue())

    def test_quick_and_full_scan_pick_their_plan(self):
        for cmd, plan in (("quickscan", "quick_scan_plan"), ("fullscan", "full_scan_plan")):
            with mock.patch(f"sentinel.engine.{plan}", return_value=(["r"], ["e"])) as p, \
                    mock.patch.object(cli, "run_scan", return_value=0) as rs:
                self.assertEqual(run([cmd])[0], 0)
            p.assert_called_once()
            self.assertEqual(rs.call_args[0][:2], (["r"], ["e"]))


class OtherCommandTests(unittest.TestCase):
    def test_gui_and_default_open_the_app(self):
        with mock.patch("sentinel.gui.run", return_value=0) as gui_run:
            self.assertEqual(run([])[0], 0)
            self.assertEqual(run(["gui"])[0], 0)
        self.assertEqual(gui_run.call_count, 2)

    def test_audit_prints_findings_details_and_fixes(self):
        finding = SimpleNamespace(severity="high", category="Network", title="RDP open", detail="port 3389", fix="turn off")
        bare = SimpleNamespace(severity="low", category="System", title="Fine", detail="", fix="")
        with mock.patch("sentinel.sysaudit.run_audit", return_value=SimpleNamespace(score=70, findings=[finding, bare])):
            code, out, _ = run(["audit"])
        self.assertEqual(code, 0)
        for text in ("Security score: 70/100", "RDP open", "port 3389", "Fix: turn off", "Fine"):
            self.assertIn(text, out)

    def test_url_exit_code_follows_the_verdict(self):
        code, out, _ = run(["url", "http://paypa1-secure-login.xyz/verify"])
        self.assertEqual(code, 1)
        self.assertIn("MALICIOUS", out)
        self.assertEqual(run(["url", "https://github.com/login"])[0], 0)

    def test_allow_accepts_hash_or_file_and_reports_unreadable(self):
        with mock.patch("sentinel.scanner.add_to_allowlist") as add:
            self.assertEqual(run(["allow", "AB" * 32])[0], 0)
            add.assert_called_with("ab" * 32, "")
            d = Path(tempfile.mkdtemp())
            self.addCleanup(shutil.rmtree, d, True)
            f = d / "tool.exe"
            f.write_bytes(b"data")
            self.assertEqual(run(["allow", str(f)])[0], 0)
            self.assertEqual(add.call_args[0][1], str(f))
            code, _out, err = run(["allow", str(d / "missing.exe")])
        self.assertEqual(code, 2)
        self.assertIn("Cannot read", err)

    def test_update_prints_each_feed_result(self):
        with mock.patch("sentinel.updater.update_feeds", return_value={"Feed A": "5 domains"}):
            code, out, _ = run(["update"])
        self.assertEqual((code, out.strip()), (0, "Feed A: 5 domains"))

    def test_benchmark_runs_and_prints_the_report(self):
        def fake_run(paths, limit, progress):
            progress(1234)
            return {"x": 1}
        with mock.patch("sentinel.benchmark.run", side_effect=fake_run), \
                mock.patch("sentinel.benchmark.report", return_value="REPORT"):
            code, out, err = run(["benchmark", "--limit", "5"])
        self.assertEqual((code, out.strip()), (0, "REPORT"))
        self.assertIn("1,234 clean files scanned", err)


class ScheduleCommandTests(unittest.TestCase):
    def test_set_off_run_and_show(self):
        with mock.patch("sentinel.schedule.create", return_value=(True, "scheduled")) as create, \
                mock.patch("sentinel.schedule.remove", return_value=(False, "nope")), \
                mock.patch("sentinel.schedule.run_now", side_effect=[(True, ""), (False, "task missing")]), \
                mock.patch("sentinel.schedule.describe", return_value="Quick scan"), \
                mock.patch("sentinel.schedule.last_result", side_effect=[None, {"time": 0, "files": 1234, "threats": 2}]):
            code, out, _ = run(["schedule", "set", "--at", "09:30", "--weekly", "MON", "--full"])
            create.assert_called_once_with("09:30", "fullscan", "MON")
            self.assertEqual((code, out.strip()), (0, "scheduled"))
            self.assertEqual(run(["schedule", "off"])[0], 1)                              # failure -> exit code 1
            self.assertIn("started in the background", run(["schedule", "run"])[1])
            self.assertIn("task missing", run(["schedule", "run"])[1])
            self.assertEqual(run(["schedule", "show"])[1].strip(), "Scheduled scan: Quick scan")
            self.assertIn("1,234 files, 2 flagged", run(["schedule", "show"])[1])


class NativeHostCommandTests(unittest.TestCase):
    def test_serve_install_uninstall_and_status(self):
        with mock.patch("sentinel.nativehost.serve", return_value=0) as serve:
            self.assertEqual(run(["nativehost", "serve"])[0], 0)
        serve.assert_called_once()
        with mock.patch("sentinel.nativehost.install", return_value=[("chrome", "Software\\X")]):
            code, out, _ = run(["nativehost", "install", "--extension-id", "a" * 32])
        self.assertEqual(code, 0)
        self.assertIn("Registered for chrome", out)
        with mock.patch("sentinel.nativehost.install", side_effect=ValueError("bad id")):
            code, _out, err = run(["nativehost", "install"])
        self.assertEqual((code, err.strip()), (2, "bad id"))
        with mock.patch("sentinel.nativehost.uninstall", side_effect=[["chrome", "edge"], []]):
            self.assertIn("chrome, edge", run(["nativehost", "uninstall"])[1])
            self.assertIn("nothing was installed", run(["nativehost", "uninstall"])[1])
        with mock.patch("sentinel.nativehost.status", return_value={"chrome": "C:/h.json", "edge": None}):
            out = run(["nativehost", "status"])[1]
        self.assertIn("chrome: installed -> C:/h.json", out)
        self.assertIn("edge: not installed", out)


class MonitorCommandTests(unittest.TestCase):
    def _run(self, start_error=None, sleep_error=KeyboardInterrupt):
        mon, pw = mock.MagicMock(), mock.MagicMock()
        if start_error:
            mon.start.side_effect = start_error
        with mock.patch("sentinel.monitor.RealtimeMonitor", return_value=mon) as rm, \
                mock.patch("sentinel.monitor.ProcessWatcher", return_value=pw), \
                mock.patch("sentinel.scanner.Scanner"), mock.patch.object(cli.time, "sleep", side_effect=sleep_error):
            code, out, err = run(["monitor", "C:/watched", "--canaries"])
        return code, out, err, mon, pw, rm

    def test_runs_until_ctrl_c_then_stops_both_watchers(self):
        code, out, _err, mon, pw, rm = self._run()
        self.assertEqual(code, 0)
        self.assertIn("protection running", out)
        mon.stop.assert_called_once()
        pw.stop.assert_called_once()
        emit = rm.call_args[0][2]                                                  # the alert printer given to the monitor
        buf = io.StringIO()
        with contextlib.redirect_stdout(buf):
            emit(SimpleNamespace(detail="more"))
            emit(SimpleNamespace(detail=""))
        self.assertIn("| more", buf.getvalue())

    def test_missing_optional_package_is_exit_code_2(self):
        code, _out, err, mon, _pw, _rm = self._run(start_error=RuntimeError("needs watchdog"))
        self.assertEqual((code, err.strip()), (2, "needs watchdog"))
        mon.stop.assert_called_once()


if __name__ == "__main__":
    unittest.main()
