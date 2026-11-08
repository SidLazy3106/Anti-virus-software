"""Optimizer internals with Windows replaced by fakes: registry switches, power plans, history/undo, temp files,
measurements, recommendations and the parallel scan."""
import ctypes
import os
import shutil
import subprocess
import sys
import tempfile
import threading
import time
import unittest
from pathlib import Path
from types import ModuleType, SimpleNamespace
from unittest import mock

from sentinel import optimizer
from sentinel.optimizer import changes, cleanup, measure, power, recommendations, scanning, startup
from sentinel.optimizer.models import ApplyResult, Snapshot, StartupItem


class FakeRegistry(ModuleType):
    """A small writable in-memory registry. tree: {(hive, path): {value name: data}}."""
    HKEY_CURRENT_USER, HKEY_LOCAL_MACHINE, KEY_SET_VALUE, REG_BINARY = "HKCU", "HKLM", 2, 3

    def __init__(self, tree=None):
        super().__init__("winreg")
        self.tree = tree if tree is not None else {}

    @staticmethod
    def _ctx(values):
        class Ctx:
            def __enter__(self):
                return values

            def __exit__(self, *a):
                return False
        return Ctx()

    def OpenKey(self, hive, path):
        if (hive, path) not in self.tree:
            raise FileNotFoundError(path)
        return self._ctx(self.tree[(hive, path)])

    def CreateKeyEx(self, hive, path, reserved, access):
        return self._ctx(self.tree.setdefault((hive, path), {}))

    def QueryValueEx(self, key, name):
        if name not in key:
            raise FileNotFoundError(name)
        return key[name], 3

    def SetValueEx(self, key, name, reserved, typ, data):
        key[name] = data

    def DeleteValue(self, key, name):
        if name not in key:
            raise FileNotFoundError(name)
        del key[name]

    def EnumValue(self, key, i):
        items = list(key.items())
        if i >= len(items):
            raise OSError("done")
        return items[i][0], items[i][1], 1


def registry(tree=None):
    reg = FakeRegistry(tree)
    return reg, mock.patch.dict(sys.modules, {"winreg": reg})


APPROVED = optimizer.APPROVED_BASE
RUN_PATH = APPROVED + r"\Run"


class HumanTests(unittest.TestCase):
    def test_sizes(self):
        self.assertEqual([optimizer.human(x) for x in (0, 1023, 1536, 5 << 20, 3 << 30)],
                         ["0 B", "1023 B", "1.5 KB", "5.0 MB", "3.0 GB"])


class StartupTests(unittest.TestCase):
    def test_state_reading(self):
        reg, patch = registry({("HKCU", RUN_PATH): {"On": b"\x02\x00", "Off": b"\x03\x00\x00\x00", "Empty": b""}})
        with patch:
            self.assertEqual(startup.get_startup_state("hkcu_run", "On"), (True, b"\x02\x00"))
            self.assertEqual(startup.get_startup_state("hkcu_run", "Off")[0], False)
            self.assertEqual(startup.get_startup_state("hkcu_run", "Empty")[0], True)
            self.assertEqual(startup.get_startup_state("hkcu_run", "Missing"), (True, None))
            self.assertEqual(startup.get_startup_state("startup_folder", "x"), (True, None))

    def test_disable_and_enable_round_trip(self):
        reg, patch = registry({("HKCU", RUN_PATH): {"App": b"\x02" + b"\x00" * 11}})
        with patch:
            res = startup.set_startup_enabled("hkcu_run", "App", False)
            self.assertTrue(res.ok)
            self.assertIn("no longer start", res.message)
            self.assertFalse(startup.get_startup_state("hkcu_run", "App")[0])
            res = startup.set_startup_enabled("hkcu_run", "App", True)
            self.assertIn("will start", res.message)

    def test_machine_wide_entries_are_refused(self):
        self.assertFalse(startup.set_startup_enabled("hklm_run", "x", False).ok)

    def test_failed_verification_rolls_back_to_the_original_value(self):
        original = b"\x02" + b"\x00" * 11
        reg, patch = registry({("HKCU", RUN_PATH): {"App": original}})
        with patch, mock.patch.object(startup, "get_startup_state", side_effect=[(True, original), (True, b"x")]):
            res = startup.set_startup_enabled("hkcu_run", "App", False)         # read-back still says "enabled"
        self.assertFalse(res.ok)
        self.assertIn("left as it was", res.message)
        self.assertEqual(reg.tree[("HKCU", RUN_PATH)]["App"], original)

    def test_rollback_that_also_fails_is_swallowed(self):
        reg, patch = registry({("HKCU", RUN_PATH): {"App": b"\x02"}})
        calls = []

        def write(source, name, raw, base):
            calls.append(raw)
            raise OSError("registry locked")
        with patch, mock.patch.object(startup, "_write_startup_raw", side_effect=write):
            res = startup.set_startup_enabled("hkcu_run", "App", False)
        self.assertFalse(res.ok)
        self.assertEqual(len(calls), 2)                                          # the write and the failed rollback

    def test_restore_original_with_and_without_a_recorded_value(self):
        reg, patch = registry({("HKCU", RUN_PATH): {"App": b"\x03" + b"\x00" * 11}})
        with patch:
            self.assertTrue(startup.restore_startup_original("hkcu_run", "App", "02" + "00" * 11).ok)
            self.assertEqual(reg.tree[("HKCU", RUN_PATH)]["App"], b"\x02" + b"\x00" * 11)
            self.assertTrue(startup.restore_startup_original("hkcu_run", "App", None).ok)          # delete
            self.assertTrue(startup.restore_startup_original("hkcu_run", "App", None).ok)          # already gone

    def test_listing_registry_and_folder_entries(self):
        folder = Path(tempfile.mkdtemp())
        self.addCleanup(shutil.rmtree, folder, True)
        startup_dir = folder / "Microsoft" / "Windows" / "Start Menu" / "Programs" / "Startup"
        startup_dir.mkdir(parents=True)
        (startup_dir / "shortcut.lnk").write_text("x")
        (startup_dir / "desktop.ini").write_text("x")
        reg, patch = registry({
            ("HKCU", startup.RUN_KEY): {"Mine": r'"C:\Apps\mine.exe" --tray'},
            ("HKLM", startup.RUN_KEY): {"Defender": r"C:\Program Files\Windows Defender\x.exe"},
        })
        with patch, mock.patch.dict(os.environ, {"APPDATA": str(folder)}), mock.patch.object(startup, "IS_WIN", True):
            items = startup.list_startup_items({os.path.normcase(r"c:\apps\mine.exe"): 42.0})
        by_name = {i.name: i for i in items}
        self.assertEqual(set(by_name), {"Mine", "Defender", "shortcut.lnk"})
        self.assertEqual(by_name["Mine"].running_mb, 42.0)
        self.assertTrue(by_name["Mine"].manageable and not by_name["Defender"].manageable)
        self.assertTrue(by_name["Defender"].protected)
        with mock.patch.object(startup, "IS_WIN", False):
            self.assertEqual(startup.list_startup_items(), [])


class ChangesTests(unittest.TestCase):
    def setUp(self):
        self.d = Path(tempfile.mkdtemp())
        self.addCleanup(shutil.rmtree, self.d, True)
        self.history = changes.History(self.d / "h.json")
        self.state = self.d / "state.json"
        patcher = mock.patch.object(changes, "_state_path", return_value=self.state)
        patcher.start()
        self.addCleanup(patcher.stop)

    def item(self, **kw):
        base = dict(name="App", command="app.exe", source="hkcu_run", enabled=True, protected=False, manageable=True)
        base.update(kw)
        return StartupItem(**base)

    def test_protected_or_machine_wide_entries_are_skipped(self):
        for bad in (self.item(protected=True), self.item(manageable=False)):
            self.assertFalse(changes.apply_startup_disable(bad, self.history).ok)
        self.assertEqual(self.history.pending(), [])

    def test_disable_is_recorded_so_it_can_be_undone(self):
        reg, patch = registry({("HKCU", RUN_PATH): {"App": b"\x02" + b"\x00" * 11}})
        with patch:
            self.assertTrue(changes.apply_startup_disable(self.item(), self.history).ok)
            entry = self.history.pending()[0]
            self.assertEqual(entry["kind"], "startup")
            self.assertTrue(changes.undo_entry(entry, self.history).ok)
            self.assertEqual(self.history.pending(), [])

    def test_failed_disable_leaves_no_history(self):
        with mock.patch.object(startup, "get_startup_state", return_value=(True, None)), \
                mock.patch.object(startup, "set_startup_enabled", return_value=ApplyResult(False, "nope")):
            self.assertFalse(changes.apply_startup_disable(self.item(), self.history).ok)
        self.assertEqual(self.history.all(), [])

    def test_applying_the_already_active_plan_only_relabels_the_profile(self):
        with mock.patch.object(power, "active_plan", return_value=(optimizer.PLAN_BALANCED, "Balanced")):
            self.assertTrue(changes.apply_profile("workspace", self.history).ok)          # shares the Balanced plan
            self.assertEqual(changes.get_state()["active_profile"], "workspace")
            self.assertTrue(changes.apply_profile("workspace", self.history).ok)          # nothing left to change
        self.assertEqual(self.history.pending(), [])

    def test_switching_and_failing(self):
        plan = {"now": (optimizer.PLAN_BALANCED, "Balanced")}
        with mock.patch.object(power, "active_plan", side_effect=lambda: plan["now"]), \
                mock.patch.object(power, "set_active_plan", return_value=ApplyResult(False, "refused")):
            self.assertFalse(changes.apply_profile("gaming", self.history).ok)
        self.assertEqual(self.history.pending(), [])

    def test_undo_power_and_unknown_kinds_and_errors(self):
        with mock.patch.object(power, "set_active_plan", return_value=ApplyResult(True, "ok")):
            entry = {"id": self.history.add("power", "t", {}, {"guid": "g", "profile": "balanced"}, {}),
                     "kind": "power", "original": {"guid": "g", "profile": "balanced"}, "title": "t"}
            self.assertTrue(changes.undo_entry(entry, self.history).ok)
            self.assertEqual(changes.get_state()["active_profile"], "balanced")
        no_plan = {"id": "x", "kind": "power", "original": {}, "title": "t"}
        self.assertEqual(changes.undo_entry(no_plan, self.history).message, "No earlier plan was recorded.")
        self.assertIn("cannot be restored", changes.undo_entry({"id": "x", "kind": "weird", "title": "t"}, self.history).message)
        boom = {"id": "x", "kind": "startup", "title": "t", "target": {"source": "hkcu_run", "name": "n"}, "original": {}}
        with mock.patch.object(startup, "restore_startup_original", side_effect=OSError("denied")):
            self.assertEqual(changes.undo_entry(boom, self.history), ApplyResult(False, "denied"))

    def test_undo_all_goes_newest_first(self):
        a = self.history.add("weird", "first", {}, {}, {})
        b = self.history.add("weird", "second", {}, {}, {})
        self.assertNotEqual(a, b)
        results = changes.undo_all(self.history)
        self.assertEqual([t for t, _ in results], ["second", "first"])

    def test_current_profile_follows_the_live_plan(self):
        with mock.patch.object(power, "active_plan", return_value=(optimizer.PLAN_HIGH, "High")):
            changes._save_state({"active_profile": "gaming"})
            self.assertEqual(changes.current_profile(), "gaming")
            changes._save_state({"active_profile": "eco"})                                 # stale label
            self.assertEqual(changes.current_profile(), "gaming")
        with mock.patch.object(power, "active_plan", return_value=("custom-guid", "Custom")):
            self.assertIsNone(changes.current_profile())
        with mock.patch.object(power, "active_plan", return_value=(None, "Unknown")):
            self.assertIsNone(changes.current_profile())

    def test_profile_support_and_corrupt_state(self):
        self.assertEqual(changes.profile_support("gaming", [(optimizer.PLAN_HIGH, "x", False)]), (True, ""))
        ok, why = changes.profile_support("gaming", [])
        self.assertFalse(ok)
        self.assertIn("isn't available", why)
        with mock.patch.object(power, "available_plans", return_value=[(optimizer.PLAN_HIGH, "x", False)]):
            self.assertTrue(changes.profile_support("gaming")[0])
        self.state.write_text("{broken")
        self.assertEqual(changes.get_state(), {})
        self.history.path.write_text("{broken")
        self.assertEqual(self.history.all(), [])


class PowerTests(unittest.TestCase):
    def test_powercfg_wrapper(self):
        with mock.patch.object(power.subprocess, "run", return_value=SimpleNamespace(stdout=" out \n")):
            self.assertEqual(power._powercfg("/list"), "out")
        for err in (OSError("missing"), subprocess.TimeoutExpired("powercfg", 1)):
            with mock.patch.object(power.subprocess, "run", side_effect=err):
                self.assertEqual(power._powercfg("/list"), "")

    def test_listing_and_the_active_plan(self):
        text = (f"Power Scheme GUID: {optimizer.PLAN_BALANCED}  (Balanced) *\n"
                f"Power Scheme GUID: {optimizer.PLAN_HIGH}  (High performance)\nnoise\n")
        with mock.patch.object(power, "IS_WIN", True), mock.patch.object(power, "_powercfg", return_value=text):
            self.assertEqual(power.active_plan(), (optimizer.PLAN_BALANCED, "Balanced"))
        only_active = f"Power Scheme GUID: {optimizer.PLAN_SAVER}  (Power saver)"
        with mock.patch.object(power, "IS_WIN", True), \
                mock.patch.object(power, "_powercfg", side_effect=lambda *a: "" if a[0] == "/list" else only_active):
            self.assertEqual(power.active_plan(), (optimizer.PLAN_SAVER, "Power saver"))
        with mock.patch.object(power, "IS_WIN", True), mock.patch.object(power, "_powercfg", return_value=""):
            self.assertEqual(power.active_plan(), (None, "Unknown"))
        with mock.patch.object(power, "IS_WIN", False):
            self.assertEqual((power.list_power_plans(), power.active_plan()), ([], (None, "Unknown")))

    def test_plan_existence_off_windows_and_for_empty_guids(self):
        with mock.patch.object(power, "IS_WIN", False):
            self.assertFalse(power.plan_exists(optimizer.PLAN_HIGH))
        with mock.patch.object(power, "IS_WIN", True):
            self.assertFalse(power.plan_exists(""))

    def test_setting_a_plan_that_does_not_exist_or_is_refused(self):
        with mock.patch.object(power, "plan_exists", return_value=False):
            self.assertIn("isn't available", power.set_active_plan("guid").message)
        calls = []
        with mock.patch.object(power, "plan_exists", return_value=True), \
                mock.patch.object(power, "active_plan", return_value=("before", "Before")), \
                mock.patch.object(power, "_powercfg", side_effect=lambda *a: calls.append(a) or ""):
            res = power.set_active_plan("wanted")
        self.assertFalse(res.ok)
        self.assertEqual(calls, [("/setactive", "wanted"), ("/setactive", "before")])             # rolled back
        calls.clear()
        with mock.patch.object(power, "plan_exists", return_value=True), \
                mock.patch.object(power, "active_plan", return_value=(None, "Unknown")), \
                mock.patch.object(power, "_powercfg", side_effect=lambda *a: calls.append(a) or ""):
            power.set_active_plan("wanted")
        self.assertEqual(calls, [("/setactive", "wanted")])                                       # nothing to roll back to
        with mock.patch.object(power, "plan_exists", return_value=True), \
                mock.patch.object(power, "active_plan", return_value=("wanted", "Wanted")), \
                mock.patch.object(power, "_powercfg", return_value=""):
            self.assertTrue(power.set_active_plan("wanted").ok)
        with mock.patch.object(power, "plan_exists", return_value=True), \
                mock.patch.object(power, "active_plan", return_value=("wanted", "Wanted")), \
                mock.patch.object(power, "_powercfg", return_value=""):
            self.assertFalse(power.set_active_plan("other").ok)                                   # before == now != guid


class CleanupTests(unittest.TestCase):
    def setUp(self):
        self.d = Path(tempfile.mkdtemp())
        self.addCleanup(shutil.rmtree, self.d, True)

    def old(self, path, data=b"x" * 10):
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_bytes(data)
        past = time.time() - 30 * 86400
        os.utime(path, (past, past))

    def test_roots_include_the_local_appdata_temp_once(self):
        with mock.patch.dict(os.environ, {"LOCALAPPDATA": str(self.d)}):
            (self.d / "Temp").mkdir()
            roots = cleanup.temp_roots()
        self.assertIn(self.d / "Temp", roots)
        with mock.patch.dict(os.environ, {"LOCALAPPDATA": ""}):
            self.assertTrue(cleanup.temp_roots())

    def test_walk_handles_errors_limits_symlinks_and_escapes(self):
        self.old(self.d / "a" / "old.tmp")
        self.old(self.d / "new.tmp")
        os.utime(self.d / "new.tmp", None)
        found = list(cleanup._eligible_temp_files([self.d]))
        self.assertEqual([os.path.basename(p) for p, _ in found], ["old.tmp"])
        self.assertEqual(list(cleanup._eligible_temp_files([self.d], limit=0)), [])
        with mock.patch.object(cleanup.os, "scandir", side_effect=OSError("denied")):
            self.assertEqual(list(cleanup._eligible_temp_files([self.d])), [])
        real_scandir = os.scandir

        class Entry:
            def __init__(self, e, kind):
                self.e, self.kind, self.path = e, kind, e.path

            def is_symlink(self):
                return self.kind == "link"

            def is_dir(self, follow_symlinks=True):
                return self.e.is_dir(follow_symlinks=False)

            def is_file(self, follow_symlinks=True):
                return self.e.is_file(follow_symlinks=False)

            def stat(self, follow_symlinks=True):
                if self.kind == "error":
                    raise OSError("vanished")
                return self.e.stat(follow_symlinks=False)

        class Listing:
            def __init__(self, path, kinds):
                self.entries = [Entry(e, kinds.get(e.name, "ok")) for e in real_scandir(path)]

            def __enter__(self):
                return self

            def __iter__(self):
                return iter(self.entries)

            def __exit__(self, *a):
                return False
        self.old(self.d / "link.tmp")
        self.old(self.d / "error.tmp")
        with mock.patch.object(cleanup.os, "scandir", side_effect=lambda p: Listing(p, {"link.tmp": "link", "error.tmp": "error"})):
            names = sorted(os.path.basename(p) for p, _ in cleanup._eligible_temp_files([self.d]))
        self.assertEqual(names, ["old.tmp"])
        outside = Path(tempfile.mkdtemp())
        self.addCleanup(shutil.rmtree, outside, True)
        self.old(outside / "far.tmp")
        with mock.patch.object(cleanup.os.path, "realpath", side_effect=lambda p: str(outside / "x") if "old.tmp" in str(p) else str(p)):
            names = [os.path.basename(p) for p, _ in cleanup._eligible_temp_files([self.d])]
        self.assertNotIn("old.tmp", names)

    def test_clean_counts_failures_and_honours_cancel(self):
        for i in range(3):
            self.old(self.d / f"f{i}.tmp")
        real_remove = os.remove

        def remove(p):
            if p.endswith("f1.tmp"):
                raise PermissionError("in use")
            real_remove(p)
        with mock.patch.object(cleanup.os, "remove", side_effect=remove):
            deleted, freed, skipped = cleanup.clean_temp([self.d])
        self.assertEqual((deleted, freed, skipped), (2, 20, 1))
        ev = threading.Event()
        ev.set()
        self.assertEqual(cleanup.clean_temp([self.d], cancel=ev)[0], 0)
        self.assertEqual(cleanup.estimate_temp([self.d]), (1, 10))


class FakePsutil:
    class Error(Exception):
        pass

    def __init__(self, procs=(), disk_error=False, counters=None):
        self.procs, self.disk_error, self._counters = list(procs), disk_error, counters

    def cpu_percent(self, interval=None):
        return 12.0

    def virtual_memory(self):
        return SimpleNamespace(total=100, available=40, percent=60.0)

    def disk_usage(self, path):
        if self.disk_error:
            raise OSError("no disk")
        return SimpleNamespace(percent=70.0, free=5)

    def pids(self):
        return [1, 2, 3]

    def cpu_count(self):
        return 4

    def process_iter(self, attrs=None):
        return iter(self.procs)

    def disk_io_counters(self):
        return self._counters.pop(0) if self._counters else None

    def Process(self, pid):
        return next(p for p in self.procs if p.pid == pid)


class FakeProc:
    def __init__(self, pid, name, rss=100, exe="", cpu=8.0, fail=False, io=(0, 0), io_fail=False):
        self.pid, self.fail, self._cpu, self.io, self.io_fail = pid, fail, cpu, io, io_fail
        self.info = {"pid": pid, "name": name, "exe": exe, "memory_info": SimpleNamespace(rss=rss) if rss else None}

    def cpu_percent(self, interval):
        if self.fail:
            raise FakePsutil.Error("gone")
        return self._cpu

    def io_counters(self):
        if self.io_fail:
            raise AttributeError("no io counters")
        return SimpleNamespace(read_bytes=self.io[0], write_bytes=self.io[1])


class MeasureTests(unittest.TestCase):
    def test_snapshot_variants(self):
        with mock.patch.object(measure, "psutil", None):
            self.assertEqual(measure.take_snapshot().cpu, 0.0)
        with mock.patch.object(measure, "psutil", FakePsutil()), mock.patch.object(measure, "IS_WIN", True), \
                mock.patch.object(measure.power, "active_plan", return_value=("g", "Balanced")):
            s = measure.take_snapshot(0)
        self.assertEqual((s.cpu, s.ram_used, s.disk_pct, s.process_count, s.power_plan), (12.0, 60, 70.0, 3, "Balanced"))
        with mock.patch.object(measure, "psutil", FakePsutil(disk_error=True)), mock.patch.object(measure, "IS_WIN", False):
            s = measure.take_snapshot(0)
        self.assertEqual((s.disk_pct, s.power_plan), (0.0, "n/a"))

    def test_windowed_pids(self):
        with mock.patch.object(measure, "IS_WIN", False):
            self.assertEqual(measure._windowed_pids(), set())
        self.assertIsInstance(measure._windowed_pids(), set)                          # real call on this PC

        def enum(proto, lp):
            raise OSError("enumeration failed")
        broken = SimpleNamespace(EnumWindows=enum)
        with mock.patch.object(measure, "IS_WIN", True), mock.patch.object(ctypes, "windll", SimpleNamespace(user32=broken), create=True):
            self.assertEqual(measure._windowed_pids(), set())

    def test_window_callback_collects_visible_titled_windows(self):
        seen = {}

        def enum(proto, lp):
            for hwnd in (1, 2, 3):
                proto(hwnd, 0)
        user32 = SimpleNamespace(
            IsWindowVisible=lambda h: h != 2, GetWindowTextLengthW=lambda h: 0 if h == 3 else 5,
            GetWindowThreadProcessId=lambda h, ref: setattr(ref._obj, "value", 100 + h), EnumWindows=enum)
        with mock.patch.object(measure, "IS_WIN", True), mock.patch.object(ctypes, "windll", SimpleNamespace(user32=user32), create=True), \
                mock.patch.object(ctypes, "WINFUNCTYPE", lambda *a: (lambda fn: fn), create=True):
            seen["pids"] = measure._windowed_pids()
        self.assertEqual(seen["pids"], {101})

    def test_system_paths(self):
        with mock.patch.dict(os.environ, {"SystemRoot": r"C:\Windows"}):
            self.assertTrue(measure._is_system_path(r"C:\Windows\System32\a.exe"))
            self.assertTrue(measure._is_system_path(r"D:\Program Files\Windows Defender\x.exe"))
            self.assertFalse(measure._is_system_path(r"C:\Apps\a.exe"))
            self.assertFalse(measure._is_system_path(None))

    def test_process_groups(self):
        me = os.getpid()
        procs = [FakeProc(1, "chrome.exe", rss=300, cpu=8), FakeProc(2, "Chrome.exe", rss=200, cpu=4),
                 FakeProc(me, "self.exe"), FakeProc(3, "svchost.exe", rss=50), FakeProc(4, "gone.exe", fail=True),
                 FakeProc(5, None, rss=0)]
        fake = FakePsutil(procs)
        fake.Error = FakePsutil.Error
        with mock.patch.object(measure, "psutil", fake), mock.patch.object(measure.time, "sleep"), \
                mock.patch.object(measure, "_windowed_pids", return_value={1}):
            groups = measure.measure_process_groups(0)
        by = {g.name.lower(): g for g in groups}
        self.assertEqual(by["chrome.exe"].count, 2)
        self.assertEqual(by["chrome.exe"].rss, 500)
        self.assertTrue(by["chrome.exe"].windowed)
        self.assertTrue(by["svchost.exe"].protected)
        self.assertIn("?", by)
        self.assertNotIn("self.exe", by)
        self.assertEqual(groups[0].name.lower(), "chrome.exe")
        ev = threading.Event()
        fake.procs = []
        with mock.patch.object(measure, "psutil", fake), mock.patch.object(measure, "_windowed_pids", return_value=set()):
            ev.set()
            self.assertEqual(measure.measure_process_groups(5, cancel=ev), [])
        with mock.patch.object(measure, "psutil", None):
            self.assertEqual(measure.measure_process_groups(), [])

    def test_disk_throughput(self):
        c = lambda r, w: SimpleNamespace(read_bytes=r, write_bytes=w)  # noqa: E731
        with mock.patch.object(measure, "psutil", None):
            self.assertIsNone(measure.disk_throughput())
        with mock.patch.object(measure, "psutil", FakePsutil(counters=[c(0, 0), c(1048576 * 2, 1048576 * 2)])), \
                mock.patch.object(measure.time, "sleep"):
            self.assertEqual(measure.disk_throughput(1.0), 4.0)
        with mock.patch.object(measure, "psutil", FakePsutil(counters=[None])):
            self.assertIsNone(measure.disk_throughput())
        ev = threading.Event()
        ev.set()
        with mock.patch.object(measure, "psutil", FakePsutil(counters=[c(0, 0), c(0, 0)])):
            self.assertEqual(measure.disk_throughput(1.0, cancel=ev), 0.0)
        fake = FakePsutil(counters=[c(0, 0)])
        fake.Error = FakePsutil.Error
        with mock.patch.object(measure, "psutil", fake), mock.patch.object(measure.time, "sleep"):
            self.assertIsNone(measure.disk_throughput(1.0))                           # second read returns None -> error

    def test_top_disk_writers(self):
        mb = 1048576
        procs = [FakeProc(1, "writer.exe", io=(0, 0)), FakeProc(2, "idle.exe", io=(0, 0)), FakeProc(3, "noio.exe", io_fail=True)]
        fake = FakePsutil(procs)
        fake.Error = FakePsutil.Error
        after = {1: (0, 10 * mb), 2: (0, 0)}

        class Reader(FakeProc):
            pass
        original = FakeProc.io_counters

        def io_counters(proc):
            if getattr(proc, "_second", False) and proc.pid in after:
                return SimpleNamespace(read_bytes=after[proc.pid][0], write_bytes=after[proc.pid][1])
            return original(proc)
        with mock.patch.object(measure, "psutil", fake), mock.patch.object(measure.time, "sleep"), \
                mock.patch.object(FakeProc, "io_counters", io_counters):
            def process(pid):
                p = next(x for x in procs if x.pid == pid)
                p._second = True
                if pid == 2:
                    raise FakePsutil.Error("exited")
                return p
            fake.Process = process
            top = measure.top_disk_writers(1.0, n=5)
        self.assertEqual([(n, round(v)) for n, v in top], [("writer.exe", 10)])
        with mock.patch.object(measure, "psutil", None):
            self.assertEqual(measure.top_disk_writers(), [])
        ev = threading.Event()
        ev.set()
        fake2 = FakePsutil([])
        fake2.Error = FakePsutil.Error
        with mock.patch.object(measure, "psutil", fake2):
            self.assertEqual(measure.top_disk_writers(5, cancel=ev), [])


class RecommendationTests(unittest.TestCase):
    def hw(self, **kw):
        base = {"cpu": {"name": "CPU"}, "ram": {"total": 16 << 30, "modules": 2}, "gpus": [], "disks": [],
                "form_factor": "desktop"}
        base.update(kw)
        return base

    def recs(self, hw, snap=None, live=None, key=None, plans=()):
        snap = snap or Snapshot(cpu=10, ram_total=16 << 30, ram_used=4 << 30, ram_pct=25, disk_pct=40, disk_free=100 << 30)
        return {r.key: r for r in recommendations.hardware_recommendations(hw, snap, live or {}, key, list(plans))}

    def test_no_hardware_no_hardware_advice(self):
        self.assertEqual(recommendations.hardware_recommendations({}, Snapshot(), {}, None), [])

    def test_memory_cpu_and_disk_rules(self):
        small = self.recs(self.hw(ram={"total": 8 << 30, "modules": 1}),
                          Snapshot(cpu=90, ram_total=8 << 30, ram_used=6 << 30, ram_pct=75, disk_pct=90, disk_free=1 << 30))
        for key in ("hw:ram-small", "hw:single-channel", "hw:cpu-busy", "hw:disk-full"):
            self.assertIn(key, small)
        pressure = self.recs(self.hw(), Snapshot(ram_total=16 << 30, ram_used=15 << 30, ram_pct=95))
        self.assertIn("hw:ram-pressure", pressure)
        self.assertNotIn("hw:ram-small", pressure)
        bad = self.recs(self.hw(disks=[{"name": "D0", "health": "Warning", "status": "OK", "type": "HDD"},
                                       {"name": "D1", "health": "Healthy", "type": "SSD"}]))
        self.assertIn("hw:disk-health:D0", bad)
        self.assertIn("hw:hdd", bad)
        self.assertNotIn("hw:disk-health:D1", bad)

    def test_gpu_rules(self):
        hybrid = self.recs(self.hw(gpus=[{"name": "Intel UHD", "vram": None}, {"name": "NVIDIA RTX 4060", "vram": 8 << 30}]))
        self.assertIn("hw:hybrid-gpu", hybrid)
        self.assertIn("video memory", hybrid["hw:hybrid-gpu"].issue)
        integrated = self.recs(self.hw(gpus=[{"name": "Intel UHD"}]))
        self.assertIn("hw:igpu-only", integrated)
        no_vram = self.recs(self.hw(gpus=[{"name": "Intel UHD"}, {"name": "GeForce GTX"}]))
        self.assertNotIn("video memory", no_vram["hw:hybrid-gpu"].issue)

    def test_power_rules(self):
        guids = [(optimizer.PLAN_BALANCED, "", False), (optimizer.PLAN_SAVER, "", False)]
        laptop = self.hw(form_factor="laptop")
        gaming = self.recs(laptop, live={"on_ac": False, "battery_pct": 80}, key="gaming", plans=guids)
        self.assertTrue(gaming["hw:battery-gaming"].actionable)
        self.assertIn("hw:thermal", gaming)
        no_balanced = self.recs(laptop, live={"on_ac": False, "battery_pct": 80}, key="gaming", plans=[])
        self.assertFalse(no_balanced["hw:battery-gaming"].actionable)
        low = self.recs(laptop, live={"on_ac": False, "battery_pct": 20}, key="balanced", plans=guids)
        self.assertIn("hw:battery-low", low)
        self.assertNotIn("hw:battery-low", self.recs(laptop, live={"on_ac": False, "battery_pct": 20}, key="eco", plans=guids))
        desktop = self.recs(self.hw(), key="eco", plans=guids)
        self.assertIn("hw:desktop-saver", desktop)

    def test_build_recommendations_covers_startup_background_memory_and_temp(self):
        mk = lambda **kw: StartupItem(**{**dict(name="A", command="a.exe", source="hkcu_run", enabled=True, protected=False,  # noqa: E731
                                                  manageable=True), **kw})
        startup_items = [mk(), mk(name="B", source="hklm_run", manageable=False, running_mb=12.0), mk(name="Off", enabled=False),
                         mk(name="Prot", protected=True)]
        MB = 1048576
        groups = [SimpleNamespace(name="Bg", count=2, rss=200 * MB, cpu=1.0, windowed=False, protected=False),
                  SimpleNamespace(name="Busy", count=1, rss=1 * MB, cpu=9.0, windowed=False, protected=False),
                  SimpleNamespace(name="Safe", count=1, rss=900 * MB, cpu=9.0, windowed=False, protected=True),
                  SimpleNamespace(name="Big", count=3, rss=900 * MB, cpu=1.0, windowed=True, protected=False),
                  SimpleNamespace(name="Small", count=1, rss=1 * MB, cpu=0.1, windowed=False, protected=False)]
        recs, protected = recommendations.build_recommendations(startup_items, groups, (5, 60 * MB), {}, Snapshot(), {}, None, [])
        keys = [r.key for r in recs]
        self.assertEqual(protected, 1)
        self.assertEqual(sum(k.startswith("startup:") for k in keys), 2)
        for expected in ("bg:bg", "bg:busy", "mem:big", "temp"):
            self.assertIn(expected, keys)
        self.assertNotIn("bg:safe", keys)
        self.assertTrue(recs[0].actionable)                                           # actionable items sort first
        deep, _ = recommendations.build_recommendations([], [SimpleNamespace(name="Mid", count=1, rss=120 * MB, cpu=0, windowed=False, protected=False)],
                                                        None, None, Snapshot(), {}, None, [], deep=True)
        self.assertEqual([r.key for r in deep], ["bg:mid"])


class RemainingBranchTests(unittest.TestCase):
    def test_marking_one_of_several_history_entries(self):
        d = Path(tempfile.mkdtemp())
        self.addCleanup(shutil.rmtree, d, True)
        history = changes.History(d / "h.json")
        first = history.add("x", "one", {}, {}, {})
        second = history.add("x", "two", {}, {}, {})
        history.mark_restored(second)
        self.assertEqual([i["id"] for i in history.pending()], [first])

    def test_special_files_in_temp_are_ignored(self):
        d = Path(tempfile.mkdtemp())
        self.addCleanup(shutil.rmtree, d, True)
        entry = SimpleNamespace(path=str(d / "pipe"), is_symlink=lambda: False, is_dir=lambda follow_symlinks=True: False,
                                is_file=lambda follow_symlinks=True: False)

        class Listing:
            def __enter__(self):
                return self

            def __iter__(self):
                return iter([entry])

            def __exit__(self, *a):
                return False
        with mock.patch.object(cleanup.os, "scandir", return_value=Listing()):
            self.assertEqual(list(cleanup._eligible_temp_files([d])), [])

    def test_process_that_vanishes_during_sampling_is_skipped(self):
        class Flaky(FakeProc):
            calls = 0

            def cpu_percent(self, interval):
                Flaky.calls += 1
                if Flaky.calls > 1:
                    raise FakePsutil.Error("exited while sampling")
                return 1.0
        fake = FakePsutil([Flaky(1, "flaky.exe")])
        fake.Error = FakePsutil.Error
        with mock.patch.object(measure, "psutil", fake), mock.patch.object(measure.time, "sleep"), \
                mock.patch.object(measure, "_windowed_pids", return_value=set()):
            self.assertEqual(measure.measure_process_groups(0), [])

    def test_missing_startup_folder_is_fine(self):
        reg, patch = registry({})
        with patch, mock.patch.dict(os.environ, {"APPDATA": r"C:\definitely\not\here"}), mock.patch.object(startup, "IS_WIN", True):
            self.assertEqual(startup.list_startup_items(), [])


class ScanOrchestrationTests(unittest.TestCase):
    def patched(self, **overrides):
        snap = Snapshot(cpu=5, ram_total=100, ram_used=50, ram_pct=50)
        defaults = dict(
            take_snapshot=lambda cpu_interval=1.0: snap,
            measure_process_groups=lambda sample, cancel=None: [],
            list_startup_items=lambda mb=None: [],
            available_plans=lambda: [],
            current_profile=lambda: None,
            disk_throughput=lambda s, c=None: 1.5,
            top_disk_writers=lambda s, c=None: [("x.exe", 2.0)],
            estimate_temp=lambda: (3, 30),
        )
        defaults.update(overrides)
        stack = [mock.patch.object(scanning, k, v) for k, v in defaults.items()]
        stack.append(mock.patch("sentinel.hardware.live_status", return_value={"on_ac": True, "battery_pct": None, "ram_available": 1}))
        stack.append(mock.patch("sentinel.hardware.get_profile", return_value={"gpus": []}))
        return stack

    def run_scan(self, kind="deep", progress=None, cancel=None, **overrides):
        stack = self.patched(**overrides)
        for p in stack:
            p.start()
            self.addCleanup(p.stop)
        scanning._temp_cache.clear()
        return scanning.scan(kind, progress=progress, cancel=cancel)

    def test_deep_scan_runs_every_part_and_reports_progress(self):
        events = []
        a = self.run_scan("deep", progress=lambda ev, name, partial: events.append((ev, name)))
        self.assertEqual(len(a.completed), 8)
        self.assertEqual((a.disk_mb_s, a.disk_top, a.temp_files), (1.5, [("x.exe", 2.0)], 3))
        self.assertIn(("start", "Per-app disk use"), events)
        self.assertEqual(sum(e == "done" for e, _ in events), 8)

    def test_quick_scan_skips_the_slow_parts_and_works_without_progress(self):
        a = self.run_scan("quick")
        self.assertEqual(len(a.completed), 4)
        self.assertIsNone(a.disk_mb_s)

    def test_a_failing_part_does_not_sink_the_scan(self):
        def boom(*a, **k):
            raise RuntimeError("counter exploded")
        a = self.run_scan("standard", disk_throughput=boom)
        self.assertIn("Disk activity", a.completed)
        self.assertIsNone(a.disk_mb_s)

    def test_cancelling_stops_waiting_for_slow_parts(self):
        ev = threading.Event()

        def slow(sample, cancel=None):
            ev.set()
            time.sleep(0.3)
            return []
        a = self.run_scan("standard", cancel=ev, measure_process_groups=slow)
        self.assertTrue(a.cancelled)

    def test_startup_part_sums_memory_per_program(self):
        seen = {}

        def list_items(mb=None):
            seen.update(mb or {})
            return []
        fake = FakePsutil([FakeProc(1, "a", rss=2 * 1048576, exe="C:/A/a.exe"), FakeProc(2, "a", rss=2 * 1048576, exe="C:/A/a.exe"),
                           FakeProc(3, "n", rss=0, exe=""), FakeProc(4, "x", rss=10, exe="C:/X/x.exe")])
        fake.Error = FakePsutil.Error

        class Broken:
            @property
            def info(self):
                raise FakePsutil.Error("gone")
        fake.procs.append(Broken())
        with mock.patch.object(scanning, "psutil", fake):
            self.run_scan("quick", list_startup_items=list_items)
        self.assertEqual(round(seen[os.path.normcase("C:/A/a.exe")]), 4)
        with mock.patch.object(scanning, "psutil", None):
            self.run_scan("quick", list_startup_items=list_items)

    def test_temp_estimate_is_cached_and_a_second_scan_is_refused(self):
        calls = []
        scanning._temp_cache.clear()
        with mock.patch.object(scanning, "estimate_temp", side_effect=lambda: calls.append(1) or (1, 2)):
            self.assertEqual(scanning.cached_temp_estimate(), (1, 2))
            self.assertEqual(scanning.cached_temp_estimate(), (1, 2))
            scanning.cached_temp_estimate(force=True)
        self.assertEqual(len(calls), 2)
        scanning._scan_lock.acquire()
        try:
            with self.assertRaises(scanning.ScanBusy):
                scanning.scan("quick")
        finally:
            scanning._scan_lock.release()

    def test_compare_wording(self):
        before = Snapshot(cpu=50, ram_total=100, ram_used=80)
        after = Snapshot(cpu=10, ram_total=100, ram_used=20)
        self.assertIn("Measured change: RAM -60.0 points, CPU -40 points", scanning.compare(before, after))
        worse = scanning.compare(after, before)
        self.assertIn("RAM +60.0", worse)


if __name__ == "__main__":
    unittest.main()
