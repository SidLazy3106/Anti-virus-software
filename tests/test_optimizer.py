"""Tests for Optimizer."""
import os
import shutil
import sys
import tempfile
import time
import unittest
from pathlib import Path


@unittest.skipUnless(sys.platform == "win32", "optimizer registry tests are Windows-only")
class OptimizerTests(unittest.TestCase):
    """All registry work happens under a scratch HKCU key, never the real StartupApproved or Run keys."""
    BASE = r"Software\XSecureTest\Approved"

    def setUp(self):
        from sentinel import optimizer
        self.opt = optimizer
        self.hist = optimizer.History(Path(tempfile.mkdtemp()) / "hist.json")

    def tearDown(self):
        import winreg

        def wipe(path):
            try:
                with winreg.OpenKey(winreg.HKEY_CURRENT_USER, path, 0,
                                    winreg.KEY_READ | winreg.KEY_WRITE) as k:
                    while True:
                        try:
                            wipe(path + "\\" + winreg.EnumKey(k, 0))
                        except OSError:
                            break
                winreg.DeleteKey(winreg.HKEY_CURRENT_USER, path)
            except OSError:
                pass
        wipe(r"Software\XSecureTest")

    def item(self, name="Spotify", protected=False, manageable=True, source="hkcu_run"):
        return self.opt.StartupItem(name=name, command=r'"C:\x\a.exe"', source=source, enabled=True,
                                    protected=protected, manageable=manageable)

    def test_disable_verify_and_exact_restore(self):
        o = self.opt
        r = o.apply_startup_disable(self.item(), self.hist, self.BASE)
        self.assertTrue(r.ok, r.message)
        self.assertFalse(o.get_startup_state("hkcu_run", "Spotify", self.BASE)[0])
        (entry,) = self.hist.pending()
        self.assertIsNone(entry["original"]["raw"])            # there was no value before
        self.assertTrue(o.undo_entry(entry, self.hist).ok)
        self.assertEqual(o.get_startup_state("hkcu_run", "Spotify", self.BASE), (True, None))  # value removed again
        self.assertEqual(self.hist.pending(), [])

    def test_restore_keeps_preexisting_value_byte_for_byte(self):
        o = self.opt
        original = b"\x02" + b"\x00" * 11
        o._write_startup_raw("hkcu_run", "Zoom", original, self.BASE)
        o.apply_startup_disable(self.item("Zoom"), self.hist, self.BASE)
        self.assertFalse(o.get_startup_state("hkcu_run", "Zoom", self.BASE)[0])
        o.undo_all(self.hist)
        self.assertEqual(o.get_startup_state("hkcu_run", "Zoom", self.BASE), (True, original))

    def test_protected_and_machine_wide_items_are_refused(self):
        o = self.opt
        self.assertFalse(o.apply_startup_disable(self.item("SecurityHealth", protected=True), self.hist,
                                                 self.BASE).ok)
        self.assertFalse(o.apply_startup_disable(self.item(manageable=False, source="hklm_run"), self.hist,
                                                 self.BASE).ok)
        self.assertEqual(self.hist.all(), [])                    # nothing recorded, nothing changed
        self.assertEqual(o.set_startup_enabled("hklm_run", "x", False, self.BASE).ok, False)

    def test_protection_rules(self):
        o = self.opt
        for name, cmd in (("SecurityHealth", "C:\\Windows\\System32\\SecurityHealthSystray.exe"),
                          ("Realtek HD Audio Manager", "C:\\x\\RtkNGUI64.exe"),
                          ("Windows Defender", ""), ("NVIDIA Display Driver", "x"),
                          ("X-Secure", "py main.py")):
            self.assertTrue(o.is_protected_startup(name, cmd), name)
        for name in ("Spotify", "Discord", "Steam", "Zoom"):
            self.assertFalse(o.is_protected_startup(name, r"C:\Users\u\AppData\Local\app.exe"), name)

    def test_parse_power_plans_any_language(self):
        text = ("Existing Power Schemes (* Active)\n-----------------------------------\n"
                "Power Scheme GUID: 381b4222-f694-41f0-9685-ff5bb260df2e  (Balanced) *\n"
                "Power Scheme GUID: a1841308-3541-4fab-bc81-f71556f20b4a  (Power saver)\n"
                "GUID du mode d'alimentation : 8c5e7fda-e8bf-4a96-9a85-a6e23a8c635c  (Performances elevees)\n")
        plans = self.opt.parse_power_plans(text)
        self.assertEqual([(g[:8], a) for g, _, a in plans], [("381b4222", True), ("a1841308", False),
                                                            ("8c5e7fda", False)])
        ok, why = self.opt.profile_support("gaming", plans)
        self.assertTrue(ok)
        ok, why = self.opt.profile_support("gaming", plans[:2])  # High performance hidden by Windows
        self.assertFalse(ok)
        self.assertIn("hidden", why)

    def test_hidden_builtin_plans_still_count_as_available(self):
        """Regression: on many PCs `powercfg /list` hides High performance / Power saver unless active. They still
        exist, so switching to them (and restoring them) must work."""
        from sentinel.optimizer import power
        o = self.opt
        listed = [(o.PLAN_BALANCED, "Balanced", True)]
        queried = []

        def fake_powercfg(*a):
            if a and a[0] == "/query":
                queried.append(a[1])
                return f"Power Scheme GUID: {a[1]}  (x)" if a[1] in (o.PLAN_HIGH, o.PLAN_SAVER) else "does not exist"
            return ""
        real = (power.list_power_plans, power._powercfg)
        power.list_power_plans, power._powercfg = (lambda: list(listed)), fake_powercfg
        power._exists_cache.clear()
        try:
            self.assertTrue(o.plan_exists(o.PLAN_HIGH))
            self.assertTrue(o.profile_support("gaming")[0])
            self.assertTrue(o.profile_support("eco")[0])
            self.assertFalse(o.plan_exists("00000000-1111-2222-3333-444444444444"))
            guids = {g for g, _, _ in o.available_plans()}
            self.assertEqual(guids, {o.PLAN_BALANCED, o.PLAN_HIGH, o.PLAN_SAVER})
            o.plan_exists(o.PLAN_HIGH)
            self.assertEqual(queried.count(o.PLAN_HIGH), 1)        # existence is cached, not re-queried
        finally:
            power.list_power_plans, power._powercfg = real
            power._exists_cache.clear()

    def test_power_switch_rolls_back_when_verification_fails(self):
        from sentinel.optimizer import power
        o = self.opt
        calls = []
        plans = [(o.PLAN_BALANCED, "Balanced", True), (o.PLAN_HIGH, "High", False)]
        real = (power.list_power_plans, power.active_plan, power._powercfg)
        power.list_power_plans, power.active_plan, power._powercfg = (
            lambda: plans, lambda: (o.PLAN_BALANCED, "Balanced"), lambda *a: calls.append(a) or "")
        try:
            r = power.set_active_plan(o.PLAN_HIGH)   # Windows "ignores" setactive: active plan never changes
        finally:
            power.list_power_plans, power.active_plan, power._powercfg = real
        self.assertFalse(r.ok)
        self.assertEqual(calls, [("/setactive", o.PLAN_HIGH), ("/setactive", o.PLAN_BALANCED)])

    def test_temp_cleanup_only_touches_old_files_inside_root(self):
        o = self.opt
        root = Path(tempfile.mkdtemp(prefix="xs_tmp_"))
        outside = Path(tempfile.mkdtemp(prefix="xs_keep_"))
        old, new = root / "old.tmp", root / "new.tmp"
        (root / "sub").mkdir()
        deep = root / "sub" / "deep.tmp"
        for f in (old, new, deep):
            f.write_bytes(b"x" * 1000)
        keep = outside / "important.docx"
        keep.write_bytes(b"do not delete")
        past = time.time() - 10 * 86400
        for f in (old, deep, keep):
            os.utime(f, (past, past))
        self.assertEqual(o.estimate_temp([root]), (2, 2000))
        deleted, freed, skipped = o.clean_temp([root])
        self.assertEqual((deleted, freed, skipped), (2, 2000, 0))
        self.assertFalse(old.exists() or deep.exists())
        self.assertTrue(new.exists() and keep.exists())          # recent file and files outside the root survive
        shutil.rmtree(root, ignore_errors=True)
        shutil.rmtree(outside, ignore_errors=True)

    def test_compare_is_honest_about_small_changes(self):
        o = self.opt
        a = o.Snapshot(cpu=10, ram_total=16 << 30, ram_used=8 << 30)
        b = o.Snapshot(cpu=12, ram_total=16 << 30, ram_used=int(7.8 * (1 << 30)))
        self.assertIn("No meaningful change", o.compare(a, b))
        c = o.Snapshot(cpu=10, ram_total=16 << 30, ram_used=6 << 30)
        self.assertIn("Measured change", o.compare(a, c))

    def test_history_persists_and_marks_restored(self):
        eid = self.hist.add("startup", "t", {}, {}, {})
        self.assertEqual(len(self.opt.History(self.hist.path).pending()), 1)
        self.hist.mark_restored(eid)
        self.assertEqual(self.hist.pending(), [])
        self.assertEqual(len(self.hist.all()), 1)                # kept for the audit trail
