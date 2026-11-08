"""Hardware detection edge cases: registry reads, PowerShell failures, profile building, caching and live status."""
import json
import subprocess
import sys
import unittest
from types import SimpleNamespace
from unittest import mock

from sentinel import config, hardware


class RegistryTests(unittest.TestCase):
    def test_reg_returns_none_when_missing_or_winreg_unavailable(self):
        self.assertIsNone(hardware._reg(r"SOFTWARE\XSecure\Definitely\Not\There", "x"))
        with mock.patch.dict(sys.modules, {"winreg": None}):                 # import fails -> ImportError
            self.assertIsNone(hardware._reg("x", "y"))

    def test_gpu_registry(self):
        with mock.patch.object(hardware, "IS_WIN", False):
            self.assertEqual(hardware._gpu_registry(), [])
        values = {
            ("0000", "DriverDesc"): "GPU A", ("0000", "HardwareInformation.qwMemorySize"): (4 << 30).to_bytes(8, "little"),
            ("0001", "DriverDesc"): "GPU B", ("0001", "HardwareInformation.qwMemorySize"): 1 << 30,
            ("0002", "DriverDesc"): "GPU C", ("0002", "HardwareInformation.qwMemorySize"): 0,
        }

        def fake_reg(path, name):
            return values.get((path[-4:], name))
        with mock.patch.object(hardware, "IS_WIN", True), mock.patch.object(hardware, "_reg", side_effect=fake_reg):
            got = hardware._gpu_registry()
        self.assertEqual(got, [("GPU A", 4 << 30), ("GPU B", 1 << 30), ("GPU C", None)])

    def test_quick_fingerprint_without_psutil_or_windows(self):
        with mock.patch.object(hardware, "IS_WIN", False), mock.patch.object(hardware, "psutil", None), \
                mock.patch.object(hardware, "_gpu_registry", return_value=[("G", None)]):
            fp = hardware.quick_fingerprint()
        self.assertEqual((fp["cpu"], fp["ram"], fp["gpus"]), (None, None, ["G"]))
        fake = SimpleNamespace(virtual_memory=lambda: SimpleNamespace(total=16), cpu_count=lambda logical: 8 if logical else 4)
        with mock.patch.object(hardware, "psutil", fake), mock.patch.object(hardware, "_gpu_registry", return_value=[]):
            fp = hardware.quick_fingerprint()
        self.assertEqual((fp["ram"], fp["cores"], fp["threads"]), (16, 4, 8))


class PowerShellTests(unittest.TestCase):
    def test_run_ps(self):
        with mock.patch.object(hardware, "IS_WIN", False):
            self.assertEqual(hardware._run_ps(), {})
        with mock.patch.object(hardware, "IS_WIN", True):
            for out, expected in (('{"cpu": 1}', {"cpu": 1}), ("  ", {}), ("not json", {})):
                with mock.patch.object(hardware.subprocess, "run", return_value=SimpleNamespace(stdout=out)):
                    self.assertEqual(hardware._run_ps(), expected)
            for err in (OSError("no powershell"), subprocess.TimeoutExpired("ps", 1)):
                with mock.patch.object(hardware.subprocess, "run", side_effect=err):
                    self.assertEqual(hardware._run_ps(), {})


class BuildProfileTests(unittest.TestCase):
    FP = {"cpu": "Fallback CPU", "cores": 4, "threads": 8, "ram": 16 << 30}

    def build(self, ps, registry=()):
        with mock.patch.object(hardware, "_gpu_registry", return_value=list(registry)):
            return hardware.build_profile(ps, self.FP)

    def test_gpus_prefer_registry_memory_then_adapter_ram_then_registry_only(self):
        ps = {"gpu": [{"Name": "RTX", "AdapterRAM": 1, "CurrentRefreshRate": 144, "DriverVersion": "1"},
                      {"Name": "Intel", "AdapterRAM": 2 << 30}, {"Name": "Basic"}]}
        prof = self.build(ps, [("RTX", 8 << 30)])
        rtx, intel, basic = prof["gpus"]
        self.assertEqual((rtx["vram"], rtx["vram_approx"], rtx["refresh_hz"]), (8 << 30, False, 144))
        self.assertEqual((intel["vram"], intel["vram_approx"]), (2 << 30, True))
        self.assertIsNone(basic["vram"])
        only_registry = self.build({}, [("From registry", 1 << 30)])
        self.assertEqual(only_registry["gpus"][0]["name"], "From registry")

    def test_disks_chassis_memory_and_cpu_fallbacks(self):
        ps = {"disks": [{"FriendlyName": "A", "MediaType": "SSD", "HealthStatus": "Healthy"},
                        {"FriendlyName": "B", "MediaType": "Unspecified", "BusType": "17"},
                        {"FriendlyName": "C", "MediaType": 4, "BusType": 3}],
              "chassis": [3, "x"], "mem": [{"ConfiguredClockSpeed": 3200}, {"Speed": 2666}, {}], "cpu": {"Name": " Ryzen "}}
        prof = self.build(ps)
        self.assertEqual([d["type"] for d in prof["disks"]], ["SSD", "SSD", None])
        self.assertEqual(prof["form_factor"], "desktop")
        self.assertEqual((prof["ram"]["modules"], prof["ram"]["speed_mhz"]), (3, 3200))
        self.assertEqual((prof["cpu"]["name"], prof["cpu"]["cores"], prof["cpu"]["threads"]), ("Ryzen", 4, 8))
        self.assertEqual(self.build({"chassis": 10})["form_factor"], "laptop")
        empty = self.build({})
        self.assertEqual((empty["form_factor"], empty["ram"]["modules"], empty["cpu"]["name"]), (None, None, "Fallback CPU"))


class ProfileCacheTests(unittest.TestCase):
    def setUp(self):
        config.ensure_dirs()
        self.path = hardware._profile_path()
        self.backup = self.path.read_bytes() if self.path.exists() else None

        def restore():
            if self.backup is None:
                self.path.unlink(missing_ok=True)
            else:
                self.path.write_bytes(self.backup)
        self.addCleanup(restore)
        self.path.unlink(missing_ok=True)
        self.fp = {"os_build": "x"}
        patcher = mock.patch.object(hardware, "quick_fingerprint", side_effect=lambda: dict(self.fp))
        patcher.start()
        self.addCleanup(patcher.stop)
        self.queries = []

    def query(self):
        self.queries.append(1)
        return {"chassis": [10]}

    def test_cache_is_used_until_forced_or_the_fingerprint_changes(self):
        self.assertIsNone(hardware.load_cached())
        first = hardware.get_profile(query=self.query)
        self.assertEqual((first["from_cache"], first["changed"]), (False, False))
        second = hardware.get_profile(query=self.query)
        self.assertTrue(second["from_cache"])
        self.assertEqual(len(self.queries), 1)
        hardware.get_profile(force=True, query=self.query)
        self.fp = {"os_build": "y"}
        changed = hardware.get_profile(query=self.query)
        self.assertTrue(changed["changed"])
        self.assertEqual(len(self.queries), 3)
        self.path.write_text("{broken")
        self.assertIsNone(hardware.load_cached())

    def test_unwritable_cache_does_not_break_detection(self):
        with mock.patch.object(hardware.config, "ensure_dirs", side_effect=OSError("read-only")):
            prof = hardware.get_profile(query=self.query)
        self.assertEqual(prof["form_factor"], "laptop")


class LiveStatusTests(unittest.TestCase):
    def fake(self, battery=None, error=None):
        def sensors():
            if error:
                raise error
            return battery
        return SimpleNamespace(virtual_memory=lambda: SimpleNamespace(available=1234), sensors_battery=sensors,
                               Error=RuntimeError)

    def test_battery_variants(self):
        with mock.patch.object(hardware, "psutil", self.fake(SimpleNamespace(percent=41.6, power_plugged=False))):
            self.assertEqual(hardware.live_status(), {"ram_available": 1234, "battery_pct": 42, "on_ac": False})
        with mock.patch.object(hardware, "psutil", self.fake(None)):
            self.assertIsNone(hardware.live_status()["battery_pct"])
        with mock.patch.object(hardware, "psutil", self.fake(error=AttributeError("no sensor"))):
            self.assertIsNone(hardware.live_status()["battery_pct"])
        with mock.patch.object(hardware, "psutil", None):
            self.assertEqual(hardware.live_status()["ram_available"], None)

    def test_laptop_detection_falls_back_to_the_battery(self):
        self.assertTrue(hardware.is_laptop({"form_factor": "laptop"}))
        self.assertFalse(hardware.is_laptop({"form_factor": "desktop"}))
        with mock.patch.object(hardware, "live_status", return_value={"battery_pct": 50}):
            self.assertTrue(hardware.is_laptop({}))
        with mock.patch.object(hardware, "live_status", return_value={"battery_pct": None}):
            self.assertFalse(hardware.is_laptop({}))

    def test_small_helpers(self):
        self.assertEqual(hardware.system_disk_type({"disks": [{"type": None}, {"type": "HDD"}]}), "HDD")
        self.assertIsNone(hardware.system_disk_type({}))
        self.assertEqual((hardware.gb(1 << 30), hardware.gb(None)), ("1.0 GB", "Not available"))
        self.assertEqual(json.loads(json.dumps(hardware._as_list(None))), [])

    def test_reduced_motion(self):
        with mock.patch.object(hardware, "IS_WIN", False):
            self.assertFalse(hardware.reduced_motion())

        def spi(action, _u, flag_ref, _w, value=0):
            flag_ref._obj.value = value
            return 1
        for value, expected in ((0, True), (1, False)):
            user32 = SimpleNamespace(SystemParametersInfoW=lambda a, u, f, w, v=value: spi(a, u, f, w, v))
            with mock.patch.object(hardware, "IS_WIN", True), \
                    mock.patch("ctypes.windll", SimpleNamespace(user32=user32), create=True):
                self.assertEqual(hardware.reduced_motion(), expected)
        with mock.patch.object(hardware, "IS_WIN", True), mock.patch("ctypes.windll", SimpleNamespace(), create=True):
            self.assertFalse(hardware.reduced_motion())


if __name__ == "__main__":
    unittest.main()
