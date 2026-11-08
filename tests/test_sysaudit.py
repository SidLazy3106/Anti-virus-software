"""Tests for the system audit: parsers, every check (with Windows/PowerShell replaced by fakes) and the score."""
import os
import shutil
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path
from types import ModuleType, SimpleNamespace
from unittest import mock

from sentinel import sysaudit
from sentinel.sysaudit import Finding


class AuditHelperTests(unittest.TestCase):
    def test_parse_hosts(self):
        from sentinel.sysaudit import parse_hosts
        txt = "# comment\n127.0.0.1 localhost\n0.0.0.0 update.microsoft.com  # blocked\n\n"
        self.assertEqual(parse_hosts(txt), [("127.0.0.1", "localhost"), ("0.0.0.0", "update.microsoft.com")])

    def test_unquoted_service_path(self):
        from sentinel.sysaudit import is_unquoted_service_path as f
        self.assertTrue(f(r"C:\Program Files\App\svc.exe -k run"))
        self.assertFalse(f(r'"C:\Program Files\App\svc.exe" -k run'))
        self.assertFalse(f(r"C:\Windows\system32\svchost.exe -k netsvcs"))
        self.assertFalse(f(""))


class FakeWinreg(ModuleType):
    """A tiny in-memory registry: tree maps key path -> {"values": {name: data}, "subkeys": [names]}."""
    HKEY_CURRENT_USER, HKEY_LOCAL_MACHINE = "HKCU", "HKLM"

    def __init__(self, tree):
        super().__init__("winreg")
        self.tree = tree

    def _node(self, hive, path):
        node = self.tree.get((hive, path))
        if node is None:
            raise FileNotFoundError(path)
        return node

    def OpenKey(self, hive, path):
        node = self._node(hive, path)

        class Ctx:
            def __enter__(self_inner):
                return (hive, path, node)

            def __exit__(self_inner, *a):
                return False
        return Ctx()

    def QueryValueEx(self, key, name):
        values = key[2]["values"]
        if name not in values:
            raise FileNotFoundError(name)
        return values[name], 1

    def EnumValue(self, key, i):
        items = list(key[2]["values"].items())
        if i >= len(items):
            raise OSError("no more")
        name, val = items[i]
        return name, val, 1

    def EnumKey(self, key, i):
        subs = key[2].get("subkeys", [])
        if i >= len(subs):
            raise OSError("no more")
        return subs[i]


def with_registry(tree):
    return mock.patch.dict(sys.modules, {"winreg": FakeWinreg(tree)})


RUN = r"Software\Microsoft\Windows\CurrentVersion\Run"
RUNONCE = r"Software\Microsoft\Windows\CurrentVersion\RunOnce"
POLICY = r"SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System"
TS = r"SYSTEM\CurrentControlSet\Control\Terminal Server"
LANMAN = r"SYSTEM\CurrentControlSet\Services\LanmanServer\Parameters"
WIN = r"SOFTWARE\Microsoft\Windows NT\CurrentVersion"
IFEO = WIN + r"\Image File Execution Options"


def titles(findings):
    return [f.title for f in findings]


class RunnerTests(unittest.TestCase):
    def test_run_returns_stdout_and_ps_json_handles_failures(self):
        done = SimpleNamespace(stdout=" out \n")
        with mock.patch.object(sysaudit.subprocess, "run", return_value=done):
            self.assertEqual(sysaudit._run(["x"]), "out")
        with mock.patch.object(sysaudit.subprocess, "run", return_value=SimpleNamespace(stdout=None)):
            self.assertEqual(sysaudit._run(["x"]), "")
        with mock.patch.object(sysaudit, "_run", return_value='{"a": 1}'):
            self.assertEqual(sysaudit._ps_json("s"), {"a": 1})
        with mock.patch.object(sysaudit, "_run", return_value=""):
            self.assertIsNone(sysaudit._ps_json("s"))
        for err in (OSError("no powershell"), ValueError("bad json"), subprocess.TimeoutExpired("x", 1)):
            with mock.patch.object(sysaudit, "_run", side_effect=err):
                self.assertIsNone(sysaudit._ps_json("s"))

    def test_reg_value(self):
        tree = {("HKLM", "k"): {"values": {"v": 5}}}
        with with_registry(tree):
            self.assertEqual(sysaudit._reg_value("HKLM", "k", "v"), 5)
            self.assertIsNone(sysaudit._reg_value("HKLM", "k", "missing"))
            self.assertIsNone(sysaudit._reg_value("HKLM", "nokey", "v"))


class HardeningTests(unittest.TestCase):
    def test_firewall(self):
        with mock.patch.object(sysaudit, "_ps_json", return_value=None):
            self.assertEqual(sysaudit.check_firewall()[0].severity, "info")
        on = [{"Name": "Domain", "Enabled": True}]
        with mock.patch.object(sysaudit, "_ps_json", return_value=on):
            self.assertEqual(sysaudit.check_firewall(), [])
        off = {"Name": "Public", "Enabled": False}                         # a single profile arrives as a dict
        with mock.patch.object(sysaudit, "_ps_json", return_value=off):
            f = sysaudit.check_firewall()
        self.assertEqual((f[0].severity, "Public" in f[0].title), ("high", True))

    def test_defender(self):
        with mock.patch.object(sysaudit, "_ps_json", return_value=None):
            self.assertIn("unavailable", sysaudit.check_defender()[0].title)
        data = {"RealTimeProtectionEnabled": False, "AntivirusSignatureAge": 9}
        with mock.patch.object(sysaudit, "_ps_json", return_value=data):
            found = sysaudit.check_defender()
        self.assertEqual([f.severity for f in found], ["high", "medium"])
        healthy = {"RealTimeProtectionEnabled": True, "AntivirusSignatureAge": 1}
        with mock.patch.object(sysaudit, "_ps_json", return_value=healthy):
            self.assertEqual(sysaudit.check_defender(), [])

    def test_registry_settings(self):
        bad = {("HKLM", POLICY): {"values": {"EnableLUA": 0}}, ("HKLM", TS): {"values": {"fDenyTSConnections": 0}},
               ("HKLM", LANMAN): {"values": {"SMB1": 1}}}
        with with_registry(bad):
            found = sysaudit.check_registry_settings()
        self.assertEqual(len(found), 3)
        good = {("HKLM", POLICY): {"values": {"EnableLUA": 1}}, ("HKLM", TS): {"values": {"fDenyTSConnections": 1}},
                ("HKLM", LANMAN): {"values": {"SMB1": 0}}}
        with with_registry(good):
            self.assertEqual(sysaudit.check_registry_settings(), [])

    def test_hosts_file(self):
        root = Path(tempfile.mkdtemp())
        self.addCleanup(shutil.rmtree, root, True)
        hosts = root / "System32" / "drivers" / "etc" / "hosts"
        hosts.parent.mkdir(parents=True)
        lines = ["127.0.0.1 localhost", "0.0.0.0 update.microsoft.com", "0.0.0.0 update.microsoft.com"]
        lines += [f"10.0.0.9 site{i}.example" for i in range(7)] + ["0.0.0.0 blocked.example"]
        hosts.write_text("\n".join(lines))
        with mock.patch.dict(os.environ, {"SystemRoot": str(root)}):
            found = sysaudit.check_hosts_file()
        self.assertEqual(sum(f.severity == "high" for f in found), 1)         # duplicate line reported once
        low = [f for f in found if f.severity == "low"]
        self.assertEqual(len(low), 1)
        self.assertIn("7 site(s) to 10.0.0.9", low[0].title)
        self.assertTrue(low[0].detail.endswith("..."))
        with mock.patch.dict(os.environ, {"SystemRoot": str(root / "missing")}):
            self.assertEqual(sysaudit.check_hosts_file(), [])

    def test_defender_exclusions(self):
        with mock.patch.object(sysaudit, "_ps_json", return_value=None):
            self.assertEqual(sysaudit.check_defender_exclusions(), [])
        data = {"ExclusionPath": [r"C:\Users\x\Downloads\tool", "N/A: Must be an administrator", "", "C:\\"],
                "ExclusionExtension": ".exe", "ExclusionProcess": None}
        with mock.patch.object(sysaudit, "_ps_json", return_value=data):
            found = sysaudit.check_defender_exclusions()
        self.assertEqual(sorted(f.severity for f in found), ["high", "high", "high"])
        calm = {"ExclusionPath": [r"D:\Games"], "ExclusionExtension": [], "ExclusionProcess": []}
        with mock.patch.object(sysaudit, "_ps_json", return_value=calm):
            self.assertEqual(sysaudit.check_defender_exclusions()[0].severity, "medium")

    def test_services(self):
        with mock.patch.object(sysaudit, "_ps_json", return_value=None):
            self.assertEqual(sysaudit.check_services(), [])
        one = {"Name": "Svc", "PathName": r"C:\Program Files\A B\svc.exe -x"}
        with mock.patch.object(sysaudit, "_ps_json", return_value=one):
            self.assertEqual(len(sysaudit.check_services()), 1)
        many = [{"Name": f"S{i}", "PathName": r"C:\Program Files\A B\svc.exe"} for i in range(12)]
        with mock.patch.object(sysaudit, "_ps_json", return_value=many):
            found = sysaudit.check_services()
        self.assertEqual(len(found), 11)
        self.assertIn("2 more", found[-1].title)


class PersistenceTests(unittest.TestCase):
    def test_startup_entries_registry(self):
        tree = {("HKCU", RUN): {"values": {"Good": r"C:\Program Files\App\app.exe",
                                           "Bad": r"powershell -enc AAAA"}},
                ("HKLM", RUNONCE): {"values": {}}}                         # RunOnce missing for HKCU, empty for HKLM
        with with_registry(tree):
            found = sysaudit.check_startup()
        by_name = {f.title: f.severity for f in found}
        self.assertEqual(by_name, {"Startup entry: Good": "info", "Startup entry: Bad": "medium"})

    def test_startup_folders(self):
        root = Path(tempfile.mkdtemp())
        self.addCleanup(shutil.rmtree, root, True)
        user, common = root / "u", root / "c"
        user.mkdir()
        (user / "evil.vbs").write_text("x")
        (user / "link.lnk").write_text("x")
        (user / "desktop.ini").write_text("x")
        with mock.patch.dict(os.environ, {"APPDATA": str(root / "nowhere"), "ProgramData": str(root / "nowhere2")}):
            self.assertEqual(sysaudit.check_startup_folders(), [])
        startup = user / "Microsoft" / "Windows" / "Start Menu" / "Programs" / "Startup"
        startup.mkdir(parents=True)
        for f in user.iterdir():
            if f.is_file():
                shutil.move(f, startup / f.name)
        common.mkdir()
        with mock.patch.dict(os.environ, {"APPDATA": str(user), "ProgramData": str(common)}):
            found = sysaudit.check_startup_folders()
        self.assertEqual({f.title: f.severity for f in found},
                         {"Startup folder item: evil.vbs": "medium", "Startup folder item: link.lnk": "info"})

    def test_scheduled_tasks(self):
        csv_text = ('"TaskName","Task To Run"\n"\\Good","C:\\Program Files\\a.exe"\n"\\Bad","mshta http://x"\n'
                    '"\\Bad","mshta http://x"\n"","x"\n')
        with mock.patch.object(sysaudit, "_run", return_value=csv_text):
            found = sysaudit.check_scheduled_tasks()
        self.assertEqual(titles(found), ["Suspicious scheduled task: \\Bad"])
        with mock.patch.object(sysaudit, "_run", side_effect=OSError("no schtasks")):
            self.assertEqual(sysaudit.check_scheduled_tasks()[0].severity, "info")

    def test_wmi_persistence(self):
        with mock.patch.object(sysaudit, "_ps_json", return_value=None):
            self.assertEqual(sysaudit.check_wmi_persistence(), [])
        data = [{"Name": "evil", "Class": "CommandLineEventConsumer"}, {"Name": "ok", "Class": "NTEventLogEventConsumer"}]
        with mock.patch.object(sysaudit, "_ps_json", return_value=data):
            self.assertEqual(titles(sysaudit.check_wmi_persistence()), ["WMI event consumer: evil"])
        with mock.patch.object(sysaudit, "_ps_json", return_value=data[0]):
            self.assertEqual(len(sysaudit.check_wmi_persistence()), 1)

    def test_registry_persistence_flags_each_hijack(self):
        tree = {
            ("HKLM", IFEO): {"values": {}, "subkeys": ["sethc.exe", "other.exe", "clean.exe"]},
            ("HKLM", IFEO + r"\sethc.exe"): {"values": {"Debugger": "cmd.exe"}},
            ("HKLM", IFEO + r"\other.exe"): {"values": {"Debugger": "x.exe"}},
            ("HKLM", IFEO + r"\clean.exe"): {"values": {}},
            ("HKLM", WIN + r"\Windows"): {"values": {"AppInit_DLLs": "evil.dll"}},
            ("HKLM", WIN + r"\Winlogon"): {"values": {"Shell": "evil.exe", "Userinit": r"C:\userinit.exe,evil.exe"}},
        }
        with with_registry(tree):
            found = sysaudit.check_registry_persistence()
        got = {f.title: f.severity for f in found}
        self.assertEqual(got["Debugger hijack on sethc.exe"], "high")
        self.assertEqual(got["Debugger hijack on other.exe"], "medium")
        self.assertNotIn("Debugger hijack on clean.exe", got)
        for t in ("AppInit_DLLs injects a DLL into every program", "Winlogon Shell was changed",
                  "Winlogon Userinit launches extra programs"):
            self.assertEqual(got[t], "high")

    def test_registry_persistence_clean_system(self):
        tree = {("HKLM", WIN + r"\Winlogon"): {"values": {"Shell": "explorer.exe", "Userinit": "C:\\userinit.exe,"}}}
        with with_registry(tree):
            self.assertEqual(sysaudit.check_registry_persistence(), [])


class FakePsutil:
    class Error(Exception):
        pass

    class AccessDenied(Error):
        pass

    CONN_LISTEN, CONN_ESTABLISHED = "LISTEN", "ESTABLISHED"

    def __init__(self, conns, names=None, fail=None):
        self.conns, self.names, self.fail = conns, names or {}, fail

    def net_connections(self, kind="inet"):
        if self.fail:
            raise self.fail
        return self.conns

    def Process(self, pid):
        if pid not in self.names:
            raise self.Error("gone")
        return SimpleNamespace(name=lambda: self.names[pid])


def conn(status, laddr=None, raddr=None, pid=1):
    mk = lambda t: SimpleNamespace(ip=t[0], port=t[1]) if t else None  # noqa: E731
    return SimpleNamespace(status=status, laddr=mk(laddr), raddr=mk(raddr), pid=pid)


class NetworkTests(unittest.TestCase):
    def test_without_psutil(self):
        with mock.patch.object(sysaudit, "psutil", None):
            self.assertIn("psutil", sysaudit.check_network()[0].title)

    def test_access_denied(self):
        fake = FakePsutil([], fail=FakePsutil.AccessDenied("no"))
        with mock.patch.object(sysaudit, "psutil", fake):
            self.assertIn("Administrator", sysaudit.check_network()[0].title)

    def test_risky_listeners_and_lolbin_connections(self):
        fake = FakePsutil([
            conn("LISTEN", ("0.0.0.0", 3389)),
            conn("LISTEN", ("0.0.0.0", 3389)),                          # same port twice: reported once
            conn("LISTEN", ("127.0.0.1", 445)),                          # loopback only: fine
            conn("LISTEN", ("0.0.0.0", 8080)),                           # not a risky port
            conn("ESTABLISHED", ("10.0.0.2", 5000), ("8.8.8.8", 443), pid=2),
            conn("ESTABLISHED", ("10.0.0.2", 5001), ("8.8.8.8", 443), pid=2),     # same process+ip once
            conn("ESTABLISHED", ("10.0.0.2", 5002), ("8.8.4.4", 443), pid=3),     # normal program
            conn("ESTABLISHED", ("10.0.0.2", 5003), ("192.168.1.5", 443), pid=2),  # private address
            conn("ESTABLISHED", ("10.0.0.2", 5004), ("not-an-ip", 443), pid=2),
            conn("ESTABLISHED", ("10.0.0.2", 5005), ("1.1.1.1", 443), pid=0),      # unknown pid
        ], names={2: "powershell.exe", 3: "chrome.exe"})
        with mock.patch.object(sysaudit, "psutil", fake):
            found = sysaudit.check_network()
        self.assertEqual(sorted(f.severity for f in found), ["high", "low"])
        self.assertTrue(any("RDP listening" in f.title for f in found))
        self.assertTrue(any("powershell.exe has an internet connection to 8.8.8.8" in f.title for f in found))


class RunAuditTests(unittest.TestCase):
    def test_score_sorting_and_failing_check_is_contained(self):
        def boom():
            raise RuntimeError("check exploded")

        checks = {name: (lambda: []) for name in (
            "check_firewall", "check_defender", "check_defender_exclusions", "check_registry_settings",
            "check_registry_persistence", "check_startup", "check_startup_folders", "check_scheduled_tasks",
            "check_wmi_persistence", "check_services", "check_hosts_file", "check_network")}
        checks["check_firewall"] = lambda: [Finding("low", "x", "low one"), Finding("high", "x", "high one")]
        checks["check_defender"] = boom
        checks["check_network"] = lambda: [Finding("info", "x", "info one")]
        with mock.patch.multiple(sysaudit, IS_WIN=True, **checks):
            rep = sysaudit.run_audit()
        self.assertEqual(rep.score, 100 - 15 - 3)
        self.assertEqual([f.severity for f in rep.findings], ["high", "low", "info", "info"])
        self.assertTrue(any("failed: check exploded" in f.title for f in rep.findings))

    def test_non_windows_runs_only_the_network_check(self):
        with mock.patch.object(sysaudit, "IS_WIN", False), \
                mock.patch.object(sysaudit, "check_network", return_value=[]) as net:
            rep = sysaudit.run_audit()
        net.assert_called_once()
        self.assertIn("Non-Windows", rep.findings[0].title)
        self.assertEqual(rep.score, 100)


if __name__ == "__main__":
    unittest.main()
