"""System audit: hardening checks, persistence review, and network exposure."""
from __future__ import annotations

import csv
import io
import ipaddress
import json
import re
import subprocess
import sys
from dataclasses import dataclass, field

try:
    import psutil
except ImportError:
    psutil = None

IS_WIN = sys.platform == "win32"
WEIGHT = {"high": 15, "medium": 7, "low": 3, "info": 0}

RISKY_CMD = re.compile(
    r"(\\temp\\|\\appdata\\local\\temp|\\users\\public\\|\\downloads\\"
    r"|powershell.*-e(nc|ncodedcommand)\b|mshta|wscript|cscript"
    r"|regsvr32.*(http|scrobj)|rundll32.*javascript)", re.I)
LOLBINS = {"powershell", "pwsh", "wscript", "cscript", "mshta", "rundll32", "regsvr32", "certutil", "bitsadmin"}
RISKY_LISTEN = {21: "FTP", 23: "Telnet", 135: "RPC", 139: "NetBIOS", 445: "SMB",
                3389: "RDP", 5900: "VNC", 5985: "WinRM"}


@dataclass
class Finding:
    severity: str
    category: str
    title: str
    detail: str = ""
    fix: str = ""


@dataclass
class AuditReport:
    score: int
    findings: list = field(default_factory=list)


def _run(cmd, timeout=25) -> str:
    flags = getattr(subprocess, "CREATE_NO_WINDOW", 0)
    r = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout, creationflags=flags)
    return r.stdout.strip()


def _ps_json(script):
    try:
        out = _run(["powershell", "-NoProfile", "-NonInteractive", "-Command", script])
        return json.loads(out) if out else None
    except (OSError, ValueError, subprocess.SubprocessError):
        return None


def _reg_value(hive, path, name):
    import winreg
    try:
        with winreg.OpenKey(hive, path) as k:
            return winreg.QueryValueEx(k, name)[0]
    except OSError:
        return None


# ---------------------------------------------------------------- hardening
def check_firewall():
    data = _ps_json("Get-NetFirewallProfile | Select-Object Name,Enabled | ConvertTo-Json")
    if data is None:
        return [Finding("info", "Hardening", "Could not read firewall status")]
    data = [data] if isinstance(data, dict) else data
    off = [d["Name"] for d in data if not d.get("Enabled")]
    if off:
        return [Finding("high", "Hardening", f"Windows Firewall is OFF for: {', '.join(off)}",
                        fix="Settings > Privacy & security > Windows Security > Firewall & network protection")]
    return []


def check_defender():
    data = _ps_json("Get-MpComputerStatus | Select-Object AntivirusEnabled,RealTimeProtectionEnabled,"
                    "AntivirusSignatureAge | ConvertTo-Json")
    if not data:
        return [Finding("info", "Hardening", "Windows Defender status unavailable (third-party antivirus?)")]
    out = []
    if not data.get("RealTimeProtectionEnabled"):
        out.append(Finding("high", "Hardening", "Defender real-time protection is off",
                           "Ignore if another antivirus is active.", "Windows Security > Virus & threat protection"))
    age = data.get("AntivirusSignatureAge")
    if isinstance(age, int) and age > 7:
        out.append(Finding("medium", "Hardening", f"Defender signatures are {age} days old",
                           fix="Run Windows Update / 'Check for updates' in Windows Security"))
    return out


def check_registry_settings():
    import winreg
    out = []
    uac = _reg_value(winreg.HKEY_LOCAL_MACHINE,
                     r"SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System", "EnableLUA")
    if uac == 0:
        out.append(Finding("high", "Hardening", "User Account Control (UAC) is disabled",
                           fix="Enable UAC in Control Panel > User Accounts > Change UAC settings"))
    rdp = _reg_value(winreg.HKEY_LOCAL_MACHINE,
                     r"SYSTEM\CurrentControlSet\Control\Terminal Server", "fDenyTSConnections")
    if rdp == 0:
        out.append(Finding("medium", "Hardening", "Remote Desktop is enabled",
                           "Exposed RDP is a common ransomware entry point.",
                           "Disable it unless needed, or require VPN + Network Level Authentication"))
    smb1 = _reg_value(winreg.HKEY_LOCAL_MACHINE,
                      r"SYSTEM\CurrentControlSet\Services\LanmanServer\Parameters", "SMB1")
    if smb1 == 1:
        out.append(Finding("high", "Hardening", "SMBv1 is enabled (WannaCry-era protocol)",
                           fix="Turn off 'SMB 1.0/CIFS File Sharing Support' in Windows Features"))
    return out


# -------------------------------------------------------------- persistence
def check_startup():
    import winreg
    out = []
    keys = [(winreg.HKEY_CURRENT_USER, "HKCU"), (winreg.HKEY_LOCAL_MACHINE, "HKLM")]
    for hive, hname in keys:
        for sub in (r"Software\Microsoft\Windows\CurrentVersion\Run",
                    r"Software\Microsoft\Windows\CurrentVersion\RunOnce"):
            try:
                with winreg.OpenKey(hive, sub) as k:
                    i = 0
                    while True:
                        try:
                            name, val, _ = winreg.EnumValue(k, i)
                        except OSError:
                            break
                        i += 1
                        risky = bool(RISKY_CMD.search(str(val)))
                        out.append(Finding("medium" if risky else "info", "Persistence",
                                           f"Startup entry: {name}", f"{hname}\\{sub} -> {val}",
                                           "Remove it if you don't recognise it" if risky else ""))
            except OSError:
                continue
    return out


def check_scheduled_tasks():
    try:
        out = _run(["schtasks", "/query", "/fo", "csv", "/v"], timeout=40)
        rows = csv.DictReader(io.StringIO(out))
        seen, findings = set(), []
        for r in rows:
            name = r.get("TaskName", "")
            if not name or name in seen or name.startswith("\\Microsoft\\"):
                continue
            seen.add(name)
            cmd = r.get("Task To Run", "")
            if RISKY_CMD.search(cmd or ""):
                findings.append(Finding("medium", "Persistence", f"Suspicious scheduled task: {name}", cmd,
                                        "Review in Task Scheduler and delete if unknown"))
        return findings
    except (OSError, subprocess.SubprocessError):
        return [Finding("info", "Persistence", "Could not enumerate scheduled tasks")]


# ------------------------------------------------------------------ network
def check_network():
    if psutil is None:
        return [Finding("info", "Network", "Install psutil for network checks")]
    out, seen = [], set()
    try:
        conns = psutil.net_connections(kind="inet")
    except (psutil.AccessDenied, OSError):
        return [Finding("info", "Network", "Run as Administrator to inspect all connections")]
    for c in conns:
        try:
            pname = psutil.Process(c.pid).name() if c.pid else "?"
        except psutil.Error:
            pname = "?"
        stem = pname.lower().removesuffix(".exe")
        if c.status == psutil.CONN_LISTEN and c.laddr and c.laddr.ip in ("0.0.0.0", "::") \
                and c.laddr.port in RISKY_LISTEN and ("L", c.laddr.port) not in seen:
            seen.add(("L", c.laddr.port))
            out.append(Finding("low", "Network", f"{RISKY_LISTEN[c.laddr.port]} listening on all interfaces (port {c.laddr.port})",
                               f"Process: {pname}. Reachable only if your firewall allows it.",
                               "Block inbound on public networks"))
        if c.status == psutil.CONN_ESTABLISHED and c.raddr:
            try:
                public = ipaddress.ip_address(c.raddr.ip).is_global
            except ValueError:
                continue
            if public and stem in LOLBINS and (pname, c.raddr.ip) not in seen:
                seen.add((pname, c.raddr.ip))
                out.append(Finding("high", "Network", f"{pname} has an internet connection to {c.raddr.ip}:{c.raddr.port}",
                                   "Script hosts and living-off-the-land binaries rarely need this.",
                                   "Investigate the parent process"))
    return out


def run_audit() -> AuditReport:
    findings = []
    checks = [check_network]
    if IS_WIN:
        checks = [check_firewall, check_defender, check_registry_settings,
                  check_startup, check_scheduled_tasks, check_network]
    else:
        findings.append(Finding("info", "System", "Non-Windows OS: only network checks are available"))
    for fn in checks:
        try:
            findings.extend(fn())
        except Exception as e:  # a failing check must never crash the audit
            findings.append(Finding("info", "System", f"{fn.__name__} failed: {e}"))
    score = max(0, 100 - sum(WEIGHT[f.severity] for f in findings))
    order = {"high": 0, "medium": 1, "low": 2, "info": 3}
    findings.sort(key=lambda f: order[f.severity])
    return AuditReport(score, findings)
