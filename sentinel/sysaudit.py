"""System audit: hardening checks, persistence review, and network exposure."""
from __future__ import annotations

import csv
import io
import ipaddress
import json
import os
import re
import subprocess
from dataclasses import dataclass, field

from .platform_utils import psutil

from .platform_utils import IS_WIN
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
    r = subprocess.run(cmd, capture_output=True, text=True, errors="replace", timeout=timeout, creationflags=flags)
    return (r.stdout or "").strip()


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
    out: list = []
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
            if not name or name in seen:  # \Microsoft\ tasks included: malware hides there too
                continue
            seen.add(name)
            cmd = r.get("Task To Run", "")
            if RISKY_CMD.search(cmd or ""):
                findings.append(Finding("medium", "Persistence", f"Suspicious scheduled task: {name}", cmd,
                                        "Review in Task Scheduler and delete if unknown"))
        return findings
    except (OSError, subprocess.SubprocessError):
        return [Finding("info", "Persistence", "Could not enumerate scheduled tasks")]


SECURITY_HOST_HINTS = ("microsoft", "windowsupdate", "defender", "google", "paypal", "amazon", "facebook",
                       "apple", "github", "virustotal", "kaspersky", "avast", "avg.", "mcafee", "norton",
                       "bitdefender", "malwarebytes", "eset", "symantec", "sophos", "trendmicro")
LOOPBACK = ("127.0.0.1", "::1", "0.0.0.0")
AUTORUN_EXT = {".exe", ".bat", ".cmd", ".vbs", ".vbe", ".js", ".jse", ".ps1", ".hta", ".scr", ".wsf"}  # .lnk shortcuts are normal in Startup
IFEO_HIJACK = {"sethc.exe", "utilman.exe", "osk.exe", "narrator.exe", "magnify.exe", "displayswitch.exe",
               "atbroker.exe"}


def parse_hosts(text: str) -> list:
    """Return [(ip, hostname)] from hosts-file text (comments stripped)."""
    out: list = []
    for line in text.splitlines():
        parts = line.split("#", 1)[0].split()
        if len(parts) >= 2:
            out.extend((parts[0], h.lower()) for h in parts[1:])
    return out


def is_unquoted_service_path(path_name) -> bool:
    """True for 'C:\\Program Files\\App\\svc.exe -x' (unquoted path containing spaces)."""
    p = (path_name or "").strip()
    if not p or p.startswith('"'):
        return False
    m = re.match(r"^(.*?\.exe)\b", p, re.I)
    return bool(m and " " in m.group(1))


def check_hosts_file():
    path = os.path.join(os.environ.get("SystemRoot", r"C:\Windows"), r"System32\drivers\etc\hosts")
    try:
        with open(path, encoding="utf-8", errors="ignore") as f:
            entries = parse_hosts(f.read())
    except OSError:
        return []
    out, others = [], {}
    for ip, host in dict.fromkeys(entries):  # de-duplicate repeated lines
        if host == "localhost" and ip in LOOPBACK:
            continue
        if any(k in host for k in SECURITY_HOST_HINTS):
            out.append(Finding("high", "Hardening", f"hosts file redirects {host} to {ip}",
                               "Malware edits this file to block antivirus/update sites or hijack logins.",
                               f"Remove the line from {path} unless you added it yourself"))
        elif ip not in LOOPBACK:
            others.setdefault(ip, []).append(host)
    for ip, hosts in others.items():  # one finding per destination, not one per line
        out.append(Finding("low", "Hardening", f"hosts file redirects {len(hosts)} site(s) to {ip}",
                           ", ".join(hosts[:5]) + (" ..." if len(hosts) > 5 else ""),
                           f"Review {path}; cracked-software installers often add entries here"))
    return out


def check_defender_exclusions():
    data = _ps_json("Get-MpPreference | Select-Object ExclusionPath,ExclusionExtension,ExclusionProcess"
                    " | ConvertTo-Json -Compress")
    if not data:
        return []
    out = []
    for key, label in (("ExclusionPath", "folder"), ("ExclusionExtension", "extension"),
                       ("ExclusionProcess", "process")):
        vals = data.get(key) or []
        for v in ([vals] if isinstance(vals, str) else vals):
            if not v or v.startswith("N/A"):  # non-admin shells get a placeholder
                continue
            high = bool(RISKY_CMD.search(v)) or v.strip(". ").lower() in ("exe", "dll", "ps1", "c:\\")
            out.append(Finding("high" if high else "medium", "Hardening",
                               f"Defender excludes {label}: {v}",
                               "Malware often adds exclusions so it can run unscanned.",
                               "Windows Security > Virus & threat protection > Manage settings > Exclusions"))
    return out


def check_startup_folders():
    dirs = [os.path.join(os.environ.get("APPDATA", ""), r"Microsoft\Windows\Start Menu\Programs\Startup"),
            os.path.join(os.environ.get("ProgramData", ""), r"Microsoft\Windows\Start Menu\Programs\StartUp")]
    out = []
    for d in dirs:
        if not d or not os.path.isdir(d):
            continue
        for fn in os.listdir(d):
            if fn.lower() == "desktop.ini":
                continue
            risky = os.path.splitext(fn)[1].lower() in AUTORUN_EXT
            out.append(Finding("medium" if risky else "info", "Persistence", f"Startup folder item: {fn}", d,
                               "Delete it if you don't recognise it" if risky else ""))
    return out


def check_services():
    data = _ps_json("Get-CimInstance Win32_Service | Select-Object Name,PathName | ConvertTo-Json -Compress")
    if not data:
        return []
    data = [data] if isinstance(data, dict) else data
    bad = [d for d in data if is_unquoted_service_path(d.get("PathName"))]
    out = [Finding("medium", "Hardening", f"Service '{d['Name']}' has an unquoted path with spaces",
                   d.get("PathName") or "", "Quote the ImagePath in HKLM\\SYSTEM\\CurrentControlSet\\Services")
           for d in bad[:10]]
    if len(bad) > 10:
        out.append(Finding("low", "Hardening", f"...and {len(bad) - 10} more unquoted service paths"))
    return out


def check_wmi_persistence():
    data = _ps_json("Get-CimInstance -Namespace root\\subscription -ClassName __EventConsumer"
                    " | Select-Object Name,@{n='Class';e={$_.CimClass.CimClassName}} | ConvertTo-Json -Compress")
    if not data:
        return []
    data = [data] if isinstance(data, dict) else data
    return [Finding("high", "Persistence", f"WMI event consumer: {d.get('Name')}",
                    f"Type {d.get('Class')}. Fileless malware uses these to run code at boot.",
                    "Investigate and remove with Get-WmiObject -Namespace root\\subscription")
            for d in data if d.get("Class") in ("CommandLineEventConsumer", "ActiveScriptEventConsumer")]


def check_registry_persistence():
    import winreg
    hklm, out = winreg.HKEY_LOCAL_MACHINE, []
    base = r"SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options"
    try:
        with winreg.OpenKey(hklm, base) as k:
            i = 0
            while True:
                try:
                    sub = winreg.EnumKey(k, i)
                except OSError:
                    break
                i += 1
                dbg = _reg_value(hklm, base + "\\" + sub, "Debugger")
                if dbg:
                    out.append(Finding("high" if sub.lower() in IFEO_HIJACK else "medium", "Persistence",
                                       f"Debugger hijack on {sub}", str(dbg),
                                       "Delete the Debugger value unless you are debugging this program"))
    except OSError:
        pass
    win = r"SOFTWARE\Microsoft\Windows NT\CurrentVersion"
    appinit = _reg_value(hklm, win + r"\Windows", "AppInit_DLLs")
    if appinit and str(appinit).strip():
        out.append(Finding("high", "Persistence", "AppInit_DLLs injects a DLL into every program",
                           str(appinit), "Clear the AppInit_DLLs value"))
    shell = _reg_value(hklm, win + r"\Winlogon", "Shell")
    if shell and str(shell).strip().lower() != "explorer.exe":
        out.append(Finding("high", "Persistence", "Winlogon Shell was changed", str(shell),
                           "Reset the value to explorer.exe"))
    userinit = _reg_value(hklm, win + r"\Winlogon", "Userinit")
    if userinit and len([x for x in str(userinit).split(",") if x.strip()]) > 1:
        out.append(Finding("high", "Persistence", "Winlogon Userinit launches extra programs", str(userinit),
                           r"Reset the value to C:\Windows\system32\userinit.exe,"))
    return out


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
        checks = [check_firewall, check_defender, check_defender_exclusions, check_registry_settings,
                  check_registry_persistence, check_startup, check_startup_folders, check_scheduled_tasks,
                  check_wmi_persistence, check_services, check_hosts_file, check_network]
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
