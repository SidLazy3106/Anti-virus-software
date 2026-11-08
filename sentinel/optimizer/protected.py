"""Names of startup entries and processes that are never offered for changing."""
from __future__ import annotations

import re


PROTECTED_RX = re.compile(
    r"(defender|windows ?security|sechealth|securityhealth|antivirus|anti-virus|firewall|malware|mcafee|norton|"
    r"kaspersky|avast|\bavg\b|bitdefender|eset|sophos|x-?secure|realtek|nahimic|waves|synaptics|\belan\b|touchpad|"
    r"\balps\b|bluetooth|audio|igfx|\bintel|radeon|nvdisplay|nvcontainer|driver|ctfmon|windows ?update|vpn|"
    r"authenticator|ipsecuritymonitor|rtkaud|dolby|vanguard|\bvgc\b|\bvgtray\b|easyanticheat|battleye|anti-?cheat)",
    re.I)
PROTECTED_PROCS = {
    "system", "system idle process", "registry", "memcompression", "smss.exe", "csrss.exe", "wininit.exe",
    "services.exe", "lsass.exe", "svchost.exe", "winlogon.exe", "dwm.exe", "fontdrvhost.exe", "explorer.exe",
    "msmpeng.exe", "nissrv.exe", "securityhealthservice.exe", "securityhealthsystray.exe", "searchindexer.exe",
    "sihost.exe", "taskhostw.exe", "runtimebroker.exe", "ctfmon.exe", "audiodg.exe", "wmiprvse.exe", "spoolsv.exe",
    "dllhost.exe", "conhost.exe", "lsaiso.exe", "wudfhost.exe", "dashost.exe", "unsecapp.exe",
}


def is_protected_startup(name: str, command: str) -> bool:
    return bool(PROTECTED_RX.search(f"{name} {command}"))
