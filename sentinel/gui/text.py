"""User-facing text tables and small formatters shared by the GUI pages."""
from __future__ import annotations

import time

from ..scanner import MALICIOUS, SUSPICIOUS

TIPS = [
    ("Pause before you click", "Scam links look real. Paste any link you're unsure about into Web guard first."),
    ("Turn on two-step login", "A stolen password is useless without your second step. Start with email and banking."),
    ("Keep Windows updated", "Most attacks use bugs that already have a fix. Install updates when they appear."),
    ("Back up what matters", "Ransomware can lock every file. Keep a copy on a drive that isn't always plugged in."),
    ("Careful on public Wi-Fi", "Avoid banking on café or airport networks, or use a VPN you trust."),
    ("Use a password manager", "A different password for every site stops one breach from becoming ten."),
    ("Doubt surprise attachments", "Invoices or résumés that ask you to 'enable macros' are a classic trick."),
    ("Download from official sites", "Cracked software and key generators are a very common way malware arrives."),
]
VERDICT_LABEL = {MALICIOUS: "Dangerous", SUSPICIOUS: "Suspicious"}
SEVERITY_LABEL = {"high": "High", "medium": "Medium", "low": "Low", "info": "Info"}


def ago(ts: float) -> str:
    d = time.time() - ts
    if d < 60:
        return "just now"
    if d < 3600:
        return f"{int(d // 60)} min ago"
    if d < 86400:
        return f"{int(d // 3600)} h ago"
    return f"{int(d // 86400)} d ago"
