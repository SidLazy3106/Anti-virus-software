"""Script heuristics: PowerShell/VBS/JS/batch patterns, including payloads hidden in -EncodedCommand."""
from __future__ import annotations

import base64
import binascii
import re
from pathlib import Path

from .. import config
from ..result import ScanResult
from .base import Check


SCRIPT_EXT = {".ps1", ".psm1", ".bat", ".cmd", ".vbs", ".vbe", ".js", ".jse", ".wsf", ".hta", ".sct"}

# PowerShell accepts any prefix of -EncodedCommand: -e, -ec, -en, -enc, -encodedcommand ...
ENC_CMD = re.compile(rb"(?:^|\s)-e(?:c|n[a-z]*)?\s+([A-Za-z0-9+/=]{20,})", re.I)
SCRIPT_READ_LIMIT = config.SCRIPT_READ_LIMIT   # scripts of any size are checked; only the first part is read

SCRIPT_PATTERNS = [
    (ENC_CMD, 30, "PowerShell encoded command"),
    (re.compile(rb"FromBase64String", re.I), 15, "Base64 decoding inside a script"),
    (re.compile(rb"(Invoke-Expression|\bIEX\b)", re.I), 15, "Dynamic script execution (IEX)"),
    (re.compile(rb"(DownloadString|DownloadFile|Invoke-WebRequest|Net\.WebClient)", re.I), 15, "Script downloads content"),
    # download-and-execute "cradle": fetched code is run straight away, never saved or reviewed
    (re.compile(rb"(\bIEX\b|Invoke-Expression)[\s(]*(\(\s*)?(New-Object\s+(System\.)?Net\.WebClient\)?\s*\.\s*"
                rb"DownloadString|\(?\s*(iwr|irm|Invoke-WebRequest|Invoke-RestMethod)\b)"
                rb"|(DownloadString\s*\([^)]*\)|\b(iwr|irm|Invoke-WebRequest|Invoke-RestMethod)\b[^|\r\n]*)\s*\|\s*"
                rb"(\bIEX\b|Invoke-Expression)", re.I), 25, "Downloads code and runs it immediately (download cradle)"),
    (re.compile(rb"-w(indowstyle)?\s+hidden", re.I), 10, "Runs with a hidden window"),
    (re.compile(rb"vssadmin(\.exe)?\s+delete\s+shadows", re.I), 50, "Deletes shadow copies (ransomware behaviour)"),
    (re.compile(rb"wmic(\.exe)?\s+shadowcopy\s+delete|bcdedit.*recoveryenabled\s+no", re.I), 50,
     "Disables Windows recovery (ransomware behaviour)"),
    (re.compile(rb"certutil(\.exe)?\s+.*-(urlcache|decode)", re.I), 25, "certutil used to download or decode files"),
    (re.compile(rb"bitsadmin(\.exe)?\s+.*/transfer", re.I), 20, "bitsadmin used to download files"),
    (re.compile(rb"(mshta|regsvr32)(\.exe)?\s+.*https?://", re.I), 30, "Remote script execution via mshta/regsvr32"),
    (re.compile(rb"Set-MpPreference\s+.*-Disable|Add-MpPreference\s+.*-ExclusionPath", re.I), 40,
     "Tries to weaken or bypass Windows Defender"),
    (re.compile(rb"AmsiUtils|amsiInitFailed|AmsiScanBuffer", re.I), 40, "AMSI bypass attempt"),
    (re.compile(rb"-ExecutionPolicy\s+Bypass|-ep\s+bypass", re.I), 10, "Bypasses the PowerShell execution policy"),
    (re.compile(rb"\[Reflection\.Assembly\]::Load", re.I), 20, "Loads a .NET assembly from memory"),
    (re.compile(rb"WScript\.Shell", re.I), 10, "Script spawns commands through WScript.Shell"),
    (re.compile(rb"eval\s*\(\s*unescape|String\.fromCharCode\s*\((\s*\d+\s*,){10,}", re.I), 25,
     "Obfuscated JavaScript"),
]


def decode_script(data: bytes) -> bytes:
    """Return script text as UTF-8 bytes. PowerShell often saves UTF-16, which would hide every pattern."""
    if data[:2] in (b"\xff\xfe", b"\xfe\xff"):
        return data.decode("utf-16", errors="ignore").encode("utf-8", errors="ignore")
    head = data[:2000]
    if len(head) >= 4 and head.count(b"\x00") > len(head) // 3:  # BOM-less UTF-16
        enc = "utf-16-le" if head[1:2] == b"\x00" else "utf-16-be"
        return data.decode(enc, errors="ignore").encode("utf-8", errors="ignore")
    return data


def decode_encoded_command(b64: bytes) -> bytes:
    """Decode a PowerShell -EncodedCommand argument (Base64 of UTF-16LE text)."""
    try:
        raw = base64.b64decode(b64 + b"=" * (-len(b64) % 4))
    except (binascii.Error, ValueError):
        return b""
    return raw.decode("utf-16-le", errors="ignore").encode("utf-8", errors="ignore")


def script_checks(p: Path, res: ScanResult):
    try:
        with open(p, "rb") as f:
            data = f.read(SCRIPT_READ_LIMIT)
    except OSError:
        return
    text = decode_script(data)
    for rx, pts, why in SCRIPT_PATTERNS:
        if rx.search(text):
            res.add(pts, why)
    # look inside -EncodedCommand payloads, where the real behaviour usually hides
    for m in list(ENC_CMD.finditer(text))[:5]:
        inner = decode_encoded_command(m.group(1))
        for rx, pts, why in SCRIPT_PATTERNS:
            if rx is not ENC_CMD and why not in res.reasons and rx.search(inner):
                res.add(pts, f"{why} (hidden in encoded command)")


class ScriptCheck(Check):
    name = "script"

    def applies(self, ctx):
        return ctx.ext in SCRIPT_EXT

    def run(self, ctx):
        script_checks(ctx.path, ctx.result)
