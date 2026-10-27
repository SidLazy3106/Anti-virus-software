"""Static scan engine: hashes, magic bytes, entropy, PE and script heuristics, optional YARA.

This is a heuristic engine. It will have false positives (installers, game cracks,
.NET apps, legitimate packers) and false negatives (anything novel). Treat verdicts
as signals, not proof.
"""
from __future__ import annotations

import hashlib
import math
import os
import re
from collections import Counter
from dataclasses import dataclass, field
from pathlib import Path
from typing import Iterator, Optional

from . import config

try:
    import pefile
except ImportError:  # optional dependency
    pefile = None
try:
    import yara
except ImportError:  # optional dependency
    yara = None

CLEAN, SUSPICIOUS, MALICIOUS, ERROR = "clean", "suspicious", "malicious", "error"

EICAR_MARKER = b"EICAR-STANDARD-ANTIVIRUS-TEST-FILE!"
EXEC_EXT = {".exe", ".scr", ".com", ".pif", ".dll", ".sys"}
SCRIPT_EXT = {".ps1", ".bat", ".cmd", ".vbs", ".js", ".jse", ".wsf", ".hta"}
DECOY_EXT = {".pdf", ".doc", ".docx", ".xls", ".xlsx", ".jpg", ".jpeg", ".png",
             ".txt", ".mp3", ".mp4", ".zip", ".gif", ".ppt", ".pptx"}
DOUBLE_EXT = re.compile(
    r"\.(pdf|docx?|xlsx?|pptx?|jpe?g|png|gif|txt|mp3|mp4|zip)\s*\.(exe|scr|com|pif|bat|cmd|js|vbs|lnk|hta)$",
    re.I)

SUSPICIOUS_IMPORTS = {
    "VirtualAllocEx": 12, "WriteProcessMemory": 12, "CreateRemoteThread": 18,
    "NtUnmapViewOfSection": 18, "QueueUserAPC": 10, "NtQueueApcThread": 10,
    "SetWindowsHookExA": 8, "SetWindowsHookExW": 8, "GetAsyncKeyState": 8,
    "URLDownloadToFileA": 8, "URLDownloadToFileW": 8, "AdjustTokenPrivileges": 4,
}

SCRIPT_PATTERNS = [
    (re.compile(rb"-e(nc|ncodedcommand)\s+[A-Za-z0-9+/=]{20,}", re.I), 30, "PowerShell encoded command"),
    (re.compile(rb"FromBase64String", re.I), 15, "Base64 decoding inside a script"),
    (re.compile(rb"(Invoke-Expression|\bIEX\b)", re.I), 15, "Dynamic script execution (IEX)"),
    (re.compile(rb"(DownloadString|DownloadFile|Invoke-WebRequest|Net\.WebClient)", re.I), 15, "Script downloads content"),
    (re.compile(rb"-w(indowstyle)?\s+hidden", re.I), 10, "Runs with a hidden window"),
    (re.compile(rb"vssadmin(\.exe)?\s+delete\s+shadows", re.I), 50, "Deletes shadow copies (ransomware behaviour)"),
]


@dataclass
class ScanResult:
    path: str
    verdict: str = CLEAN
    score: int = 0
    sha256: str = ""
    reasons: list = field(default_factory=list)

    def add(self, points: int, reason: str):
        self.score += points
        self.reasons.append(reason)

    def finalize(self):
        self.score = min(self.score, 100)
        if self.verdict == ERROR:
            return
        if self.score >= config.MALICIOUS_THRESHOLD:
            self.verdict = MALICIOUS
        elif self.score >= config.SUSPICIOUS_THRESHOLD:
            self.verdict = SUSPICIOUS
        else:
            self.verdict = CLEAN


def shannon_entropy(data: bytes) -> float:
    if not data:
        return 0.0
    n = len(data)
    return -sum((c / n) * math.log2(c / n) for c in Counter(data).values())


class SignatureDB:
    """Known-bad SHA-256 hashes loaded from bundled and updated feed files."""

    def __init__(self, dirs=None):
        self.hashes: dict[str, str] = {}
        for d in dirs or (config.SIGNATURES_DIR, config.UPDATED_SIGS_DIR):
            d = Path(d)
            if not d.is_dir():
                continue
            for f in d.glob("hashes*.txt"):
                self._load(f)

    def _load(self, f: Path):
        try:
            lines = f.read_text(errors="ignore").splitlines()
        except OSError:
            return
        for line in lines:
            line = line.strip()
            if not line or line.startswith("#"):
                continue
            parts = line.split(None, 1)
            h = parts[0].lower()
            if len(h) == 64 and all(c in "0123456789abcdef" for c in h):
                self.hashes[h] = parts[1] if len(parts) > 1 else "Known malware hash"


def _hash_and_sample(path: Path):
    h = hashlib.sha256()
    sample = b""
    with open(path, "rb") as f:
        while True:
            chunk = f.read(1 << 20)
            if not chunk:
                break
            if len(sample) < config.ENTROPY_SAMPLE:
                sample += chunk[: config.ENTROPY_SAMPLE - len(sample)]
            h.update(chunk)
    return h.hexdigest(), sample


class Scanner:
    def __init__(self, db: Optional[SignatureDB] = None):
        self.db = db or SignatureDB()
        self.rules = self._load_rules()

    @staticmethod
    def _load_rules():
        if yara is None or not config.RULES_DIR.is_dir():
            return None
        files = {p.stem: str(p) for p in config.RULES_DIR.glob("*.yar")}
        if not files:
            return None
        try:
            return yara.compile(filepaths=files)
        except Exception:
            return None

    def scan_file(self, path) -> ScanResult:
        p = Path(path)
        res = ScanResult(path=str(p))
        try:
            size = p.stat().st_size
            res.sha256, sample = _hash_and_sample(p)
        except OSError as e:
            res.verdict = ERROR
            res.reasons.append(f"Could not read file: {e}")
            return res

        name = self.db.hashes.get(res.sha256)
        if name:
            res.add(100, f"Known malware hash: {name}")
        if size <= 256 and EICAR_MARKER in sample:
            res.add(100, "EICAR antivirus test file")

        ext = p.suffix.lower()
        is_pe = sample[:2] == b"MZ"
        if is_pe and ext in DECOY_EXT:
            res.add(40, f"Executable disguised as a {ext} file")
        if DOUBLE_EXT.search(p.name):
            res.add(45, "Double extension (document name hiding a program)")

        if size <= config.MAX_HEURISTIC_SIZE:
            if is_pe:
                self._pe_checks(p, sample, ext, res)
            if ext in SCRIPT_EXT and size <= 2 * 1024 * 1024:
                self._script_checks(p, res)
            if self.rules is not None:
                self._yara_checks(p, res)
        res.finalize()
        return res

    @staticmethod
    def _pe_checks(p: Path, sample: bytes, ext: str, res: ScanResult):
        if ext in {".exe", ".scr", ".com", ".pif"} and shannon_entropy(sample) > 7.2:
            res.add(20, "Very high entropy (packed or encrypted)")
        if pefile is None:
            return
        try:
            pe = pefile.PE(str(p), fast_load=False)
        except Exception:
            return
        try:
            wx, high, upx = [], [], False
            for s in pe.sections:
                name = s.Name.rstrip(b"\x00").decode(errors="ignore")
                ch = s.Characteristics
                if ch & 0x20000000 and ch & 0x80000000:
                    wx.append(name)
                if s.SizeOfRawData > 4096 and s.get_entropy() > 7.4:
                    high.append(name)
                upx = upx or name.upper().startswith("UPX")
            if wx:
                res.add(15, f"Writable+executable sections: {', '.join(wx)}")
            if high:
                res.add(10, f"High-entropy sections: {', '.join(high)}")
            if upx:
                res.add(10, "UPX-packed executable")
            found, pts = [], 0
            for entry in getattr(pe, "DIRECTORY_ENTRY_IMPORT", []):
                for imp in entry.imports:
                    nm = imp.name.decode(errors="ignore") if imp.name else ""
                    if nm in SUSPICIOUS_IMPORTS:
                        found.append(nm)
                        pts += SUSPICIOUS_IMPORTS[nm]
            if found:
                res.add(min(pts, 40), f"Suspicious API imports: {', '.join(sorted(set(found)))}")
        finally:
            pe.close()

    @staticmethod
    def _script_checks(p: Path, res: ScanResult):
        try:
            data = p.read_bytes()
        except OSError:
            return
        for rx, pts, why in SCRIPT_PATTERNS:
            if rx.search(data):
                res.add(pts, why)

    def _yara_checks(self, p: Path, res: ScanResult):
        try:
            for m in self.rules.match(filepath=str(p)):
                res.add(60, f"YARA rule matched: {m.rule}")
        except Exception:
            pass

    def scan_tree(self, root, cancel=None) -> Iterator[ScanResult]:
        root = Path(root)
        if root.is_file():
            yield self.scan_file(root)
            return
        skip = {os.path.normcase(str(config.QUARANTINE_DIR))}
        for dirpath, dirnames, filenames in os.walk(root, followlinks=False):
            dirnames[:] = [d for d in dirnames
                           if os.path.normcase(os.path.join(dirpath, d)) not in skip]
            for fn in filenames:
                if cancel is not None and cancel.is_set():
                    return
                fp = os.path.join(dirpath, fn)
                if os.path.islink(fp):
                    continue
                yield self.scan_file(fp)
