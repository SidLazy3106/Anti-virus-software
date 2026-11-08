"""Static scan engine: hashes, magic bytes, entropy, PE and script heuristics, optional YARA.

This is a heuristic engine. It will have false positives (installers, game cracks,
.NET apps, legitimate packers) and false negatives (anything novel). Treat verdicts
as signals, not proof.
"""
from __future__ import annotations

import base64
import binascii
import hashlib
import math
import os
import re
import zipfile
from collections import Counter
from dataclasses import dataclass, field
from pathlib import Path
from typing import Iterator, Optional

from . import ads, authenticode, config, logger

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
SCRIPT_EXT = {".ps1", ".psm1", ".bat", ".cmd", ".vbs", ".vbe", ".js", ".jse", ".wsf", ".hta", ".sct"}
DECOY_EXT = {".pdf", ".doc", ".docx", ".xls", ".xlsx", ".jpg", ".jpeg", ".png",
             ".txt", ".mp3", ".mp4", ".zip", ".gif", ".ppt", ".pptx"}
RECENT_LNK_DIR = re.compile(r"[\\/]microsoft[\\/](?:windows[\\/]recent|office[\\/]recent|word|excel|powerpoint)[\\/]",
                            re.I)
DOUBLE_EXT = re.compile(
    r"\.(pdf|docx?|xlsx?|pptx?|jpe?g|png|gif|txt|mp3|mp4|zip)\s*\.(exe|scr|com|pif|bat|cmd|js|vbs|lnk|hta)$",
    re.I)

SUSPICIOUS_IMPORTS = {
    "VirtualAllocEx": 12, "WriteProcessMemory": 12, "CreateRemoteThread": 18,
    "NtUnmapViewOfSection": 18, "QueueUserAPC": 10, "NtQueueApcThread": 10,
    "SetWindowsHookExA": 8, "SetWindowsHookExW": 8, "GetAsyncKeyState": 8,
    "URLDownloadToFileA": 8, "URLDownloadToFileW": 8, "AdjustTokenPrivileges": 4,
}

# PowerShell accepts any prefix of -EncodedCommand: -e, -ec, -en, -enc, -encodedcommand ...
ENC_CMD = re.compile(rb"(?:^|\s)-e(?:c|n[a-z]*)?\s+([A-Za-z0-9+/=]{20,})", re.I)
SCRIPT_READ_LIMIT = 4 * 1024 * 1024   # scripts of any size are checked; only the first 4 MB is read

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


ARCHIVE_EXEC_EXT = {".exe", ".scr", ".com", ".pif", ".dll", ".bat", ".cmd", ".vbs", ".vbe", ".js", ".jse",
                    ".hta", ".lnk", ".ps1", ".wsf", ".msi"}
OFFICE_ZIP_EXT = {".docx", ".docm", ".xlsx", ".xlsm", ".pptx", ".pptm", ".dotm", ".xltm"}
MACRO_ENABLED_EXT = {".docm", ".xlsm", ".pptm", ".dotm", ".xltm"}
OLE_EXT = {".doc", ".xls", ".ppt", ".dot", ".xlt"}
OLE_MAGIC = b"\xd0\xcf\x11\xe0\xa1\xb1\x1a\xe1"
MAX_ZIP_ENTRIES = 5000
MACRO_AUTORUN = re.compile(rb"(AutoOpen|Document_Open|Workbook_Open|Auto_Open|AutoExec)", re.I)
MACRO_DANGEROUS = re.compile(rb"(Shell|CreateObject|powershell|WScript\.Shell|URLDownloadToFile|cmd\.exe)", re.I)

# Ransomware indicators (also used by the real-time ransomware guard)
RANSOM_EXT = {".locked", ".encrypted", ".crypt", ".crypted", ".lockbit", ".conti", ".ryk", ".wncry", ".wnry",
              ".cerber", ".locky", ".zepto", ".petya", ".djvu", ".akira", ".blackcat", ".basta", ".phobos",
              ".dharma", ".makop", ".medusa", ".rhysida"}
RANSOM_NOTE = re.compile(
    r"(how[_\- ]?to[_\- ]?(recover|decrypt|restore)|decrypt[_\- ]?(your[_\- ]?)?(files|instructions)"
    r"|(recover|restore)[_\- ]?(your[_\- ]?)?files|read[_\- ]?me[_\- ]?to[_\- ]?decrypt|^_?readme_for_decrypt)", re.I)


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
    def __init__(self, db: Optional[SignatureDB] = None, log: bool = True):
        self.db = db or SignatureDB()
        self.log = log  # ScanEngine logs centrally, so its worker processes pass log=False
        self.rules = self._load_rules()
        self.allow = self._load_allowlist()

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
        if not name and res.sha256 in self.allow:
            res.finalize()  # user-trusted file (known-bad hashes always win over the allowlist)
            return res
        if name:
            res.add(100, f"Known malware hash: {name}")
        if size <= 256 and EICAR_MARKER in sample:
            res.add(100, "EICAR antivirus test file")

        ext = p.suffix.lower()
        is_pe = sample[:2] == b"MZ"
        hard_hit = res.score >= 100                  # known-bad hash or EICAR: never softened by a signature
        pe_points = 0                                # points from program-structure heuristics only
        if is_pe and ext in DECOY_EXT:
            res.add(40, f"Executable disguised as a {ext} file")
            pe_points += 40
        # Office and Windows keep "name.docx.lnk" shortcuts in their recent-files folders; that is normal there
        if DOUBLE_EXT.search(p.name) and not (ext == ".lnk" and RECENT_LNK_DIR.search(str(p))):
            res.add(45, "Double extension (document name hiding a program)")
        if RANSOM_NOTE.search(p.name) or ext in RANSOM_EXT:
            res.add(35, "File name or extension matches ransomware activity")

        if is_pe:  # any size: padding a program past the size limit must not hide it
            before = res.score
            self._pe_checks(p, sample, ext, res)
            if size > config.MAX_HEURISTIC_SIZE:
                self._padding_check(p, size, res)
            pe_points += res.score - before
        if ext in SCRIPT_EXT:
            self._script_checks(p, res)
        if size <= config.MAX_HEURISTIC_SIZE:
            if sample[:4] == b"PK\x03\x04" and (ext in (".zip", ".jar") or ext in OFFICE_ZIP_EXT):
                self._zip_checks(p, ext, res)
            elif sample[:8] == OLE_MAGIC and ext in OLE_EXT:
                self._ole_checks(sample, res)
            if self.rules is not None:
                self._yara_checks(p, res)
        if ads.IS_WIN and ":" not in p.name:          # hidden NTFS streams (never recurse into a stream's streams)
            for sname, _size in ads.suspicious_streams(p)[:8]:
                self._ads_check(p, sname, res)
        # A valid Authenticode signature (verified offline by Windows) offsets program-structure heuristics such as
        # packers, entropy or imports. It never offsets a double extension, scripts, ransomware signs or known-bad
        # hashes, because signed tools can still be renamed or abused.
        if (is_pe and pe_points > 0 and not hard_hit and res.score >= config.SUSPICIOUS_THRESHOLD
                and authenticode.has_valid_signature(str(p))):
            cut = min(pe_points, 30)
            res.score -= cut
            res.reasons.append(f"Valid digital signature verified by Windows (risk lowered by {cut})")
        res.finalize()
        if self.log and res.verdict in (SUSPICIOUS, MALICIOUS):
            logger.get().warning("%s %s score=%d sha256=%s :: %s", res.verdict.upper(), res.path,
                                 res.score, res.sha256, "; ".join(res.reasons))
        return res

    def _ads_check(self, p: Path, sname: str, res: ScanResult):
        """Scan one hidden stream like a file. A program hidden in a stream is a strong sign by itself."""
        spath = f"{p}:{sname}"
        try:
            with open(spath, "rb") as f:
                head = f.read(4)
        except OSError:
            return
        sub = self.scan_file(spath)
        hidden_program = head[:2] == b"MZ"
        pts = (50 if hidden_program else 0) + (sub.score if sub.verdict != ERROR else 0)
        if pts >= 20:
            what = "a hidden program" if hidden_program else "hidden risky content"
            detail = ("; ".join(sub.reasons[:2])) if sub.reasons else ""
            res.add(min(pts, 100), f"Alternate data stream ':{sname}' holds {what}" + (f" ({detail})" if detail else ""))

    @staticmethod
    def _load_allowlist() -> set:
        try:
            lines = config.ALLOWLIST_FILE.read_text(errors="ignore").splitlines()
        except OSError:
            return set()
        out = set()
        for line in lines:
            parts = line.split()
            if parts and not parts[0].startswith("#") and len(parts[0]) == 64:
                out.add(parts[0].lower())
        return out

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
                if 4096 < s.SizeOfRawData <= (32 << 20) and s.get_entropy() > 7.4:  # cap: pure-Python entropy
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
                # Capped below the "suspicious" threshold: overlays, launchers, Chromium (libcef) and even
                # Defender import these APIs legitimately. Imports only corroborate other signals
                # (packing, disguise, hidden window...); they must never convict a file on their own.
                res.add(min(pts, 25), f"Uses process-injection style APIs: {', '.join(sorted(set(found)))}")
        finally:
            pe.close()

    @staticmethod
    def _zip_checks(p: Path, ext: str, res: ScanResult):
        """Inspect archives and OOXML Office files without extracting anything to disk."""
        try:
            zf = zipfile.ZipFile(p)
        except (zipfile.BadZipFile, OSError):
            return
        with zf:
            infos = zf.infolist()
            if len(infos) > MAX_ZIP_ENTRIES:
                res.add(10, "Archive with an unusually large number of entries")
                infos = infos[:MAX_ZIP_ENTRIES]
            total = sum(i.file_size for i in infos)
            comp = sum(i.compress_size for i in infos)
            if total > (1 << 30) or (total > (100 << 20) and comp and total / comp > 200):
                res.add(30, "Possible zip bomb (extreme compression ratio)")
            if any(i.flag_bits & 1 for i in infos):
                res.add(10, "Password-protected archive (contents cannot be scanned)")

            def read(info, cap=5 << 20):
                try:
                    return zf.read(info) if info.file_size <= cap else b""
                except Exception:
                    return b""

            if ext in OFFICE_ZIP_EXT:
                for i in infos:
                    low = i.filename.lower()
                    if low.endswith("vbaproject.bin"):
                        data = read(i)
                        res.add(25 if ext in MACRO_ENABLED_EXT else 45,
                                "Office document contains VBA macros" if ext in MACRO_ENABLED_EXT
                                else "Macros hidden inside a macro-free file type")
                        if MACRO_AUTORUN.search(data):
                            res.add(10, "Macro runs automatically when the document opens")
                        if MACRO_DANGEROUS.search(data):
                            res.add(20, "Macro can launch programs or download files")
                    elif low.endswith(".rels") and i.file_size < (1 << 20):
                        data = read(i)
                        if b"attachedTemplate" in data and b"External" in data and b"http" in data:
                            res.add(30, "Document loads a remote template (template injection)")
                return
            if ext == ".jar":
                return
            execs = []
            for i in infos:
                base = i.filename.replace("\\", "/").rsplit("/", 1)[-1]
                if DOUBLE_EXT.search(base):
                    res.add(40, f"Archive contains a disguised program: {base}")
                    break
                if os.path.splitext(base.lower())[1] in ARCHIVE_EXEC_EXT:
                    execs.append(base)
            if execs:
                res.add(25, f"Archive contains programs/scripts: {', '.join(execs[:3])}")

    @staticmethod
    def _ole_checks(sample: bytes, res: ScanResult):
        """Legacy .doc/.xls: look for VBA macro streams in the first MB."""
        if b"VBA" not in sample and b"_VBA_PROJECT" not in sample:
            return
        res.add(15, "Legacy Office document contains VBA macros")
        if MACRO_AUTORUN.search(sample):
            res.add(10, "Macro runs automatically when the document opens")
        if MACRO_DANGEROUS.search(sample):
            res.add(20, "Macro can launch programs or download files")

    @staticmethod
    def _padding_check(p: Path, size: int, res: ScanResult):
        """Malware is often padded with zeros to exceed scanners' size limits."""
        try:
            with open(p, "rb") as f:
                f.seek(max(0, size - (1 << 20)))
                tail = f.read(1 << 20)
        except OSError:
            return
        if tail and shannon_entropy(tail) < 0.5:
            res.add(40, "Oversized program padded with filler data (scanner evasion trick)")

    @staticmethod
    def _script_checks(p: Path, res: ScanResult):
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
        skip = {os.path.normcase(os.path.abspath(config.QUARANTINE_DIR))}
        for dirpath, dirnames, filenames in os.walk(root, followlinks=False):
            dirnames[:] = [d for d in dirnames
                           if os.path.normcase(os.path.abspath(os.path.join(dirpath, d))) not in skip]
            for fn in filenames:
                if cancel is not None and cancel.is_set():
                    return
                fp = os.path.join(dirpath, fn)
                if os.path.islink(fp):
                    continue
                yield self.scan_file(fp)


def add_to_allowlist(sha256: str, note: str = ""):
    """Trust a file hash so the scanner stops flagging it (false-positive handling)."""
    config.ensure_dirs()
    with open(config.ALLOWLIST_FILE, "a", encoding="utf-8") as f:
        f.write(f"{sha256.lower()} {note}".rstrip() + "\n")
