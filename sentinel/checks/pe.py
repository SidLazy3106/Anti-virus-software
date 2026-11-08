"""Windows program (PE) heuristics: packing, writable+executable sections, injection-style imports, padding."""
from __future__ import annotations

from pathlib import Path

from .. import config, logger
from ..entropy import shannon_entropy
from ..result import ScanResult
from ..winconst import IMAGE_SCN_MEM_EXECUTE, IMAGE_SCN_MEM_WRITE
from .base import Check


SUSPICIOUS_IMPORTS = {
    "VirtualAllocEx": 12, "WriteProcessMemory": 12, "CreateRemoteThread": 18,
    "NtUnmapViewOfSection": 18, "QueueUserAPC": 10, "NtQueueApcThread": 10,
    "SetWindowsHookExA": 8, "SetWindowsHookExW": 8, "GetAsyncKeyState": 8,
    "URLDownloadToFileA": 8, "URLDownloadToFileW": 8, "AdjustTokenPrivileges": 4,
}

try:
    import pefile
except ImportError:  # pragma: no cover - optional dependency
    pefile = None


def pe_checks(p: Path, sample: bytes, ext: str, res: ScanResult):
    if ext in {".exe", ".scr", ".com", ".pif"} and shannon_entropy(sample) > config.EXE_ENTROPY_PACKED:
        res.add(20, "Very high entropy (packed or encrypted)")
    if pefile is None:
        return
    try:
        pe = pefile.PE(str(p), fast_load=False)
    except Exception as e:   # hostile input: pefile can raise many types on malformed headers
        logger.get().debug("pefile could not parse %s: %s", p, e)
        return
    try:
        wx, high, upx = [], [], False
        for s in pe.sections:
            name = s.Name.rstrip(b"\x00").decode(errors="ignore")
            ch = s.Characteristics
            if ch & IMAGE_SCN_MEM_EXECUTE and ch & IMAGE_SCN_MEM_WRITE:
                wx.append(name)
            if (config.SECTION_ENTROPY_MIN_BYTES < s.SizeOfRawData <= config.SECTION_ENTROPY_MAX_BYTES
                    and s.get_entropy() > config.SECTION_ENTROPY_PACKED):
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


def padding_check(p: Path, size: int, res: ScanResult):
    """Malware is often padded with zeros to exceed scanners' size limits."""
    try:
        with open(p, "rb") as f:
            f.seek(max(0, size - config.PADDING_TAIL_BYTES))
            tail = f.read(config.PADDING_TAIL_BYTES)
    except OSError:
        return
    if tail and shannon_entropy(tail) < config.PADDING_MAX_ENTROPY:
        res.add(40, "Oversized program padded with filler data (scanner evasion trick)")


class PeHeuristicsCheck(Check):
    name = "pe-heuristics"
    structural = True            # program-structure points: a valid signature may offset them

    def applies(self, ctx):
        return ctx.is_pe         # any size: padding a program past the size limit must not hide it

    def run(self, ctx):
        pe_checks(ctx.path, ctx.sample, ctx.ext, ctx.result)
        if ctx.size > config.MAX_HEURISTIC_SIZE:
            padding_check(ctx.path, ctx.size, ctx.result)
