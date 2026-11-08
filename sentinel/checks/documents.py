"""Archive and Office-document inspection (nothing is extracted to disk)."""
from __future__ import annotations

import os
import re
import zipfile
import zlib
from pathlib import Path

from .. import config
from ..result import ScanResult
from .base import Check
from .identity import DOUBLE_EXT


ARCHIVE_EXEC_EXT = {".exe", ".scr", ".com", ".pif", ".dll", ".bat", ".cmd", ".vbs", ".vbe", ".js", ".jse",
                    ".hta", ".lnk", ".ps1", ".wsf", ".msi"}
OFFICE_ZIP_EXT = {".docx", ".docm", ".xlsx", ".xlsm", ".pptx", ".pptm", ".dotm", ".xltm"}
MACRO_ENABLED_EXT = {".docm", ".xlsm", ".pptm", ".dotm", ".xltm"}
OLE_EXT = {".doc", ".xls", ".ppt", ".dot", ".xlt"}
OLE_MAGIC = b"\xd0\xcf\x11\xe0\xa1\xb1\x1a\xe1"
MAX_ZIP_ENTRIES = config.MAX_ZIP_ENTRIES
# What zipfile raises for corrupt, encrypted or unsupported members
ZIP_READ_ERRORS = (zipfile.BadZipFile, RuntimeError, NotImplementedError, zlib.error, EOFError, OSError, ValueError)
MACRO_AUTORUN = re.compile(rb"(AutoOpen|Document_Open|Workbook_Open|Auto_Open|AutoExec)", re.I)
MACRO_DANGEROUS = re.compile(rb"(Shell|CreateObject|powershell|WScript\.Shell|URLDownloadToFile|cmd\.exe)", re.I)


def zip_checks(p: Path, ext: str, res: ScanResult):
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
        if total > config.ZIP_BOMB_TOTAL_BYTES or (total > config.ZIP_BOMB_MIN_BYTES and comp
                                              and total / comp > config.ZIP_BOMB_RATIO):
            res.add(30, "Possible zip bomb (extreme compression ratio)")
        if any(i.flag_bits & 1 for i in infos):
            res.add(10, "Password-protected archive (contents cannot be scanned)")

        def read(info, cap=config.ZIP_MEMBER_READ_CAP):
            try:
                return zf.read(info) if info.file_size <= cap else b""
            except ZIP_READ_ERRORS:     # corrupt, encrypted or unsupported member: skip it
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


def ole_checks(sample: bytes, res: ScanResult):
    """Legacy .doc/.xls: look for VBA macro streams in the first MB."""
    if b"VBA" not in sample and b"_VBA_PROJECT" not in sample:
        return
    res.add(15, "Legacy Office document contains VBA macros")
    if MACRO_AUTORUN.search(sample):
        res.add(10, "Macro runs automatically when the document opens")
    if MACRO_DANGEROUS.search(sample):
        res.add(20, "Macro can launch programs or download files")


class ArchiveCheck(Check):
    """Zip/jar archives and OOXML Office files."""
    name = "archive"

    def applies(self, ctx):
        return (ctx.size <= config.MAX_HEURISTIC_SIZE and ctx.sample[:4] == b"PK\x03\x04"
                and (ctx.ext in (".zip", ".jar") or ctx.ext in OFFICE_ZIP_EXT))

    def run(self, ctx):
        zip_checks(ctx.path, ctx.ext, ctx.result)


class LegacyOfficeCheck(Check):
    """Legacy OLE documents (.doc/.xls/...): VBA macro streams in the first part of the file."""
    name = "legacy-office"

    def applies(self, ctx):
        return ctx.size <= config.MAX_HEURISTIC_SIZE and ctx.sample[:8] == OLE_MAGIC and ctx.ext in OLE_EXT

    def run(self, ctx):
        ole_checks(ctx.sample, ctx.result)
