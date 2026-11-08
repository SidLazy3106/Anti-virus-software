"""Scan orchestration: fast file enumeration, result cache, parallel workers, and the full-PC scan plan.

Scanner.scan_file() decides what a single file is. This module decides *which* files to scan, *in what
order*, skips files that have not changed since a previous clean scan, and spreads the work across CPU cores.
"""
from __future__ import annotations

import hashlib
import json
import os
import sqlite3
import stat as stat_mod
import sys
import time
from concurrent.futures import FIRST_COMPLETED, ProcessPoolExecutor, wait
from concurrent.futures.process import BrokenProcessPool
from dataclasses import dataclass
from pathlib import Path
from typing import Iterable, Iterator, Optional

from . import config, logger
from .scanner import ERROR, MALICIOUS, SUSPICIOUS, ScanResult, Scanner

IS_WIN = sys.platform == "win32"
# Locked or virtual system files: reading them only produces errors.
SKIP_FILES = {"pagefile.sys", "hiberfil.sys", "swapfile.sys", "dumpstack.log.tmp"}
FILE_ATTRIBUTE_OFFLINE = 0x1000
FILE_ATTRIBUTE_RECALL_ON_DATA_ACCESS = 0x400000   # OneDrive "online-only": reading would download it
FILE_ATTRIBUTE_RECALL_ON_OPEN = 0x40000
IO_REPARSE_TAG_MOUNT_POINT = 0xA0000003
CACHE_MAX_AGE = 7 * 24 * 3600                       # re-verify every file at least weekly


def _norm(p) -> str:
    return os.path.normcase(os.path.abspath(str(p)))


def _inside(path_norm: str, roots: Iterable[str]) -> bool:
    return any(path_norm == r or path_norm.startswith(r.rstrip(os.sep) + os.sep) for r in roots)


# ─────────────────────────────────────────────────────────────── enumeration
@dataclass
class ScanStats:
    files: int = 0          # files examined (scanned + served from cache)
    cached: int = 0         # unchanged files answered from the cache
    threats: int = 0
    errors: int = 0         # files that could not be read (locked, access denied)
    skipped: int = 0        # cloud-only placeholders and locked system files
    dirs_denied: int = 0    # folders we were not allowed to list
    bytes: int = 0
    started: float = 0.0
    finished: float = 0.0

    @property
    def elapsed(self) -> float:
        return (self.finished or time.time()) - self.started


def _is_junction(entry: os.DirEntry) -> bool:
    fn = getattr(entry, "is_junction", None)  # Python 3.12+
    if fn is not None:
        return fn()
    if not IS_WIN:
        return False
    try:
        return os.lstat(entry.path).st_reparse_tag == IO_REPARSE_TAG_MOUNT_POINT
    except (OSError, AttributeError):
        return False


def iter_files(roots, exclude=(), stats: Optional[ScanStats] = None) -> Iterator[tuple]:
    """Yield (path, size, mtime_ns) for every regular file under `roots`.

    * never follows symlinks or junctions (no loops, no double counting via "C:\\Users\\All Users")
    * each file is yielded once even if roots overlap; earlier roots win
    * skips cloud-only files instead of silently downloading the user's whole OneDrive
    """
    stats = stats if stats is not None else ScanStats()
    excl = {_norm(e) for e in exclude}
    done: list = []
    for root in roots:
        r = _norm(root)
        if r in excl or _inside(r, done) or _inside(r, excl):
            continue
        if os.path.isfile(r):
            try:
                st = os.stat(r)
                yield r, st.st_size, st.st_mtime_ns
            except OSError:
                stats.errors += 1
            continue
        prune = excl | set(done)
        stack = [r]
        while stack:
            d = stack.pop()
            try:
                it = os.scandir(d)
            except OSError:
                stats.dirs_denied += 1
                continue
            with it:
                while True:
                    try:
                        e = next(it)
                    except StopIteration:
                        break
                    except OSError:
                        stats.dirs_denied += 1
                        break
                    try:
                        if e.is_symlink() or _is_junction(e):
                            continue
                        if e.is_dir(follow_symlinks=False):
                            if _norm(e.path) not in prune:
                                stack.append(e.path)
                            continue
                        if not e.is_file(follow_symlinks=False):
                            continue
                        if e.name.lower() in SKIP_FILES:
                            stats.skipped += 1
                            continue
                        st = e.stat(follow_symlinks=False)
                        attrs = getattr(st, "st_file_attributes", 0)
                        if attrs & (FILE_ATTRIBUTE_OFFLINE | FILE_ATTRIBUTE_RECALL_ON_DATA_ACCESS
                                    | FILE_ATTRIBUTE_RECALL_ON_OPEN):
                            stats.skipped += 1
                            continue
                        if not stat_mod.S_ISREG(st.st_mode):
                            continue
                        yield e.path, st.st_size, st.st_mtime_ns
                    except OSError:
                        stats.errors += 1
        done.append(r)


# ─────────────────────────────────────────────────────────────── scan plans
def _env_path(*names_and_parts) -> Optional[str]:
    var, *parts = names_and_parts
    base = os.environ.get(var)
    return os.path.join(base, *parts) if base else None


def priority_locations() -> list:
    """Where malware usually lands or persists. Scanned first in every quick/full scan."""
    home = Path.home()
    cands = [
        _env_path("APPDATA", r"Microsoft\Windows\Start Menu\Programs\Startup"),
        _env_path("ProgramData", r"Microsoft\Windows\Start Menu\Programs\StartUp"),
        _env_path("TEMP"),
        _env_path("SystemRoot", "Temp"),
        str(home / "Downloads"),
        str(home / "Desktop"),
        _env_path("APPDATA"),
        _env_path("LOCALAPPDATA"),
        _env_path("PUBLIC"),
        _env_path("ProgramData"),
    ]
    out, seen = [], set()
    for c in cands:
        if c and os.path.isdir(c) and _norm(c) not in seen:
            seen.add(_norm(c))
            out.append(c)
    return out


def fixed_drives() -> list:
    if not IS_WIN:
        return ["/"]
    import ctypes
    k32 = ctypes.windll.kernel32
    mask, drives = k32.GetLogicalDrives(), []
    for i in range(26):
        if mask & (1 << i):
            root = f"{chr(65 + i)}:\\"
            if k32.GetDriveTypeW(ctypes.c_wchar_p(root)) == 3:  # DRIVE_FIXED (skips USB sticks, DVD, network)
                drives.append(root)
    return drives


def default_excludes() -> list:
    """Our own data (quarantine, cache, logs) and WinSxS, which only holds Microsoft-signed component copies."""
    ex = [str(config.DATA_DIR)]
    winsxs = _env_path("SystemRoot", "WinSxS")
    if winsxs:
        ex.append(winsxs)
    return ex


def quick_scan_plan():
    return priority_locations(), default_excludes()


def full_scan_plan():
    return priority_locations() + fixed_drives(), default_excludes()


# ─────────────────────────────────────────────────────────────── cache
def rules_fingerprint() -> str:
    """Changes whenever detection could change: scanner code, signatures, rules, allowlist, optional libs."""
    h = hashlib.sha256()
    for mod in ("scanner.py", "ads.py", "authenticode.py"):           # every module that affects verdicts
        try:
            h.update(Path(__file__).with_name(mod).read_bytes())
        except OSError:                    # packaged (PyInstaller) build has no .py files: the build identifies the code
            exe = Path(sys.executable)
            h.update(f"{config.VERSION}:{exe}:{exe.stat().st_mtime_ns if exe.exists() else 0}".encode())
            break
    h.update(f"{config.SUSPICIOUS_THRESHOLD}/{config.MALICIOUS_THRESHOLD}/{config.MAX_HEURISTIC_SIZE}".encode())
    from . import scanner as _s
    h.update(f"pefile={_s.pefile is not None};yara={_s.yara is not None}".encode())
    files = []
    for d in (config.SIGNATURES_DIR, config.UPDATED_SIGS_DIR, config.RULES_DIR):
        if Path(d).is_dir():
            files += sorted(Path(d).iterdir())
    files.append(config.ALLOWLIST_FILE)
    for f in files:
        try:
            st = f.stat()
            h.update(f"{f.name}:{st.st_size}:{st.st_mtime_ns};".encode())
        except OSError:
            h.update(f"{f.name}:missing;".encode())
    return h.hexdigest()


class ScanCache:
    """SQLite memory of earlier verdicts, keyed by path and valid only while size+mtime+fingerprint match."""

    def __init__(self, path=None, fingerprint: str = "", max_age: float = CACHE_MAX_AGE):
        config.ensure_dirs()
        self.path = Path(path or config.DATA_DIR / "scan_cache.sqlite")
        self.fp, self.max_age = fingerprint, max_age
        self.db = sqlite3.connect(str(self.path), timeout=30)
        self.db.execute("PRAGMA journal_mode=WAL")
        self.db.execute("CREATE TABLE IF NOT EXISTS files (path TEXT PRIMARY KEY, size INTEGER, mtime_ns INTEGER,"
                        " fp TEXT, sha256 TEXT, verdict TEXT, score INTEGER, reasons TEXT, scanned REAL)")
        self._pending: list = []

    def get(self, path: str, size: int, mtime_ns: int) -> Optional[ScanResult]:
        row = self.db.execute("SELECT size, mtime_ns, fp, sha256, verdict, score, reasons, scanned FROM files"
                              " WHERE path=?", (_norm(path),)).fetchone()
        if not row or row[0] != size or row[1] != mtime_ns or row[2] != self.fp:
            return None
        if time.time() - row[7] > self.max_age:
            return None
        return ScanResult(path=path, verdict=row[4], score=row[5], sha256=row[3], reasons=json.loads(row[6]))

    def put(self, res: ScanResult, size: int, mtime_ns: int):
        if res.verdict == ERROR:
            return
        self._pending.append((_norm(res.path), size, mtime_ns, self.fp, res.sha256, res.verdict, res.score,
                              json.dumps(res.reasons), time.time()))
        if len(self._pending) >= 500:
            self.flush()

    def flush(self):
        if self._pending:
            self.db.executemany("INSERT OR REPLACE INTO files VALUES (?,?,?,?,?,?,?,?,?)", self._pending)
            self.db.commit()
            self._pending.clear()

    def close(self):
        try:
            self.flush()
        finally:
            self.db.close()


# ─────────────────────────────────────────────────────────────── workers
_worker_scanner: Optional[Scanner] = None


def _lower_priority():
    try:
        if IS_WIN:
            import ctypes
            k32 = ctypes.windll.kernel32
            k32.SetPriorityClass(k32.GetCurrentProcess(), 0x00004000)  # BELOW_NORMAL_PRIORITY_CLASS
        else:
            os.nice(10)
    except Exception:
        pass


def _init_worker(low_priority: bool):
    global _worker_scanner
    if low_priority:
        _lower_priority()
    _worker_scanner = Scanner(log=False)  # the parent process logs; avoids several writers on one log file


def _scan_in_worker(path: str) -> ScanResult:
    return _worker_scanner.scan_file(path)


def default_workers() -> int:
    return max(1, min(8, (os.cpu_count() or 2) - 1))


class ScanEngine:
    """Scan many files quickly: cached results for unchanged files, a process pool for the rest."""

    def __init__(self, workers: Optional[int] = None, use_cache: bool = True, cache_path=None,
                 low_priority: bool = True):
        self.workers = max(1, workers if workers is not None else default_workers())
        self.use_cache, self.cache_path, self.low_priority = use_cache, cache_path, low_priority
        self.stats = ScanStats()

    def scan(self, roots, exclude=(), cancel=None) -> Iterator[ScanResult]:
        """Yield a ScanResult for every file. Read self.stats for totals (also while running)."""
        stats = self.stats = ScanStats(started=time.time())
        cache = ScanCache(self.cache_path, rules_fingerprint()) if self.use_cache else None
        log = logger.get()
        cancelled = (lambda: cancel is not None and cancel.is_set())
        local: Optional[Scanner] = None

        def record(res: ScanResult, size: int, mtime: int, from_cache: bool):
            stats.files += 1
            stats.bytes += size
            if from_cache:
                stats.cached += 1
            elif cache is not None:
                cache.put(res, size, mtime)
            if res.verdict == ERROR:
                stats.errors += 1
            elif res.verdict in (SUSPICIOUS, MALICIOUS):
                stats.threats += 1
                if not from_cache:
                    log.warning("%s %s score=%d sha256=%s :: %s", res.verdict.upper(), res.path, res.score,
                                res.sha256, "; ".join(res.reasons))
            return res

        def scan_local(path):
            nonlocal local
            if local is None:
                local = Scanner(log=False)
            return local.scan_file(path)

        files = iter_files(roots, exclude, stats)
        try:
            if self.workers == 1:
                for path, size, mtime in files:
                    if cancelled():
                        break
                    hit = cache.get(path, size, mtime) if cache else None
                    yield record(hit or scan_local(path), size, mtime, hit is not None)
                return

            pool = ProcessPoolExecutor(max_workers=self.workers, initializer=_init_worker,
                                       initargs=(self.low_priority,))
            pending: dict = {}
            exhausted = broken = False
            try:
                while True:
                    # keep a bounded number of files in flight (memory stays flat on million-file drives)
                    while not exhausted and not cancelled() and len(pending) < self.workers * 4:
                        try:
                            path, size, mtime = next(files)
                        except StopIteration:
                            exhausted = True
                            break
                        hit = cache.get(path, size, mtime) if cache else None
                        if hit is not None:
                            yield record(hit, size, mtime, True)
                            continue
                        if broken:
                            yield record(scan_local(path), size, mtime, False)
                            continue
                        try:
                            pending[pool.submit(_scan_in_worker, path)] = (path, size, mtime)
                        except (BrokenProcessPool, RuntimeError):
                            broken = True  # a worker died: finish the job in this process
                            yield record(scan_local(path), size, mtime, False)
                    if cancelled():
                        for f in pending:
                            f.cancel()
                        break
                    if not pending:
                        if exhausted:
                            break
                        continue
                    done, _ = wait(pending, timeout=0.5, return_when=FIRST_COMPLETED)
                    for f in done:
                        path, size, mtime = pending.pop(f)
                        try:
                            res = f.result()
                        except BrokenProcessPool:
                            broken = True
                            res = scan_local(path)
                        except Exception as e:  # never lose a file because a worker failed
                            res = ScanResult(path=path, verdict=ERROR, reasons=[f"Scan failed: {e}"])
                        yield record(res, size, mtime, False)
            finally:
                pool.shutdown(wait=True, cancel_futures=True)
        finally:
            stats.finished = time.time()
            if cache is not None:
                cache.close()
