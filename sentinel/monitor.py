"""Real-time protection (user mode): file watcher, ransomware guard, process-chain watcher."""
from __future__ import annotations

import os
import queue
import sys
import threading
import time
from collections import deque
from dataclasses import dataclass
from pathlib import Path

from . import quarantine
from .scanner import MALICIOUS, SUSPICIOUS, Scanner

try:
    from watchdog.events import FileSystemEventHandler
    from watchdog.observers import Observer
except ImportError:  # optional until real-time protection is started
    Observer = None
    FileSystemEventHandler = object

try:
    import psutil
except ImportError:
    psutil = None


@dataclass
class Alert:
    source: str      # "file", "ransomware", "process"
    severity: str    # "info", "warning", "high", "critical"
    message: str
    detail: str = ""
    time: float = 0.0

    def __post_init__(self):
        self.time = self.time or time.time()

    def __str__(self):
        stamp = time.strftime("%H:%M:%S", time.localtime(self.time))
        return f"[{stamp}] {self.severity.upper():8} {self.source}: {self.message}"


class RansomwareGuard:
    """Decoy (canary) files plus a file-change-rate check."""

    CANARY_NAMES = ("_sentinel_canary.docx", "_sentinel_canary.xlsx")

    def __init__(self, on_alert, window=5.0, limit=60):
        self.on_alert = on_alert
        self.window, self.limit = window, limit
        self.canaries: set[str] = set()
        self.events: deque = deque()
        self._last_rate_alert = 0.0

    @staticmethod
    def _norm(p) -> str:
        return os.path.normcase(os.path.abspath(str(p)))

    def create_canaries(self, folders):
        for folder in folders:
            for name in self.CANARY_NAMES:
                p = Path(folder) / name
                try:
                    p.write_text("Sentinel canary file. Do not edit. If this changes, something is encrypting your files.\n")
                    if sys.platform == "win32":
                        import ctypes
                        ctypes.windll.kernel32.SetFileAttributesW(str(p), 0x2)  # hidden
                    self.canaries.add(self._norm(p))
                except OSError:
                    pass

    def remove_canaries(self):
        for c in list(self.canaries):
            try:
                os.remove(c)
            except OSError:
                pass
        self.canaries.clear()

    def event(self, path, kind):
        n = self._norm(path)
        if n in self.canaries and kind in ("modified", "deleted", "moved"):
            self.on_alert(Alert("ransomware", "critical",
                                f"Canary file {kind}: possible ransomware activity", str(path)))
            return
        if kind == "modified":
            now = time.time()
            self.events.append(now)
            while self.events and now - self.events[0] > self.window:
                self.events.popleft()
            if len(self.events) >= self.limit and now - self._last_rate_alert > 30:
                self._last_rate_alert = now
                self.on_alert(Alert("ransomware", "warning",
                                    f"{len(self.events)} files modified in {self.window:.0f}s (unusual rate)"))


class _Handler(FileSystemEventHandler):
    def __init__(self, mon):
        self.mon = mon

    def on_created(self, e):
        if not e.is_directory:
            self.mon.enqueue(e.src_path, "created")

    def on_modified(self, e):
        if not e.is_directory:
            self.mon.enqueue(e.src_path, "modified")

    def on_moved(self, e):
        if not e.is_directory:
            self.mon.guard.event(e.src_path, "moved")
            self.mon.enqueue(e.dest_path, "created")

    def on_deleted(self, e):
        if not e.is_directory:
            self.mon.guard.event(e.src_path, "deleted")


class RealtimeMonitor:
    IGNORE_SUFFIX = (".crdownload", ".part", ".partial", ".tmp", ".download")

    def __init__(self, scanner: Scanner, paths, on_alert, auto_quarantine=False, canaries=False):
        self.scanner, self.paths, self.on_alert = scanner, [str(p) for p in paths], on_alert
        self.auto_quarantine, self.use_canaries = auto_quarantine, canaries
        self.guard = RansomwareGuard(on_alert)
        self._q: queue.Queue = queue.Queue()
        self._stop = threading.Event()
        self._observer = None
        self._worker = None
        self._seen: dict = {}

    def start(self):
        if Observer is None:
            raise RuntimeError("Real-time protection needs the 'watchdog' package (pip install watchdog).")
        if self.use_canaries:
            self.guard.create_canaries(self.paths)
        self._observer = Observer()
        for p in self.paths:
            self._observer.schedule(_Handler(self), p, recursive=True)
        self._observer.start()
        self._worker = threading.Thread(target=self._run, daemon=True)
        self._worker.start()

    def stop(self):
        self._stop.set()
        if self._observer:
            self._observer.stop()
            self._observer.join(timeout=3)
        self.guard.remove_canaries()

    def enqueue(self, path, kind):
        self.guard.event(path, kind)
        if self.guard._norm(path) in self.guard.canaries:
            return
        if path.lower().endswith(self.IGNORE_SUFFIX):
            return
        self._q.put(path)

    def _wait_stable(self, path, tries=20):
        last = -1
        for _ in range(tries):
            try:
                size = os.path.getsize(path)
            except OSError:
                return False
            if size == last:
                return True
            last = size
            time.sleep(0.5)
        return False

    def _run(self):
        while not self._stop.is_set():
            try:
                path = self._q.get(timeout=0.5)
            except queue.Empty:
                continue
            if not self._wait_stable(path):
                continue
            try:
                st = os.stat(path)
            except OSError:
                continue
            key = (st.st_mtime_ns, st.st_size)
            if self._seen.get(path) == key:
                continue
            self._seen[path] = key
            res = self.scanner.scan_file(path)
            if res.verdict not in (SUSPICIOUS, MALICIOUS):
                continue
            msg = f"{res.verdict.upper()}: {os.path.basename(path)}"
            if res.verdict == MALICIOUS and self.auto_quarantine:
                try:
                    quarantine.quarantine_file(path, "; ".join(res.reasons), res.sha256)
                    msg += " (quarantined)"
                except Exception as e:
                    msg += f" (quarantine failed: {e})"
            self.on_alert(Alert("file", "high" if res.verdict == MALICIOUS else "warning",
                                msg, "; ".join(res.reasons)))


# parent process -> children that are suspicious to see spawned from it
OFFICE = {"winword", "excel", "powerpnt", "outlook", "acrord32", "acrobat", "msaccess"}
SHELLS = {"powershell", "pwsh", "cmd", "wscript", "cscript", "mshta", "rundll32", "regsvr32"}
SUSPICIOUS_CHAINS = {p: SHELLS for p in OFFICE}
SUSPICIOUS_CHAINS.update({"mshta": {"powershell", "pwsh", "cmd"}, "wscript": {"powershell", "pwsh", "cmd"}})
RISKY_DIRS = ("\\temp\\", "\\appdata\\local\\temp", "\\users\\public\\", "\\downloads\\")


def _stem(name: str) -> str:
    n = (name or "").lower()
    return n[:-4] if n.endswith(".exe") else n


class ProcessWatcher:
    """Polls for new processes and flags suspicious parent/child chains and risky launches."""

    def __init__(self, on_alert, interval=1.0):
        self.on_alert, self.interval = on_alert, interval
        self._stop = threading.Event()
        self._known: set = set()
        self._thread = None

    def start(self):
        if psutil is None:
            raise RuntimeError("Process watching needs 'psutil' (pip install psutil).")
        self._known = {p.pid for p in psutil.process_iter()}
        self._thread = threading.Thread(target=self._run, daemon=True)
        self._thread.start()

    def stop(self):
        self._stop.set()

    def _run(self):
        while not self._stop.wait(self.interval):
            for p in psutil.process_iter(["pid", "name", "ppid", "exe", "cmdline"]):
                if p.pid in self._known:
                    continue
                self._known.add(p.pid)
                try:
                    self._inspect(p)
                except (psutil.Error, OSError):
                    pass

    def _inspect(self, p):
        name = _stem(p.info.get("name"))
        cmd = " ".join(p.info.get("cmdline") or [])
        parent = psutil.Process(p.info["ppid"]).name() if p.info.get("ppid") else ""
        pstem = _stem(parent)
        if name in SUSPICIOUS_CHAINS.get(pstem, ()):
            self.on_alert(Alert("process", "high",
                                f"{parent} spawned {p.info['name']} (common malware chain)", cmd[:300]))
        if name in ("powershell", "pwsh") and "-enc" in cmd.lower():
            self.on_alert(Alert("process", "high", "PowerShell started with an encoded command", cmd[:300]))
        exe = (p.info.get("exe") or "").lower()
        if exe and any(d in exe for d in RISKY_DIRS):
            self.on_alert(Alert("process", "info", f"{p.info['name']} launched from a temp/downloads folder", exe))
