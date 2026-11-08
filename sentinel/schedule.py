"""Scheduled scans through Windows Task Scheduler (per-user task: no administrator rights needed).

The task runs `main.py quickscan --scheduled` (or fullscan) with pythonw, so no console window appears. The scan
writes its result to ~/.x-secure/last_scheduled_scan.json (the app shows it) and only pops up a message when
something was flagged. Turning the schedule off deletes the task; nothing else is changed.
"""
from __future__ import annotations

import json
import re
import subprocess
import sys
import time
from pathlib import Path
from typing import Optional

from . import config

TASK = r"X-Secure\Scheduled Scan"
DAYS = ("MON", "TUE", "WED", "THU", "FRI", "SAT", "SUN")
HHMM = re.compile(r"^([01]?\d|2[0-3]):([0-5]\d)$")


def _schtasks(*args) -> subprocess.CompletedProcess:
    return subprocess.run(["schtasks", *args], capture_output=True, text=True, errors="replace", timeout=30,
                          creationflags=getattr(subprocess, "CREATE_NO_WINDOW", 0))


def result_file() -> Path:
    return config.DATA_DIR / "last_scheduled_scan.json"


def task_command(kind: str = "quickscan") -> str:
    """The command line the task runs. Uses pythonw (no console window) when it exists."""
    if getattr(sys, "frozen", False):                       # PyInstaller build: use the windowed exe (no console)
        gui = Path(sys.executable).with_name("X-Secure.exe")
        return f'"{gui if gui.exists() else sys.executable}" {kind} --scheduled'
    exe = Path(sys.executable)
    pyw = exe.with_name("pythonw.exe")
    main = Path(__file__).resolve().parent.parent / "main.py"
    return f'"{pyw if pyw.exists() else exe}" "{main}" {kind} --scheduled'


def create(at: str, kind: str = "quickscan", weekly_day: Optional[str] = None) -> tuple:
    """(ok, message). at = 'HH:MM' (24h). Daily unless weekly_day ('MON'..'SUN') is given."""
    m = HHMM.match(at.strip())
    if not m:
        return False, "Use a 24-hour time like 13:00."
    if kind not in ("quickscan", "fullscan"):
        return False, "Scan type must be quickscan or fullscan."
    at = f"{int(m.group(1)):02d}:{m.group(2)}"
    cmd = task_command(kind)
    if len(cmd) > 261:
        return False, "The install path is too long for Task Scheduler (261 characters max)."
    args = ["/Create", "/TN", TASK, "/TR", cmd, "/ST", at, "/F"]
    if weekly_day:
        day = weekly_day.upper()[:3]
        if day not in DAYS:
            return False, "Day must be one of " + ", ".join(DAYS)
        args += ["/SC", "WEEKLY", "/D", day]
        when = f"every {day.title()} at {at}"
    else:
        args += ["/SC", "DAILY"]
        when = f"every day at {at}"
    r = _schtasks(*args)
    if r.returncode != 0:
        return False, (r.stderr or r.stdout).strip() or "Task Scheduler refused the task."
    if query() is None:                                   # verify it really exists
        return False, "Task Scheduler did not keep the task."
    label = "Quick scan" if kind == "quickscan" else "Full PC scan"
    return True, f"{label} scheduled {when}."


def query() -> Optional[dict]:
    """The task's details, or None if no schedule exists."""
    r = _schtasks("/Query", "/TN", TASK, "/FO", "LIST", "/V")
    if r.returncode != 0:
        return None
    info = {}
    for line in r.stdout.splitlines():
        if ":" in line:
            k, v = line.split(":", 1)
            info.setdefault(k.strip(), v.strip())
    return info


def describe() -> str:
    q = query()
    if q is None:
        return "Off"
    nxt = q.get("Next Run Time", "")
    kind = "Full PC scan" if "fullscan" in q.get("Task To Run", "") else "Quick scan"
    return f"{kind}, next run {nxt}" if nxt and nxt.upper() != "N/A" else kind


def remove() -> tuple:
    if query() is None:
        return True, "No scheduled scan was set."
    r = _schtasks("/Delete", "/TN", TASK, "/F")
    ok = r.returncode == 0 and query() is None
    return ok, "Scheduled scan turned off." if ok else (r.stderr or r.stdout).strip()


def run_now() -> tuple:
    r = _schtasks("/Run", "/TN", TASK)
    return r.returncode == 0, (r.stdout or r.stderr).strip()


def save_result(kind: str, stats, flagged: list):
    config.ensure_dirs()
    result_file().write_text(json.dumps({
        "time": time.time(), "kind": kind, "files": stats.files, "cached": stats.cached, "threats": stats.threats,
        "seconds": round(stats.elapsed, 1), "flagged": flagged[:200]}, indent=1), encoding="utf-8")


def last_result() -> Optional[dict]:
    try:
        return json.loads(result_file().read_text(encoding="utf-8"))
    except (OSError, ValueError):
        return None


def notify(threats: int):
    """Small Windows message box after an unattended scan that found something."""
    if sys.platform != "win32" or not threats:
        return
    import ctypes
    ctypes.windll.user32.MessageBoxW(
        None, f"The scheduled X-Secure scan flagged {threats} item(s).\n\nOpen X-Secure and go to Scan to review "
              f"them. Nothing was deleted or quarantined automatically.", "X-Secure scheduled scan",
        0x30 | 0x40000)  # MB_ICONWARNING | MB_TOPMOST
