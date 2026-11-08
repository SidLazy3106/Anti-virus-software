"""Read-only measurements: CPU/RAM snapshot, per-program process groups, disk activity."""
from __future__ import annotations

import ctypes
import os
import platform
import time
from typing import Optional

from ..platform_utils import IS_WIN, psutil
from . import power
from .models import ProcGroup, Snapshot
from .protected import PROTECTED_PROCS, PROTECTED_RX


# ── measuring ────────────────────────────────────────────────────────────
def take_snapshot(cpu_interval: float = 1.0) -> Snapshot:
    s = Snapshot(taken=time.time(), os_name=platform.platform(terse=True))
    if psutil is None:
        return s
    s.cpu = psutil.cpu_percent(interval=cpu_interval)
    vm = psutil.virtual_memory()
    s.ram_total, s.ram_used, s.ram_pct = vm.total, vm.total - vm.available, vm.percent
    try:
        du = psutil.disk_usage(os.environ.get("SystemDrive", "C:") + "\\" if IS_WIN else "/")
        s.disk_pct, s.disk_free = du.percent, du.free
    except OSError:
        pass
    s.process_count = len(psutil.pids())
    s.power_plan = power.active_plan()[1] if IS_WIN else "n/a"
    return s


def _windowed_pids() -> set[int]:
    """PIDs that own at least one visible, titled top-level window (i.e. apps the user can see)."""
    pids: set = set()
    if not IS_WIN:
        return pids
    user32 = ctypes.windll.user32
    proto = ctypes.WINFUNCTYPE(ctypes.c_bool, ctypes.c_void_p, ctypes.c_void_p)

    def cb(hwnd, _lp):
        if user32.IsWindowVisible(hwnd) and user32.GetWindowTextLengthW(hwnd) > 0:
            pid = ctypes.c_ulong()
            user32.GetWindowThreadProcessId(hwnd, ctypes.byref(pid))
            pids.add(pid.value)
        return True

    try:
        user32.EnumWindows(proto(cb), 0)
    except (OSError, ctypes.ArgumentError):   # no window list: treat every process as windowless
        pass
    return pids


def _is_system_path(path: str) -> bool:
    p = os.path.normcase(path or "")
    root = os.path.normcase(os.environ.get("SystemRoot", r"C:\Windows"))
    return p.startswith(root + os.sep) or "windows defender" in p


def measure_process_groups(sample: float = 2.0, cancel=None) -> list[ProcGroup]:
    """Group processes by program name and measure memory and CPU over `sample` seconds."""
    if psutil is None:
        return []
    procs = []
    for p in psutil.process_iter(["pid", "name", "exe", "memory_info"]):
        try:
            p.cpu_percent(None)  # prime
            procs.append(p)
        except psutil.Error:
            continue
    (cancel.wait(sample) if cancel is not None else time.sleep(sample))
    windowed = _windowed_pids()
    ncpu = psutil.cpu_count() or 1
    me = os.getpid()
    groups: dict = {}
    for p in procs:
        try:
            if p.pid == me:
                continue
            name = (p.info.get("name") or "?")
            mem = p.info.get("memory_info")
            cpu = p.cpu_percent(None) / ncpu
            exe = p.info.get("exe") or ""
            g = groups.setdefault(name.lower(), {"name": name, "count": 0, "rss": 0, "cpu": 0.0,
                                                 "windowed": False, "protected": False})
            g["count"] += 1
            g["rss"] += mem.rss if mem else 0
            g["cpu"] += cpu
            g["windowed"] |= p.pid in windowed
            g["protected"] |= name.lower() in PROTECTED_PROCS or _is_system_path(exe) or bool(
                PROTECTED_RX.search(name))
        except psutil.Error:
            continue
    out = [ProcGroup(**g) for g in groups.values()]
    out.sort(key=lambda g: g.rss, reverse=True)
    return out


def disk_throughput(seconds=1.0, cancel=None) -> Optional[float]:
    """Total disk read+write in MB/s over `seconds`. None when the OS doesn't expose counters."""
    if psutil is None:
        return None
    try:
        a = psutil.disk_io_counters()
        if a is None:
            return None
        (cancel.wait(seconds) if cancel else time.sleep(seconds))
        b = psutil.disk_io_counters()
        return ((b.read_bytes + b.write_bytes) - (a.read_bytes + a.write_bytes)) / seconds / 1048576
    except (OSError, AttributeError, ValueError, ZeroDivisionError, psutil.Error):   # counters unavailable
        return None


def top_disk_writers(seconds=2.0, cancel=None, n=5) -> list[tuple[str, float]]:
    """[(name, MB/s)] processes doing the most disk I/O over the window (deep scan)."""
    if psutil is None:
        return []
    first = {}
    for p in psutil.process_iter(["name"]):
        try:
            io = p.io_counters()
            first[p.pid] = (p.info["name"], io.read_bytes + io.write_bytes)
        except (psutil.Error, AttributeError):
            continue
    (cancel.wait(seconds) if cancel else time.sleep(seconds))
    out: dict = {}
    for pid, (name, b0) in first.items():
        try:
            io = psutil.Process(pid).io_counters()
            out[name] = out.get(name, 0) + (io.read_bytes + io.write_bytes - b0) / seconds / 1048576
        except (psutil.Error, AttributeError):
            continue
    return sorted([(k, v) for k, v in out.items() if v >= 0.1], key=lambda x: -x[1])[:n]
