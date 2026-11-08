"""Scan orchestration: parallel read-only analysis parts, caching and before/after comparison."""
from __future__ import annotations

import os
import threading
import time

from .. import config, logger
from ..platform_utils import psutil
from .changes import current_profile
from .cleanup import estimate_temp
from .measure import disk_throughput, measure_process_groups, take_snapshot, top_disk_writers
from .models import Analysis, Snapshot, human
from .power import available_plans
from .recommendations import build_recommendations
from .startup import list_startup_items


# ── analysis ─────────────────────────────────────────────────────────────
CATEGORIES = ["CPU", "RAM", "Startup Applications", "Background Applications", "GPU", "Storage",
              "Power Management", "Hardware-Specific Recommendations"]
SCAN_KINDS = {
    "quick": {"label": "Quick scan", "sample": 1.0, "target": "about 5 seconds",
              "what": "CPU, memory, startup apps and the busiest background apps"},
    "standard": {"label": "Standard scan", "sample": 2.0, "target": "about 15 seconds",
                 "what": "Adds disk activity, power setup, hardware details and old temp files"},
    "deep": {"label": "Deep scan", "sample": 4.0, "target": "can take a minute; cancellable",
             "what": "Adds per-app disk use, storage health and a longer measurement window"},
}
TEMP_TTL = config.TEMP_ESTIMATE_TTL_SECONDS
_temp_cache: dict = {}
_scan_lock = threading.Lock()


class ScanBusy(RuntimeError):
    """A scan is already running; a second one is refused instead of duplicating the work."""


def cached_temp_estimate(force=False):
    hit = _temp_cache.get("v")
    if hit and not force and time.time() - hit[0] < TEMP_TTL:
        return hit[1], hit[2]
    files, size = estimate_temp()
    _temp_cache["v"] = (time.time(), files, size)
    return files, size


def _assemble(kind, parts, started, done, cancelled=False) -> Analysis:
    snap = parts.get("snapshot") or Snapshot(taken=time.time())
    live = parts.get("live") or {}
    plans = parts.get("plans")
    cur = parts.get("active_key")
    recs, prot = build_recommendations(parts.get("startup"), parts.get("groups"), parts.get("temp"),
                                       parts.get("hardware"), snap, live, cur, plans, deep=(kind == "deep"))
    a = Analysis(snap, parts.get("startup") or [], parts.get("groups") or [], (parts.get("temp") or (0, 0))[0],
                 (parts.get("temp") or (0, 0))[1], recs, prot)
    a.hardware, a.kind, a.completed, a.cancelled = parts.get("hardware"), kind, list(done), cancelled
    a.duration, a.disk_mb_s, a.disk_top = time.time() - started, parts.get("disk_mb_s"), parts.get("disk_top") or []
    a.live = live
    return a


def scan(kind: str = "standard", progress=None, cancel=None) -> Analysis:
    """Read-only, parallel, cancellable scan. `progress(event, name, partial_analysis)` fires as parts finish
    ("start" when a part begins, "done" with the partial result so far). Raises ScanBusy if one is running."""
    cfg = SCAN_KINDS[kind]
    if not _scan_lock.acquire(blocking=False):
        raise ScanBusy("A scan is already running.")
    try:
        from concurrent.futures import ThreadPoolExecutor, wait, FIRST_COMPLETED
        from .. import hardware as hwmod
        started = time.time()
        cancel = cancel or threading.Event()
        parts: dict = {}
        done: list = []

        def t_groups():
            parts["groups"] = measure_process_groups(cfg["sample"], cancel)

        def t_snapshot():
            parts["snapshot"] = take_snapshot(cpu_interval=0.5)
            parts["live"] = hwmod.live_status()

        def t_startup():
            exe_mb: dict = {}
            if psutil is not None:
                for p in psutil.process_iter(["exe", "memory_info"]):
                    try:
                        exe = os.path.normcase(p.info.get("exe") or "")
                        if exe and p.info.get("memory_info"):
                            exe_mb[exe] = exe_mb.get(exe, 0) + p.info["memory_info"].rss / 1048576
                    except psutil.Error:
                        continue
            parts["startup"] = list_startup_items(exe_mb)

        def t_power():
            parts["plans"] = available_plans()
            parts["active_key"] = current_profile()

        def t_hw():
            parts["hardware"] = hwmod.get_profile()

        def t_temp():
            parts["temp"] = cached_temp_estimate()

        def t_disk():
            parts["disk_mb_s"] = disk_throughput(1.0, cancel)

        def t_disk_top():
            parts["disk_top"] = top_disk_writers(cfg["sample"], cancel)

        tasks = [("Memory and CPU", t_snapshot), ("Startup apps", t_startup), ("Background apps", t_groups)]
        if kind in ("standard", "deep"):
            tasks += [("Power setup", t_power), ("Hardware details", t_hw), ("Old temp files", t_temp),
                      ("Disk activity", t_disk)]
        else:
            tasks += [("Power setup", t_power)]
        if kind == "deep":
            tasks += [("Per-app disk use", t_disk_top)]

        with ThreadPoolExecutor(max_workers=6) as ex:
            futs = {}
            for name, fn in tasks:
                if progress:
                    progress("start", name, None)
                futs[ex.submit(fn)] = name
            pending = set(futs)
            while pending:
                finished, pending = wait(pending, timeout=0.2, return_when=FIRST_COMPLETED)
                for f in finished:
                    try:
                        f.result()
                    except Exception as e:  # one failing part must not sink the scan
                        logger.get().info("optimizer scan part '%s' failed: %s", futs[f], e)
                    done.append(futs[f])
                    if progress and not cancel.is_set():
                        progress("done", futs[f], _assemble(kind, parts, started, done))
                if cancel.is_set():
                    for f in pending:
                        f.cancel()
                    break
        return _assemble(kind, parts, started, done, cancelled=cancel.is_set())
    finally:
        _scan_lock.release()


def compare(before: Snapshot, after: Snapshot) -> str:
    """Honest before/after text. Small differences are normal fluctuation, not an improvement."""
    d_ram = (before.ram_used - after.ram_used) / max(before.ram_total, 1) * 100
    d_cpu = before.cpu - after.cpu
    parts = [f"RAM {human(before.ram_used)} -> {human(after.ram_used)}",
             f"CPU {before.cpu:.0f}% -> {after.cpu:.0f}%"]
    if abs(d_ram) < 3 and abs(d_cpu) < 5:
        verdict = "No meaningful change was measured (differences this small are normal fluctuation)."
    else:
        verdict = (f"Measured change: RAM {'-' if d_ram > 0 else '+'}{abs(d_ram):.1f} points, "
                   f"CPU {'-' if d_cpu > 0 else '+'}{abs(d_cpu):.0f} points.")
    return " | ".join(parts) + "\n" + verdict
