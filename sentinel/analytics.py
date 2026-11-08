"""Performance analytics: real measurements of this PC, stored locally, only with the user's permission.

Rules this module enforces:
* Only actual measurements are stored or shown. A metric that cannot be measured is None and shown as "Not available".
* FPS, frame-time and power draw need game-capture or hardware sensors that Windows does not expose to normal
  apps, so they are always reported unavailable rather than estimated.
* Sessions are only compared when they were recorded on the same hardware (same hardware id).
* Public benchmark data is never mixed with these numbers (see external_benchmarks).
"""
from __future__ import annotations

import hashlib
import json
import math
import os
import threading
import time
from pathlib import Path
from typing import Optional

from .platform_utils import psutil

from . import config, hardware, logger

# key, label, unit, higher_is_worse
METRICS = [
    ("cpu_avg", "CPU utilization (average)", "%", True),
    ("cpu_peak", "CPU utilization (peak)", "%", True),
    ("ram_avg", "RAM utilization (average)", "%", True),
    ("procs", "Background process count", "processes", True),
    ("disk", "Disk throughput", "MB/s", True),
    ("latency", "Responsiveness (timer latency)", "ms", True),
    ("power", "Power consumption", "W", True),
    ("fps", "Gaming frame rate", "FPS", False),
    ("frametime", "Frame-time consistency", "ms", True),
]
UNAVAILABLE = {
    "power": "Windows doesn't expose power draw to normal apps without a hardware sensor.",
    "fps": "Needs a game-capture tool such as PresentMon; X-Secure doesn't hook games.",
    "frametime": "Needs a game-capture tool such as PresentMon; X-Secure doesn't hook games.",
}
MIN_SECONDS = 15


def _path() -> Path:
    return config.DATA_DIR / "analytics.json"


def _load() -> dict:
    try:
        d = json.loads(_path().read_text(encoding="utf-8"))
        if isinstance(d, dict):
            return d
    except (OSError, ValueError):
        pass
    return {"consent": False, "sessions": []}


def _save(d: dict):
    config.ensure_dirs()
    tmp = _path().with_suffix(".tmp")
    tmp.write_text(json.dumps(d), encoding="utf-8")
    os.replace(tmp, _path())


def has_consent() -> bool:
    return bool(_load().get("consent"))


def set_consent(on: bool):
    d = _load()
    d["consent"] = bool(on)
    _save(d)


def sessions() -> list[dict]:
    return _load().get("sessions", [])


def clear_sessions():
    d = _load()
    d["sessions"] = []
    _save(d)


def hardware_id(prof: Optional[dict] = None) -> str:
    """Stable id of this machine's core hardware; sessions with different ids are never compared."""
    fp = hardware.quick_fingerprint()
    raw = json.dumps([fp.get("cpu"), fp.get("ram"), fp.get("gpus")], sort_keys=True)
    return hashlib.sha1(raw.encode()).hexdigest()[:12]


def stats(values: list) -> Optional[dict]:
    vals = [v for v in values if v is not None]
    if not vals:
        return None
    n = len(vals)
    mean = sum(vals) / n
    sd = math.sqrt(sum((v - mean) ** 2 for v in vals) / (n - 1)) if n > 1 else 0.0
    return {"mean": mean, "std": sd, "min": min(vals), "max": max(vals), "n": n}


def timer_latency_ms() -> float:
    """How late a 10 ms sleep wakes up. Rises when the system is too busy to schedule us promptly."""
    t = time.perf_counter()
    time.sleep(0.01)
    return max(0.0, (time.perf_counter() - t - 0.01) * 1000)


def measure(label: str, profile: Optional[str], seconds: int = 30, cancel: Optional[threading.Event] = None,
            on_sample=None) -> Optional[dict]:
    """Sample the live system once per second. Returns a session dict, or None if cancelled/too short.
    Requires the user's consent (checked by the caller via has_consent). Measures whatever the PC is doing, so
    compare runs done under similar activity."""
    if psutil is None:
        return None
    cancel = cancel or threading.Event()
    cpu, ram, procs, disk, lat = [], [], [], [], []
    psutil.cpu_percent(None)
    last = psutil.disk_io_counters()
    t0 = time.time()
    for i in range(seconds):
        if cancel.wait(1.0):
            break
        c = psutil.cpu_percent(None)
        r = psutil.virtual_memory().percent
        n = len(psutil.pids())
        d = None
        cur = psutil.disk_io_counters()
        if cur is not None and last is not None:
            d = ((cur.read_bytes + cur.write_bytes) - (last.read_bytes + last.write_bytes)) / 1048576
        last = cur
        l = timer_latency_ms()
        cpu.append(c); ram.append(r); procs.append(n); disk.append(d); lat.append(l)
        if on_sample:
            on_sample(i + 1, seconds, c, r)
    elapsed = time.time() - t0
    if len(cpu) < MIN_SECONDS and cancel.is_set():
        return None
    live = hardware.live_status()
    plan = ""
    try:
        from . import optimizer
        plan = optimizer.active_plan()[1]
    except (ImportError, OSError, IndexError) as e:     # the power plan is optional context for the report
        logger.get().info("analytics: could not read the power plan: %s", e)
    sess = {
        "id": f"{int(t0)}", "label": label, "profile": profile, "time": t0, "duration": round(elapsed, 1),
        "interval_s": 1.0, "hw_id": hardware_id(), "conditions": {"on_ac": live["on_ac"],
                                                                   "battery_pct": live["battery_pct"],
                                                                   "power_plan": plan},
        "series": {"cpu": cpu, "ram": ram, "procs": procs, "disk": disk, "latency": lat},
        "metrics": {"cpu_avg": stats(cpu), "cpu_peak": stats([max(cpu)]) if cpu else None, "ram_avg": stats(ram),
                    "procs": stats(procs), "disk": stats(disk), "latency": stats(lat),
                    "power": None, "fps": None, "frametime": None},
    }
    d = _load()
    d.setdefault("sessions", []).append(sess)
    d["sessions"] = d["sessions"][-200:]
    _save(d)
    return sess


def comparable(all_sessions: Optional[list] = None) -> list:
    """Only sessions recorded on this hardware."""
    hid = hardware_id()
    return [s for s in (all_sessions if all_sessions is not None else sessions()) if s.get("hw_id") == hid]


def by_series(metric: str, all_sessions: Optional[list] = None) -> dict:
    """{series_key: {"runs": [...], "mean": float, "spread": (lo, hi), "n_total": int, "seconds": float}}
    series_key is 'baseline' or a profile key. Means of the runs; spread shows run-to-run variation."""
    out: dict = {}
    for s in comparable(all_sessions):
        m = (s.get("metrics") or {}).get(metric)
        if not m:
            continue
        key = "baseline" if s.get("label") == "baseline" else (s.get("profile") or "custom")
        out.setdefault(key, []).append((s, m))
    res = {}
    for key, runs in out.items():
        means = [m["mean"] for _s, m in runs]
        res[key] = {"runs": [s for s, _ in runs], "mean": sum(means) / len(means), "spread": (min(means), max(means)),
                    "n_total": sum(m["n"] for _s, m in runs), "seconds": sum(s["duration"] for s, _ in runs),
                    "last": runs[-1][1], "count": len(runs)}
    return res


def confidence_note(entry: dict) -> str:
    n = entry["count"]
    if n < 2:
        return "1 run: variability across runs unknown"
    lo, hi = entry["spread"]
    return f"{n} runs, means ranged {lo:.1f}-{hi:.1f}"


def external_benchmarks(hw_name: str) -> Optional[dict]:
    """No public benchmark dataset is bundled or downloaded, so there is nothing to show. Returning None makes
    the UI say 'Not available' instead of inventing numbers. A future implementation must return
    {source, retrieved, methodology, model_matched, values} and keep it separate from local sessions."""
    return None
