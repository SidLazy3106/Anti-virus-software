"""Hardware detection with a local cache. Everything stays on this PC; nothing is uploaded.

Static facts (CPU/GPU model, RAM size, disk type...) are cached in ~/.x-secure/hardware_profile.json. A cheap
fingerprint (CPU name, RAM size, GPU names, OS build) is recomputed each run; the expensive PowerShell query only
runs again when the fingerprint changes. Dynamic values (available RAM, battery) are always read live.
A value that cannot be read is None and the UI shows "Not available", never a guess.
"""
from __future__ import annotations

import json
import platform
import subprocess
import time
from typing import Any, Optional

from .platform_utils import psutil

from . import config
from .winconst import SPI_GETCLIENTAREAANIMATION

from .platform_utils import IS_WIN
LAPTOP_CHASSIS = {8, 9, 10, 11, 12, 14, 18, 21, 30, 31, 32}
DESKTOP_CHASSIS = {3, 4, 5, 6, 7, 13, 15, 16, 23, 24, 34, 35, 36}

PS_SCRIPT = r"""
$ErrorActionPreference='SilentlyContinue'
$o=[ordered]@{}
$o.disks=@(Get-PhysicalDisk | Select-Object FriendlyName,MediaType,BusType,Size,HealthStatus,OperationalStatus)
$o.chassis=@((Get-CimInstance Win32_SystemEnclosure).ChassisTypes)
$o.mem=@(Get-CimInstance Win32_PhysicalMemory | Select-Object Capacity,Speed,ConfiguredClockSpeed)
$o.gpu=@(Get-CimInstance Win32_VideoController | Select-Object Name,AdapterRAM,CurrentRefreshRate,DriverVersion)
$o.cpu=Get-CimInstance Win32_Processor | Select-Object -First 1 Name,Manufacturer,NumberOfCores,NumberOfLogicalProcessors,MaxClockSpeed
$o | ConvertTo-Json -Depth 4 -Compress
"""


def _reg(path: str, name: str):
    try:
        import winreg
        with winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, path) as k:
            return winreg.QueryValueEx(k, name)[0]
    except (OSError, ImportError):
        return None


def _gpu_registry() -> list[tuple]:
    """[(name, vram_bytes or None)] from the display-adapter class key. Fast, no PowerShell."""
    out: list[tuple] = []
    if not IS_WIN:
        return out
    base = r"SYSTEM\CurrentControlSet\Control\Class\{4d36e968-e325-11ce-bfc1-08002be10318}"
    for i in range(8):
        sub = f"{base}\\{i:04d}"
        name = _reg(sub, "DriverDesc")
        if not name:
            continue
        vram = _reg(sub, "HardwareInformation.qwMemorySize")
        if isinstance(vram, bytes):
            vram = int.from_bytes(vram[:8], "little")
        out.append((str(name), int(vram) if isinstance(vram, int) and vram > 0 else None))
    return out


def quick_fingerprint() -> dict:
    fp = {"os_build": platform.version(), "cpu": None, "ram": None, "cores": None, "threads": None,
          "gpus": [n for n, _ in _gpu_registry()]}
    if IS_WIN:
        fp["cpu"] = _reg(r"HARDWARE\DESCRIPTION\System\CentralProcessor\0", "ProcessorNameString")
    if psutil:
        fp["ram"] = psutil.virtual_memory().total
        fp["cores"] = psutil.cpu_count(logical=False)
        fp["threads"] = psutil.cpu_count(logical=True)
    return fp


def _run_ps(timeout=30) -> dict:
    if not IS_WIN:
        return {}
    try:
        r = subprocess.run(["powershell", "-NoProfile", "-NonInteractive", "-Command", PS_SCRIPT],
                           capture_output=True, text=True, errors="replace", timeout=timeout,
                           creationflags=getattr(subprocess, "CREATE_NO_WINDOW", 0))
        return json.loads(r.stdout) if r.stdout.strip() else {}
    except (OSError, subprocess.SubprocessError, ValueError):
        return {}


def _as_list(v) -> list:
    return [] if v is None else v if isinstance(v, list) else [v]


MEDIA = {"SSD": "SSD", "HDD": "HDD", "SCM": "SSD"}


def build_profile(ps: dict, fp: dict) -> dict:
    """Turn raw query output into a plain dict. Unknowns stay None."""
    cpu = ps.get("cpu") or {}
    gpu_reg = dict(_gpu_registry())
    gpus = []
    for g in _as_list(ps.get("gpu")):
        name = g.get("Name")
        vram, approx = gpu_reg.get(name), False
        if vram is None and g.get("AdapterRAM"):
            vram, approx = int(g["AdapterRAM"]), True      # 32-bit field: under-reports above 4 GB
        gpus.append({"name": name, "vram": vram, "vram_approx": approx, "refresh_hz": g.get("CurrentRefreshRate"),
                     "driver": g.get("DriverVersion")})
    if not gpus:
        gpus = [{"name": n, "vram": v, "vram_approx": False, "refresh_hz": None, "driver": None}
                for n, v in gpu_reg.items()]
    disks = []
    for d in _as_list(ps.get("disks")):
        mt = d.get("MediaType")
        mt = MEDIA.get(mt) if isinstance(mt, str) else None
        if mt is None and str(d.get("BusType")) in ("17", "NVMe"):
            mt = "SSD"
        disks.append({"name": d.get("FriendlyName"), "type": mt, "size": d.get("Size"),
                      "health": d.get("HealthStatus"), "status": d.get("OperationalStatus")})
    chassis = {int(c) for c in _as_list(ps.get("chassis")) if str(c).isdigit()}
    form = "laptop" if chassis & LAPTOP_CHASSIS else "desktop" if chassis & DESKTOP_CHASSIS else None
    mods = _as_list(ps.get("mem"))
    speeds = [m.get("ConfiguredClockSpeed") or m.get("Speed") or 0 for m in mods]
    return {
        "cpu": {"name": (cpu.get("Name") or fp.get("cpu") or "").strip() or None, "vendor": cpu.get("Manufacturer"),
                "cores": cpu.get("NumberOfCores") or fp.get("cores"),
                "threads": cpu.get("NumberOfLogicalProcessors") or fp.get("threads"),
                "max_mhz": cpu.get("MaxClockSpeed")},
        "ram": {"total": fp.get("ram"), "modules": len(mods) or None, "speed_mhz": max(speeds or [0]) or None},
        "gpus": gpus, "disks": disks, "form_factor": form,
        "os": f"{platform.system()} {platform.release()} (build {platform.version()})",
        "detected": time.time(),
    }


def _profile_path():
    return config.DATA_DIR / "hardware_profile.json"


def load_cached() -> Optional[dict]:
    try:
        return json.loads(_profile_path().read_text(encoding="utf-8"))
    except (OSError, ValueError):
        return None


def get_profile(force: bool = False, query=None) -> dict:
    """Cached hardware profile. Re-queries only if forced or the fingerprint changed."""
    fp = quick_fingerprint()
    cached = load_cached()
    if cached and not force and cached.get("fingerprint") == fp and cached.get("profile"):
        cached["profile"]["from_cache"] = True
        return cached["profile"]
    prof = build_profile((query or _run_ps)(), fp)
    prof["from_cache"] = False
    prof["changed"] = bool(cached and cached.get("fingerprint") != fp)
    try:
        config.ensure_dirs()
        _profile_path().write_text(json.dumps({"fingerprint": fp, "profile": prof}), encoding="utf-8")
    except OSError:
        pass
    return prof


def live_status() -> dict:
    """Values that change: available RAM, battery. Always read fresh."""
    out: dict[str, Any] = {"ram_available": None, "battery_pct": None, "on_ac": None}
    if psutil:
        out["ram_available"] = psutil.virtual_memory().available
        try:
            b = psutil.sensors_battery()
        except (AttributeError, OSError, psutil.Error):   # no battery sensor on this machine
            b = None
        if b is not None:
            out["battery_pct"], out["on_ac"] = round(b.percent), bool(b.power_plugged)
    return out


def is_laptop(prof: dict) -> bool:
    if prof.get("form_factor"):
        return prof["form_factor"] == "laptop"
    return live_status()["battery_pct"] is not None


def system_disk_type(prof: dict) -> Optional[str]:
    types = [d.get("type") for d in prof.get("disks") or [] if d.get("type")]
    return types[0] if types else None


def reduced_motion() -> bool:
    """True when Windows 'Animation effects' is off."""
    if not IS_WIN:
        return False
    try:
        import ctypes
        flag = ctypes.c_int(1)
        ok = ctypes.windll.user32.SystemParametersInfoW(SPI_GETCLIENTAREAANIMATION, 0, ctypes.byref(flag), 0)
        return bool(ok) and flag.value == 0
    except (OSError, AttributeError):
        return False


def gb(n) -> str:
    return f"{n / 1073741824:.1f} GB" if n else "Not available"
