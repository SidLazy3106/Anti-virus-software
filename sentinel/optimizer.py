"""Windows optimizer: analysis is read-only; every change is individual, user-approved, verified and reversible.

What it does NOT do, by design: terminate any process, change Windows services, touch the registry outside the
per-user "StartupApproved" switches Task Manager itself uses, disable any security feature, or change the pagefile
or boot settings. Closing apps is only ever *recommended*; the user does it.

Changes are recorded in ~/.x-secure/optimizer_history.json with the original value, so they can be restored exactly.
"""
from __future__ import annotations

import ctypes
import json
import os
import platform
import re
import subprocess
import sys
import tempfile
import threading
import time
import uuid
from dataclasses import dataclass, field
from pathlib import Path
from typing import Optional

try:
    import psutil
except ImportError:  # optional: analysis is limited without it
    psutil = None

from . import config, logger

IS_WIN = sys.platform == "win32"
APPROVED_BASE = r"Software\Microsoft\Windows\CurrentVersion\Explorer\StartupApproved"
RUN_KEY = r"Software\Microsoft\Windows\CurrentVersion\Run"
TEMP_MAX_AGE_DAYS = 7

# Windows built-in power plans (stable GUIDs on every Windows version)
PLAN_BALANCED = "381b4222-f694-41f0-9685-ff5bb260df2e"
PLAN_HIGH = "8c5e7fda-e8bf-4a96-9a85-a6e23a8c635c"
PLAN_SAVER = "a1841308-3541-4fab-bc81-f71556f20b4a"

PROFILES = {
    "gaming": {
        "name": "Gaming Mode", "plan": PLAN_HIGH, "icon": "play",
        "short": "Responsive and smooth for games",
        "applies": "Switches the Windows power plan to High performance.",
        "side_effects": "Uses more power and runs warmer. On a laptop the battery drains faster.",
        "not_automated": "Pausing background apps and silencing notifications is up to you; see the "
                         "recommendations list. Game launchers, anti-cheat and Defender are never touched.",
    },
    "balanced": {
        "name": "Balanced Mode", "plan": PLAN_BALANCED, "icon": "home",
        "short": "Everyday performance, normal Windows",
        "applies": "Switches the Windows power plan to Balanced (the Windows default).",
        "side_effects": "None. This is how Windows normally runs.",
        "not_automated": "Nothing else is changed.",
    },
    "workspace": {
        "name": "Workspace Mode", "plan": PLAN_BALANCED, "icon": "folder",
        "short": "Multitasking, work and creative apps",
        "applies": "Uses the Balanced power plan, which keeps all your apps and caches intact.",
        "side_effects": "None. No app is closed and no unsaved work is at risk.",
        "not_automated": "Your open documents, dev servers, transfers and renders are never interrupted.",
    },
    "eco": {
        "name": "Eco Mode", "plan": PLAN_SAVER, "icon": "bulb",
        "short": "Lower power use, longer battery",
        "applies": "Switches the Windows power plan to Power saver.",
        "side_effects": "The PC may feel slower under heavy load. Security and updates keep working.",
        "not_automated": "Display timeout and pausing background apps are left for you to choose.",
    },
}

PROTECTED_RX = re.compile(
    r"(defender|windows ?security|sechealth|securityhealth|antivirus|anti-virus|firewall|malware|mcafee|norton|"
    r"kaspersky|avast|\bavg\b|bitdefender|eset|sophos|x-?secure|realtek|nahimic|waves|synaptics|\belan\b|touchpad|"
    r"\balps\b|bluetooth|audio|igfx|\bintel|radeon|nvdisplay|nvcontainer|driver|ctfmon|windows ?update|vpn|"
    r"authenticator|ipsecuritymonitor|rtkaud|dolby|vanguard|\bvgc\b|\bvgtray\b|easyanticheat|battleye|anti-?cheat)",
    re.I)
PROTECTED_PROCS = {
    "system", "system idle process", "registry", "memcompression", "smss.exe", "csrss.exe", "wininit.exe",
    "services.exe", "lsass.exe", "svchost.exe", "winlogon.exe", "dwm.exe", "fontdrvhost.exe", "explorer.exe",
    "msmpeng.exe", "nissrv.exe", "securityhealthservice.exe", "securityhealthsystray.exe", "searchindexer.exe",
    "sihost.exe", "taskhostw.exe", "runtimebroker.exe", "ctfmon.exe", "audiodg.exe", "wmiprvse.exe", "spoolsv.exe",
    "dllhost.exe", "conhost.exe", "lsaiso.exe", "wudfhost.exe", "dashost.exe", "unsecapp.exe",
}


# ── data types ───────────────────────────────────────────────────────────
@dataclass
class Snapshot:
    cpu: float = 0.0
    ram_total: int = 0
    ram_used: int = 0
    ram_pct: float = 0.0
    disk_pct: float = 0.0
    disk_free: int = 0
    power_plan: str = "Unknown"
    os_name: str = ""
    process_count: int = 0
    taken: float = 0.0


@dataclass
class StartupItem:
    name: str
    command: str
    source: str            # "hkcu_run" | "startup_folder" | "hklm_run" | "hklm_run32"
    enabled: bool
    protected: bool
    manageable: bool       # we only change per-user entries (no administrator needed)
    running_mb: Optional[float] = None


@dataclass
class ProcGroup:
    name: str
    count: int
    rss: int
    cpu: float             # % of total CPU, measured over the sample window
    windowed: bool         # has a visible window (the user is probably using it)
    protected: bool


@dataclass
class Recommendation:
    key: str
    kind: str              # "startup" | "background" | "memory" | "temp" | "info"
    title: str
    uses: str
    benefit: str
    risk: str              # "low" | "medium" | "high"
    action: str
    actionable: bool
    target: dict = field(default_factory=dict)
    category: str = ""
    issue: str = ""
    why: str = ""
    component: str = ""
    side_effects: str = ""
    restore: str = ""
    original: str = ""


@dataclass
class Analysis:
    snapshot: Snapshot
    startup: list
    groups: list
    temp_files: int
    temp_bytes: int
    recommendations: list
    protected_startup: int = 0
    hardware: Optional[dict] = None
    kind: str = "standard"
    completed: list = field(default_factory=list)
    cancelled: bool = False
    duration: float = 0.0
    disk_mb_s: Optional[float] = None
    disk_top: list = field(default_factory=list)
    live: dict = field(default_factory=dict)


@dataclass
class ApplyResult:
    ok: bool
    message: str


def human(n: float) -> str:
    n = float(n)
    for unit in ("B", "KB", "MB", "GB"):
        if n < 1024 or unit == "GB":
            return f"{n:.0f} {unit}" if unit == "B" else f"{n:.1f} {unit}"
        n /= 1024
    return f"{n:.1f} GB"


def is_protected_startup(name: str, command: str) -> bool:
    return bool(PROTECTED_RX.search(f"{name} {command}"))


def _exe_of(command: str) -> str:
    c = (command or "").strip()
    m = re.match(r'^"([^"]+)"', c) or re.match(r"^(\S+?\.(?:exe|bat|cmd|lnk))", c, re.I)
    return os.path.normcase(os.path.expandvars(m.group(1))) if m else ""


# ── power plans ──────────────────────────────────────────────────────────
def _powercfg(*args) -> str:
    try:
        r = subprocess.run(["powercfg", *args], capture_output=True, text=True, errors="replace", timeout=20,
                           creationflags=getattr(subprocess, "CREATE_NO_WINDOW", 0))
        return (r.stdout or "").strip()
    except (OSError, subprocess.SubprocessError):
        return ""


GUID_RX = re.compile(r"([0-9a-fA-F]{8}-(?:[0-9a-fA-F]{4}-){3}[0-9a-fA-F]{12})\s*(?:\(([^)]*)\))?")


def parse_power_plans(text: str) -> list:
    """[(guid, name, active)] from `powercfg /list` output (works in any language)."""
    out = []
    for line in text.splitlines():
        m = GUID_RX.search(line)
        if m:
            out.append((m.group(1).lower(), (m.group(2) or "").strip(), line.rstrip().endswith("*")))
    return out


def list_power_plans() -> list:
    return parse_power_plans(_powercfg("/list")) if IS_WIN else []


def active_plan():
    for guid, name, active in list_power_plans():
        if active:
            return guid, name
    m = GUID_RX.search(_powercfg("/getactivescheme")) if IS_WIN else None
    return (m.group(1).lower(), (m.group(2) or "").strip()) if m else (None, "Unknown")


_exists_cache: dict = {}
BUILTIN_PLANS = {PLAN_HIGH: "High performance", PLAN_BALANCED: "Balanced", PLAN_SAVER: "Power saver"}


def plan_exists(guid: str, listed=None) -> bool:
    """Whether the power plan exists, even if Windows hides it. On many PCs `powercfg /list` only shows High
    performance or Power saver while they are active, but they still exist and can be activated."""
    guid = (guid or "").lower()
    if not guid or not IS_WIN:
        return False
    listed = listed if listed is not None else list_power_plans()
    if guid in {g for g, _, _ in listed}:
        return True
    if guid not in _exists_cache:
        out = _powercfg("/query", guid, "SUB_PROCESSOR")
        _exists_cache[guid] = guid in out.lower()
    return _exists_cache[guid]


def available_plans() -> list:
    """[(guid, name, active)]: the listed plans plus built-in plans that exist but are hidden."""
    plans = list_power_plans()
    have = {g for g, _, _ in plans}
    for guid, name in BUILTIN_PLANS.items():
        if guid not in have and plan_exists(guid, plans):
            plans.append((guid, name, False))
    return plans


def set_active_plan(guid: str) -> ApplyResult:
    """Switch plan and verify. Never creates or edits plans, only activates existing ones."""
    before = active_plan()[0]
    if not plan_exists(guid):
        return ApplyResult(False, "That power plan isn't available on this PC.")
    _powercfg("/setactive", guid)
    now = active_plan()[0]
    if now != guid:
        if before and before != guid:
            _powercfg("/setactive", before)  # automatic rollback: verification failed
        return ApplyResult(False, "Windows did not accept the change, so nothing was modified.")
    return ApplyResult(True, "Power plan changed.")


# ── startup items (per-user StartupApproved switches) ────────────────────
def _approved_key(source: str, base: str) -> str:
    return f"{base}\\{'StartupFolder' if source == 'startup_folder' else 'Run'}"


def get_startup_state(source: str, name: str, base: str = APPROVED_BASE):
    """(enabled, raw bytes or None). Windows stores an even first byte for enabled, odd for disabled."""
    import winreg
    try:
        with winreg.OpenKey(winreg.HKEY_CURRENT_USER, _approved_key(source, base)) as k:
            raw, _ = winreg.QueryValueEx(k, name)
            raw = bytes(raw)
            return (not (raw[:1] and raw[0] & 1)), raw
    except OSError:
        return True, None


def _write_startup_raw(source: str, name: str, raw: Optional[bytes], base: str):
    import winreg
    with winreg.CreateKeyEx(winreg.HKEY_CURRENT_USER, _approved_key(source, base), 0,
                            winreg.KEY_SET_VALUE) as k:
        if raw is None:
            try:
                winreg.DeleteValue(k, name)
            except FileNotFoundError:
                pass
        else:
            winreg.SetValueEx(k, name, 0, winreg.REG_BINARY, raw)


def set_startup_enabled(source: str, name: str, enabled: bool, base: str = APPROVED_BASE) -> ApplyResult:
    """Enable/disable one per-user startup entry, verify it, and roll back on mismatch."""
    if source not in ("hkcu_run", "startup_folder"):
        return ApplyResult(False, "Only per-user startup entries can be changed (no administrator needed).")
    _, original = get_startup_state(source, name, base)
    if enabled:
        raw = b"\x02" + b"\x00" * 11
    else:
        raw = b"\x03\x00\x00\x00" + int((time.time() + 11644473600) * 10_000_000).to_bytes(8, "little")
    try:
        _write_startup_raw(source, name, raw, base)
        ok_state, _ = get_startup_state(source, name, base)
        if ok_state != enabled:
            raise OSError("read-back did not match")
    except OSError as e:
        try:
            _write_startup_raw(source, name, original, base)
        except OSError:
            pass
        return ApplyResult(False, f"Could not change '{name}' ({e}). It was left as it was.")
    return ApplyResult(True, f"'{name}' will {'start' if enabled else 'no longer start'} at sign-in.")


def restore_startup_original(source: str, name: str, original_hex: Optional[str], base: str = APPROVED_BASE):
    raw = bytes.fromhex(original_hex) if original_hex else None
    _write_startup_raw(source, name, raw, base)
    now, now_raw = get_startup_state(source, name, base)
    return ApplyResult(now_raw == raw, "Restored.")


def list_startup_items(proc_mb: Optional[dict] = None) -> list:
    """All startup entries (per-user ones are manageable; machine-wide ones are shown read-only)."""
    if not IS_WIN:
        return []
    import winreg
    proc_mb = proc_mb or {}
    items = []

    def add(source, name, command, hive_manageable):
        enabled, _ = get_startup_state(source, name) if hive_manageable else (True, None)
        exe = _exe_of(command)
        items.append(StartupItem(name=name, command=command, source=source, enabled=enabled,
                                 protected=is_protected_startup(name, command), manageable=hive_manageable,
                                 running_mb=proc_mb.get(exe)))

    for source, hive, path, manageable in (
            ("hkcu_run", winreg.HKEY_CURRENT_USER, RUN_KEY, True),
            ("hklm_run", winreg.HKEY_LOCAL_MACHINE, RUN_KEY, False),
            ("hklm_run32", winreg.HKEY_LOCAL_MACHINE, r"SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Run",
             False)):
        try:
            with winreg.OpenKey(hive, path) as k:
                i = 0
                while True:
                    try:
                        name, val, _ = winreg.EnumValue(k, i)
                    except OSError:
                        break
                    i += 1
                    add(source, name, str(val), manageable)
        except OSError:
            continue
    folder = os.path.join(os.environ.get("APPDATA", ""), r"Microsoft\Windows\Start Menu\Programs\Startup")
    if os.path.isdir(folder):
        for fn in os.listdir(folder):
            if fn.lower() != "desktop.ini":
                add("startup_folder", fn, os.path.join(folder, fn), True)
    return items


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
    s.power_plan = active_plan()[1] if IS_WIN else "n/a"
    return s


def _windowed_pids() -> set:
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
    except Exception:
        pass
    return pids


def _is_system_path(path: str) -> bool:
    p = os.path.normcase(path or "")
    root = os.path.normcase(os.environ.get("SystemRoot", r"C:\Windows"))
    return p.startswith(root + os.sep) or "windows defender" in p


def measure_process_groups(sample: float = 2.0, cancel=None) -> list:
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


# ── temp files ───────────────────────────────────────────────────────────
def temp_roots() -> list:
    roots = {os.path.normcase(os.path.realpath(tempfile.gettempdir())): tempfile.gettempdir()}
    lad = os.environ.get("LOCALAPPDATA")
    if lad:
        p = os.path.join(lad, "Temp")
        roots.setdefault(os.path.normcase(os.path.realpath(p)), p)
    return [Path(p) for p in roots.values() if os.path.isdir(p)]


def _eligible_temp_files(roots, max_age_days=TEMP_MAX_AGE_DAYS, limit=400_000):
    cutoff = time.time() - max_age_days * 86400
    keep_out = os.path.normcase(os.path.realpath(str(config.DATA_DIR)))
    n = 0
    for root in roots:
        real_root = os.path.normcase(os.path.realpath(str(root)))
        stack = [str(root)]
        while stack:
            d = stack.pop()
            try:
                it = os.scandir(d)
            except OSError:
                continue
            with it:
                for e in it:
                    n += 1
                    if n > limit:
                        return
                    try:
                        if e.is_symlink():
                            continue
                        real = os.path.normcase(os.path.realpath(e.path))
                        if not real.startswith(real_root + os.sep) or real.startswith(keep_out):
                            continue
                        if e.is_dir(follow_symlinks=False):
                            stack.append(e.path)
                        elif e.is_file(follow_symlinks=False):
                            st = e.stat(follow_symlinks=False)
                            if st.st_mtime < cutoff:  # age by last modification only
                                yield e.path, st.st_size
                    except OSError:
                        continue


def estimate_temp(roots=None, max_age_days=TEMP_MAX_AGE_DAYS):
    files = size = 0
    for _p, sz in _eligible_temp_files(roots or temp_roots(), max_age_days):
        files += 1
        size += sz
    return files, size


def clean_temp(roots=None, max_age_days=TEMP_MAX_AGE_DAYS, cancel=None):
    """Delete eligible old temp files. Returns (deleted, bytes_freed, skipped). Cannot be undone."""
    deleted = freed = skipped = 0
    for path, sz in list(_eligible_temp_files(roots or temp_roots(), max_age_days)):
        if cancel is not None and cancel.is_set():
            break
        try:
            os.remove(path)
            deleted += 1
            freed += sz
        except OSError:  # in use or protected: leave it
            skipped += 1
    logger.get().info("optimizer: cleaned %d temp files, freed %s, skipped %d", deleted, human(freed), skipped)
    return deleted, freed, skipped


# ── history (rollback) ───────────────────────────────────────────────────
class History:
    def __init__(self, path=None):
        self.path = Path(path or config.DATA_DIR / "optimizer_history.json")

    def _load(self) -> list:
        try:
            return json.loads(self.path.read_text(encoding="utf-8"))
        except (OSError, ValueError):
            return []

    def _save(self, items: list):
        config.ensure_dirs()
        tmp = self.path.with_suffix(".tmp")
        tmp.write_text(json.dumps(items, indent=2), encoding="utf-8")
        os.replace(tmp, self.path)

    def add(self, kind: str, title: str, target: dict, original: dict, applied: dict) -> str:
        items = self._load()
        eid = uuid.uuid4().hex[:12]
        items.append({"id": eid, "time": time.time(), "kind": kind, "title": title, "target": target,
                      "original": original, "applied": applied, "restored": False})
        self._save(items)
        logger.get().info("optimizer: applied %s: %s", kind, title)
        return eid

    def pending(self) -> list:
        return [i for i in self._load() if not i["restored"]]

    def all(self) -> list:
        return self._load()

    def mark_restored(self, eid: str):
        items = self._load()
        for i in items:
            if i["id"] == eid:
                i["restored"] = True
                i["restored_at"] = time.time()
        self._save(items)


def apply_startup_disable(item: StartupItem, history: History, base: str = APPROVED_BASE) -> ApplyResult:
    if item.protected or not item.manageable:
        return ApplyResult(False, f"'{item.name}' is protected or needs administrator rights, so it was skipped.")
    _, raw = get_startup_state(item.source, item.name, base)
    res = set_startup_enabled(item.source, item.name, False, base)
    if res.ok:
        history.add("startup", f"Disabled startup item '{item.name}'",
                    {"source": item.source, "name": item.name, "base": base},
                    {"raw": raw.hex() if raw else None}, {"enabled": False})
    return res


def apply_profile(key: str, history: History) -> ApplyResult:
    prof = PROFILES[key]
    guid, name = active_plan()
    if guid == prof["plan"]:
        st = get_state()
        if st.get("active_profile") != key:        # e.g. Workspace vs Balanced share a plan: label only, no change
            st["active_profile"] = key
            _save_state(st)
        return ApplyResult(True, f"{prof['name']} is already active (the power plan is already right).")
    res = set_active_plan(prof["plan"])      # verifies; rolls back to the earlier plan by itself on failure
    if res.ok:
        st = get_state()
        history.add("power", f"Activated {prof['name']}", {"profile": key},
                    {"guid": guid, "name": name, "profile": st.get("active_profile")},
                    {"guid": prof["plan"], "profile": key})
        st["active_profile"] = key
        st.setdefault("original_plan", {"guid": guid, "name": name})   # the PC's plan before any profile
        _save_state(st)
    return res


def undo_entry(entry: dict, history: History) -> ApplyResult:
    try:
        if entry["kind"] == "startup":
            t = entry["target"]
            res = restore_startup_original(t["source"], t["name"], entry["original"].get("raw"),
                                           t.get("base", APPROVED_BASE))
        elif entry["kind"] == "power":
            guid = entry["original"].get("guid")
            res = set_active_plan(guid) if guid else ApplyResult(False, "No earlier plan was recorded.")
            if res.ok:
                st = get_state()
                st["active_profile"] = entry["original"].get("profile")
                _save_state(st)
        else:
            res = ApplyResult(False, "This change type cannot be restored.")
    except OSError as e:
        res = ApplyResult(False, str(e))
    if res.ok:
        history.mark_restored(entry["id"])
    logger.get().info("optimizer: restore %s -> %s", entry.get("title"), "ok" if res.ok else res.message)
    return res


def undo_all(history: History) -> list:
    """Restore every pending change, newest first. Returns [(title, ApplyResult)]."""
    return [(e["title"], undo_entry(e, history)) for e in reversed(history.pending())]


# ── profile state ────────────────────────────────────────────────────────
def _state_path() -> Path:
    return config.DATA_DIR / "optimizer_state.json"


def get_state() -> dict:
    try:
        return json.loads(_state_path().read_text(encoding="utf-8"))
    except (OSError, ValueError):
        return {}


def _save_state(state: dict):
    config.ensure_dirs()
    _state_path().write_text(json.dumps(state), encoding="utf-8")


def current_profile() -> Optional[str]:
    """The active profile, only if it still matches the live power plan (the user may have changed it)."""
    key = get_state().get("active_profile")
    guid = active_plan()[0]
    if key in PROFILES and PROFILES[key]["plan"] == guid:
        return key
    return {PLAN_BALANCED: "balanced", PLAN_HIGH: "gaming", PLAN_SAVER: "eco"}.get(guid)


def profile_support(key: str, plans=None):
    plans = plans if plans is not None else available_plans()
    guids = {g for g, _, _ in plans}
    if PROFILES[key]["plan"] in guids:
        return True, ""
    return False, "This power plan isn't available on this PC (removed or hidden by Windows or the PC maker)."


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
TEMP_TTL = 600           # a temp-folder estimate stays valid for 10 minutes
_temp_cache: dict = {}
_scan_lock = threading.Lock()


class ScanBusy(RuntimeError):
    """A scan is already running; a second one is refused instead of duplicating the work."""


def _rec(key, kind, category, title, issue, why, benefit, risk, component, action, actionable=False,
         side_effects="None expected.", restore="Nothing is changed by this tip.", original="", target=None,
         uses=""):
    return Recommendation(key=key, kind=kind, title=title, uses=uses or issue, benefit=benefit, risk=risk,
                          action=action, actionable=actionable, target=target or {}, category=category, issue=issue,
                          why=why, component=component, side_effects=side_effects, restore=restore,
                          original=original)


def cached_temp_estimate(force=False):
    hit = _temp_cache.get("v")
    if hit and not force and time.time() - hit[0] < TEMP_TTL:
        return hit[1], hit[2]
    files, size = estimate_temp()
    _temp_cache["v"] = (time.time(), files, size)
    return files, size


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
    except Exception:
        return None


def top_disk_writers(seconds=2.0, cancel=None, n=5) -> list:
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


def hardware_recommendations(hw: dict, snap: Snapshot, live: dict, active_key: Optional[str],
                             plans=None) -> list:
    """Recommendations that only make sense for THIS machine. Each rule needs a real, detected fact."""
    recs: list = []
    if not hw:
        return recs
    from . import hardware as hwmod
    laptop = hwmod.is_laptop(hw)
    ram = (hw.get("ram") or {})
    total = ram.get("total") or snap.ram_total
    gpus = hw.get("gpus") or []
    plans = plans if plans is not None else []
    guids = {g for g, _, _ in plans}
    on_battery = live.get("on_ac") is False
    disk_type = hwmod.system_disk_type(hw)

    if snap.ram_pct >= 85:
        recs.append(_rec(
            "hw:ram-pressure", "info", "RAM", "Memory is almost full",
            f"{human(snap.ram_used)} of {human(snap.ram_total)} in use ({snap.ram_pct:.0f}%)",
            "When memory runs out Windows moves data to the much slower disk, which makes everything lag.",
            "Closing apps you aren't using gives the rest of the PC more room.", "low", "Installed memory (RAM)",
            "Close apps you aren't using", original=f"{snap.ram_pct:.0f}% in use"))
    elif total and total <= 8 * 1073741824 and snap.ram_pct >= 70:
        recs.append(_rec(
            "hw:ram-small", "info", "Hardware-Specific Recommendations", "Limited memory for heavy multitasking",
            f"Only {human(total)} installed, and {snap.ram_pct:.0f}% is already in use",
            "With this little RAM, several browsers tabs plus a game or editor will make Windows swap to disk.",
            "Keeping fewer large apps open at once avoids slowdowns.", "low", "Installed memory (RAM)",
            "Avoid running several large apps together"))
    if ram.get("modules") == 1:
        recs.append(_rec(
            "hw:single-channel", "info", "Hardware-Specific Recommendations", "Only one memory module detected",
            "One RAM stick is installed, so memory most likely runs in single-channel mode",
            "Two matching sticks normally give the CPU and integrated graphics more memory bandwidth.",
            "Can improve integrated-graphics and some CPU-heavy workloads. This is a hardware change.", "low",
            "Memory modules", "Consider adding a matching module (X-Secure can't do this)"))
    if snap.cpu >= 70:
        recs.append(_rec(
            "hw:cpu-busy", "info", "CPU", "CPU is under heavy load right now",
            f"CPU at {snap.cpu:.0f}% while scanning",
            "A busy CPU slows every app. If nothing you started is working hard, a background app may be.",
            "Finding and closing the busy app brings responsiveness back.", "low",
            f"Processor ({(hw.get('cpu') or {}).get('name') or 'CPU'})", "See the background apps below"))

    free_pct = 100 - snap.disk_pct
    if snap.disk_pct and free_pct < 15:
        recs.append(_rec(
            "hw:disk-full", "info", "Storage", "System drive is nearly full",
            f"Only {human(snap.disk_free)} free ({free_pct:.0f}%)",
            "Windows needs free space for updates, caches and virtual memory; a full drive slows everything.",
            "Freeing space keeps Windows updates and apps working smoothly.", "medium", "System drive",
            "Remove files you no longer need", original=f"{free_pct:.0f}% free"))
    bad = [d for d in hw.get("disks") or [] if d.get("health") not in (None, "Healthy")]
    for d in bad:
        recs.append(_rec(
            f"hw:disk-health:{d.get('name')}", "info", "Storage", f"Drive reports '{d.get('health')}'",
            f"{d.get('name')} health: {d.get('health')} / {d.get('status')}",
            "A drive that is not 'Healthy' may be failing and can lose data.",
            "Backing up now protects your files.", "high", d.get("name") or "Disk",
            "Back up important files and check the drive"))
    if disk_type == "HDD":
        recs.append(_rec(
            "hw:hdd", "info", "Hardware-Specific Recommendations", "Windows is on a hard disk drive",
            "Your system drive is a mechanical disk, not an SSD",
            "Hard disks are far slower at start-up and app loading, so startup apps hurt more here.",
            "Fewer startup apps help noticeably; an SSD is the largest single upgrade.", "low", "System drive",
            "Disable unneeded startup apps; consider an SSD (hardware change)"))

    discrete = [g for g in gpus if re.search(r"nvidia|geforce|radeon rx|radeon pro|arc a|rtx|gtx", g.get("name") or "", re.I)]
    integrated = [g for g in gpus if g not in discrete]
    if discrete and integrated:
        g = discrete[0]
        vr = f", {hwmod.gb(g['vram'])} video memory" if g.get("vram") else ""
        recs.append(_rec(
            "hw:hybrid-gpu", "info", "GPU", "Make sure games use the dedicated graphics card",
            f"This PC has {integrated[0].get('name')} and {g.get('name')}{vr}",
            "Windows may run a game on the weaker integrated GPU unless told otherwise, which lowers frame rates.",
            "Assigning games to the dedicated GPU can raise frame rates. Not measured here.", "low",
            g.get("name") or "GPU",
            "Windows Settings > System > Display > Graphics > pick the game > High performance",
            side_effects="The dedicated GPU uses more power and, on a laptop, more battery.",
            restore="Set the game back to 'Let Windows decide' in the same screen."))
    elif gpus and not discrete:
        recs.append(_rec(
            "hw:igpu-only", "info", "GPU", "Integrated graphics only",
            f"Detected: {gpus[0].get('name')}",
            "Integrated graphics share system memory, so Gaming Mode cannot add GPU power.",
            "Lower in-game resolution and effects; keep RAM free for the GPU.", "low", gpus[0].get("name") or "GPU",
            "Use lower graphics settings in games"))

    if laptop and on_battery and active_key == "gaming":
        ok = PLAN_BALANCED in guids
        recs.append(_rec(
            "hw:battery-gaming", "profile", "Power Management", "High performance on battery",
            f"Gaming Mode is active while unplugged ({live.get('battery_pct')}% battery)",
            "High performance drains a laptop battery quickly and runs hotter.",
            "Switching to Balanced extends battery life. Savings not measured.", "low", "Power plan",
            "Switch to Balanced Mode", actionable=ok, target={"profile": "balanced"},
            side_effects="Games may run slower than in Gaming Mode.",
            restore="'Restore previous settings' returns to High performance.",
            original="Power plan: High performance"))
    elif laptop and on_battery and (live.get("battery_pct") or 100) <= 30 and active_key != "eco" \
            and PLAN_SAVER in guids:
        recs.append(_rec(
            "hw:battery-low", "profile", "Power Management", "Battery is low",
            f"{live.get('battery_pct')}% left and not on Eco Mode",
            "Power saver lowers CPU speed and background activity to stretch the charge.",
            "Longer battery life. Savings not measured.", "low", "Power plan", "Switch to Eco Mode",
            actionable=True, target={"profile": "eco"},
            side_effects="The PC may feel slower under heavy load.",
            restore="'Restore previous settings' returns to the earlier plan.", original=f"Power plan: {snap.power_plan}"))
    if not laptop and active_key == "eco" and PLAN_BALANCED in guids:
        recs.append(_rec(
            "hw:desktop-saver", "profile", "Power Management", "Power saver on a desktop",
            "Eco Mode limits performance, but a desktop has no battery to save",
            "Power saver mostly just makes a plugged-in desktop slower.",
            "Balanced restores normal speed.", "low", "Power plan", "Switch to Balanced Mode", actionable=True,
            target={"profile": "balanced"}, side_effects="Slightly higher power use.",
            restore="'Restore previous settings' returns to Power saver.", original="Power plan: Power saver"))
    if laptop and active_key == "gaming":
        recs.append(_rec(
            "hw:thermal", "info", "Power Management", "Sustained load heats a laptop",
            "Gaming Mode is active on a laptop; temperature sensors can't be read here",
            "Thin laptops reduce speed when hot, which can hurt long sessions more than a short burst.",
            "Raised, ventilated placement keeps performance steadier.", "low", "Cooling",
            "Keep vents clear; use Balanced for light work"))
    return recs


def build_recommendations(startup, groups, temp, hw, snap, live, active_key, plans, deep=False):
    recs: list = []
    protected_startup = 0
    for it in startup or []:
        if not it.enabled:
            continue
        if it.protected:
            protected_startup += 1
            continue
        uses = f"Running now, using {it.running_mb:.0f} MB" if it.running_mb else "Not running right now"
        if it.manageable:
            recs.append(_rec(
                f"startup:{it.source}:{it.name}", "startup", "Startup Applications", f"Startup: {it.name}",
                f"Starts automatically at sign-in. {uses}.",
                "Every program that starts with Windows lengthens sign-in and keeps using memory afterwards.",
                "Fewer programs at sign-in; faster start. Takes effect next sign-in.", "low",
                f"Startup entry ({it.source.replace('_', ' ')})", "Stop it starting at sign-in", True,
                side_effects="It won't open itself at sign-in; you can still open it manually.",
                restore="'Restore previous settings' re-enables it exactly as it was.",
                original=f"Enabled. Command: {it.command[:120]}", uses=uses,
                target={"source": it.source, "name": it.name, "command": it.command}))
        else:
            recs.append(_rec(
                f"startup:{it.source}:{it.name}", "info", "Startup Applications", f"Startup (all users): {it.name}",
                f"Starts at sign-in for every user. {uses}.", "Same cost as any startup app.",
                "Needs administrator rights, so this tool leaves it alone.", "medium", "Machine-wide startup entry",
                "Task Manager > Startup apps", uses=uses))
    rss_min = 100 if deep else 150
    for g in groups or []:
        if g.protected or g.windowed:
            continue
        if g.rss >= rss_min * 1048576 or g.cpu >= 5:
            cat = "CPU" if g.cpu >= 5 else "Background Applications"
            recs.append(_rec(
                f"bg:{g.name.lower()}", "background", cat,
                f"Background app: {g.name}" + (f" (x{g.count})" if g.count > 1 else ""),
                f"Using {human(g.rss)} RAM and {g.cpu:.1f}% CPU with no visible window",
                "Background apps compete with the things you are doing for CPU and memory.",
                "Frees memory/CPU if you don't need it running.", "low", f"Process: {g.name}",
                "Close it yourself if unused", side_effects="Closing an app may lose unsaved work in it, which is why "
                "X-Secure never closes apps for you.", uses=f"{human(g.rss)} RAM, {g.cpu:.1f}% CPU"))
    for g in [g for g in groups or [] if g.windowed and not g.protected and g.rss >= 800 * 1048576][:3]:
        recs.append(_rec(
            f"mem:{g.name.lower()}", "memory", "RAM", f"Memory-heavy app: {g.name}" + (f" (x{g.count})" if g.count > 1 else ""),
            f"Using {human(g.rss)} of memory", "Large apps take memory other programs could use.",
            "Closing it when not needed frees memory.", "low", f"Process: {g.name}", "Close it yourself if unused",
            side_effects="Unsaved work in that app would be lost, so X-Secure leaves this to you.",
            uses=f"{human(g.rss)} RAM"))
    t_files, t_bytes = temp if temp else (0, 0)
    if t_bytes >= 50 * 1048576:
        recs.append(_rec(
            "temp", "temp", "Storage", "Old temporary files", f"{human(t_bytes)} in {t_files:,} files older than "
            f"{TEMP_MAX_AGE_DAYS} days", "Leftover temp files from installers and apps just take up space.",
            f"Frees up to {human(t_bytes)} of disk space.", "low", "Temp folders on the system drive",
            "Delete (can't be undone)", True, side_effects="Deleted files cannot be recovered. Files in use are skipped.",
            restore="NOT reversible. Only files older than 7 days in your Temp folder are touched.",
            original=f"{t_files:,} files, {human(t_bytes)}", uses=f"{human(t_bytes)} in {t_files:,} files",
            target={"files": t_files}))
    recs += hardware_recommendations(hw, snap, live, active_key, plans)
    order = {"low": 0, "medium": 1, "high": 2}
    recs.sort(key=lambda r: (not r.actionable, order[r.risk]))
    return recs, protected_startup


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
        from . import hardware as hwmod
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


def analyze(sample: float = 2.0) -> Analysis:
    """Read-only standard scan (kept for callers/tests that don't need progress)."""
    return scan("standard")


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
