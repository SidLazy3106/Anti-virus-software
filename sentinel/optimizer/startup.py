"""Per-user startup entries (the StartupApproved switches Task Manager uses)."""
from __future__ import annotations

import os
import re
import time
from typing import Optional

from ..platform_utils import IS_WIN
from .models import ApplyResult, StartupItem
from .protected import is_protected_startup


APPROVED_BASE = r"Software\Microsoft\Windows\CurrentVersion\Explorer\StartupApproved"
RUN_KEY = r"Software\Microsoft\Windows\CurrentVersion\Run"


def _exe_of(command: str) -> str:
    c = (command or "").strip()
    m = re.match(r'^"([^"]+)"', c) or re.match(r"^(\S+?\.(?:exe|bat|cmd|lnk))", c, re.I)
    return os.path.normcase(os.path.expandvars(m.group(1))) if m else ""


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
