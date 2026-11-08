"""Windows power plans through powercfg (list, query, activate with verification)."""
from __future__ import annotations

import re
import subprocess
from typing import Optional

from ..platform_utils import IS_WIN
from .models import ApplyResult
from .profiles import PLAN_BALANCED, PLAN_HIGH, PLAN_SAVER


# ── power plans ──────────────────────────────────────────────────────────
def _powercfg(*args) -> str:
    try:
        r = subprocess.run(["powercfg", *args], capture_output=True, text=True, errors="replace", timeout=20,
                           creationflags=getattr(subprocess, "CREATE_NO_WINDOW", 0))
        return (r.stdout or "").strip()
    except (OSError, subprocess.SubprocessError):
        return ""


GUID_RX = re.compile(r"([0-9a-fA-F]{8}-(?:[0-9a-fA-F]{4}-){3}[0-9a-fA-F]{12})\s*(?:\(([^)]*)\))?")


def parse_power_plans(text: str) -> list[tuple[str, str, bool]]:
    """[(guid, name, active)] from `powercfg /list` output (works in any language)."""
    out = []
    for line in text.splitlines():
        m = GUID_RX.search(line)
        if m:
            out.append((m.group(1).lower(), (m.group(2) or "").strip(), line.rstrip().endswith("*")))
    return out


def list_power_plans() -> list[tuple[str, str, bool]]:
    return parse_power_plans(_powercfg("/list")) if IS_WIN else []


def active_plan() -> tuple[Optional[str], str]:
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


def available_plans() -> list[tuple[str, str, bool]]:
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
