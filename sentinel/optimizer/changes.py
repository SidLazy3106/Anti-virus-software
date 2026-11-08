"""Applying and undoing user-approved changes, with the history that makes them reversible."""
from __future__ import annotations

import json
import os
import time
import uuid
from pathlib import Path
from typing import Optional

from .. import config
from .. import logger
from . import power, startup
from .models import ApplyResult, StartupItem
from .profiles import PLAN_BALANCED, PLAN_HIGH, PLAN_SAVER, PROFILES
from .startup import APPROVED_BASE


# ── history (rollback) ───────────────────────────────────────────────────
class History:
    def __init__(self, path=None):
        self.path = Path(path or config.DATA_DIR / "optimizer_history.json")

    def _load(self) -> list[dict]:
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

    def pending(self) -> list[dict]:
        return [i for i in self._load() if not i["restored"]]

    def all(self) -> list[dict]:
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
    _, raw = startup.get_startup_state(item.source, item.name, base)
    res = startup.set_startup_enabled(item.source, item.name, False, base)
    if res.ok:
        history.add("startup", f"Disabled startup item '{item.name}'",
                    {"source": item.source, "name": item.name, "base": base},
                    {"raw": raw.hex() if raw else None}, {"enabled": False})
    return res


def apply_profile(key: str, history: History) -> ApplyResult:
    prof = PROFILES[key]
    guid, name = power.active_plan()
    if guid == prof["plan"]:
        st = get_state()
        if st.get("active_profile") != key:        # e.g. Workspace vs Balanced share a plan: label only, no change
            st["active_profile"] = key
            _save_state(st)
        return ApplyResult(True, f"{prof['name']} is already active (the power plan is already right).")
    res = power.set_active_plan(prof["plan"])      # verifies; rolls back to the earlier plan by itself on failure
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
            res = startup.restore_startup_original(t["source"], t["name"], entry["original"].get("raw"),
                                           t.get("base", APPROVED_BASE))
        elif entry["kind"] == "power":
            guid = entry["original"].get("guid")
            res = power.set_active_plan(guid) if guid else ApplyResult(False, "No earlier plan was recorded.")
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


def undo_all(history: History) -> list[tuple[str, ApplyResult]]:
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
    guid = power.active_plan()[0]
    if key in PROFILES and PROFILES[key]["plan"] == guid:
        return key
    return {PLAN_BALANCED: "balanced", PLAN_HIGH: "gaming", PLAN_SAVER: "eco"}.get(guid or "")


def profile_support(key: str, plans=None) -> tuple[bool, str]:
    plans = plans if plans is not None else power.available_plans()
    guids = {g for g, _, _ in plans}
    if PROFILES[key]["plan"] in guids:
        return True, ""
    return False, "This power plan isn't available on this PC (removed or hidden by Windows or the PC maker)."
