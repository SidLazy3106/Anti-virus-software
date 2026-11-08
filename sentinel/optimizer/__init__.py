"""Windows optimizer: analysis is read-only; every change is individual, user-approved, verified and reversible.

What it does NOT do, by design: terminate any process, change Windows services, touch the registry outside the
per-user "StartupApproved" switches Task Manager itself uses, disable any security feature, or change the pagefile
or boot settings. Closing apps is only ever *recommended*; the user does it.

Changes are recorded in ~/.x-secure/optimizer_history.json with the original value, so they can be restored exactly.

Layout: models, profiles, protected, power, startup, measure, cleanup, changes, recommendations, scanning.
This package re-exports the same names the old single module had, so callers keep using `optimizer.X`.
"""
from __future__ import annotations

from ..platform_utils import IS_WIN, psutil
from .models import (
    Analysis,
    ApplyResult,
    ProcGroup,
    Recommendation,
    Snapshot,
    StartupItem,
    human,
)
from .profiles import (
    PLAN_BALANCED,
    PLAN_HIGH,
    PLAN_SAVER,
    PROFILES,
)
from .protected import (
    PROTECTED_PROCS,
    PROTECTED_RX,
    is_protected_startup,
)
from .power import (
    BUILTIN_PLANS,
    GUID_RX,
    _exists_cache,
    _powercfg,
    active_plan,
    available_plans,
    list_power_plans,
    parse_power_plans,
    plan_exists,
    set_active_plan,
)
from .startup import (
    APPROVED_BASE,
    RUN_KEY,
    _approved_key,
    _exe_of,
    _write_startup_raw,
    get_startup_state,
    list_startup_items,
    restore_startup_original,
    set_startup_enabled,
)
from .measure import (
    _is_system_path,
    _windowed_pids,
    disk_throughput,
    measure_process_groups,
    take_snapshot,
    top_disk_writers,
)
from .cleanup import (
    TEMP_MAX_AGE_DAYS,
    _eligible_temp_files,
    clean_temp,
    estimate_temp,
    temp_roots,
)
from .changes import (
    History,
    _save_state,
    _state_path,
    apply_profile,
    apply_startup_disable,
    current_profile,
    get_state,
    profile_support,
    undo_all,
    undo_entry,
)
from .recommendations import (
    _rec,
    build_recommendations,
    hardware_recommendations,
)
from .scanning import (
    CATEGORIES,
    SCAN_KINDS,
    ScanBusy,
    TEMP_TTL,
    _assemble,
    _scan_lock,
    _temp_cache,
    cached_temp_estimate,
    compare,
    scan,
)

__all__ = [
    "APPROVED_BASE",
    "Analysis",
    "ApplyResult",
    "BUILTIN_PLANS",
    "CATEGORIES",
    "GUID_RX",
    "History",
    "IS_WIN",
    "PLAN_BALANCED",
    "PLAN_HIGH",
    "PLAN_SAVER",
    "PROFILES",
    "PROTECTED_PROCS",
    "PROTECTED_RX",
    "ProcGroup",
    "RUN_KEY",
    "Recommendation",
    "SCAN_KINDS",
    "ScanBusy",
    "Snapshot",
    "StartupItem",
    "TEMP_MAX_AGE_DAYS",
    "TEMP_TTL",
    "_approved_key",
    "_assemble",
    "_eligible_temp_files",
    "_exe_of",
    "_exists_cache",
    "_is_system_path",
    "_powercfg",
    "_rec",
    "_save_state",
    "_scan_lock",
    "_state_path",
    "_temp_cache",
    "_windowed_pids",
    "_write_startup_raw",
    "active_plan",
    "annotations",
    "apply_profile",
    "apply_startup_disable",
    "available_plans",
    "build_recommendations",
    "cached_temp_estimate",
    "clean_temp",
    "compare",
    "current_profile",
    "disk_throughput",
    "estimate_temp",
    "get_startup_state",
    "get_state",
    "hardware_recommendations",
    "human",
    "is_protected_startup",
    "list_power_plans",
    "list_startup_items",
    "measure_process_groups",
    "parse_power_plans",
    "plan_exists",
    "profile_support",
    "psutil",
    "restore_startup_original",
    "scan",
    "set_active_plan",
    "set_startup_enabled",
    "take_snapshot",
    "temp_roots",
    "top_disk_writers",
    "undo_all",
    "undo_entry",
]
