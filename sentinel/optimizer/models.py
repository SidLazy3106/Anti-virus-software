"""Data types shared by the optimizer modules."""
from __future__ import annotations

from dataclasses import dataclass, field
from typing import Optional


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
    for unit in ("B", "KB", "MB"):
        if n < 1024:
            return f"{n:.0f} {unit}" if unit == "B" else f"{n:.1f} {unit}"
        n /= 1024
    return f"{n:.1f} GB"
