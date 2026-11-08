"""Turns measurements into explained, risk-rated recommendations."""
from __future__ import annotations

import re
from typing import Optional

from .cleanup import TEMP_MAX_AGE_DAYS
from .models import Recommendation, Snapshot, human
from .profiles import PLAN_BALANCED, PLAN_SAVER

MB = 1048576
GB = 1073741824
# Thresholds that decide when a recommendation is shown (each one needs a real, measured value above it).
RAM_PRESSURE_PCT = 85            # memory use that makes Windows page to disk
RAM_SMALL_BYTES = 8 * GB         # "limited memory" machines...
RAM_SMALL_USED_PCT = 70          # ...once this much is already in use
CPU_BUSY_PCT = 70
DISK_LOW_FREE_PCT = 15
BATTERY_LOW_PCT = 30
BG_RSS_MIN_MB = 150              # background app memory worth mentioning (standard scan)
BG_RSS_MIN_MB_DEEP = 100         # (deep scan looks for smaller apps too)
BG_CPU_PCT = 5
MEM_HEAVY_MB = 800               # visible app that is memory-heavy
MEM_HEAVY_MAX_SHOWN = 3
TEMP_MIN_BYTES = 50 * MB         # old temp files must add up to this before cleanup is suggested


def _rec(key, kind, category, title, issue, why, benefit, risk, component, action, actionable=False,
         side_effects="None expected.", restore="Nothing is changed by this tip.", original="", target=None,
         uses=""):
    return Recommendation(key=key, kind=kind, title=title, uses=uses or issue, benefit=benefit, risk=risk,
                          action=action, actionable=actionable, target=target or {}, category=category, issue=issue,
                          why=why, component=component, side_effects=side_effects, restore=restore,
                          original=original)


def hardware_recommendations(hw: dict, snap: Snapshot, live: dict, active_key: Optional[str],
                             plans=None) -> list:
    """Recommendations that only make sense for THIS machine. Each rule needs a real, detected fact."""
    recs: list = []
    if not hw:
        return recs
    from .. import hardware as hwmod
    laptop = hwmod.is_laptop(hw)
    ram = (hw.get("ram") or {})
    total = ram.get("total") or snap.ram_total
    gpus = hw.get("gpus") or []
    plans = plans if plans is not None else []
    guids = {g for g, _, _ in plans}
    on_battery = live.get("on_ac") is False
    disk_type = hwmod.system_disk_type(hw)

    if snap.ram_pct >= RAM_PRESSURE_PCT:
        recs.append(_rec(
            "hw:ram-pressure", "info", "RAM", "Memory is almost full",
            f"{human(snap.ram_used)} of {human(snap.ram_total)} in use ({snap.ram_pct:.0f}%)",
            "When memory runs out Windows moves data to the much slower disk, which makes everything lag.",
            "Closing apps you aren't using gives the rest of the PC more room.", "low", "Installed memory (RAM)",
            "Close apps you aren't using", original=f"{snap.ram_pct:.0f}% in use"))
    elif total and total <= RAM_SMALL_BYTES and snap.ram_pct >= RAM_SMALL_USED_PCT:
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
    if snap.cpu >= CPU_BUSY_PCT:
        recs.append(_rec(
            "hw:cpu-busy", "info", "CPU", "CPU is under heavy load right now",
            f"CPU at {snap.cpu:.0f}% while scanning",
            "A busy CPU slows every app. If nothing you started is working hard, a background app may be.",
            "Finding and closing the busy app brings responsiveness back.", "low",
            f"Processor ({(hw.get('cpu') or {}).get('name') or 'CPU'})", "See the background apps below"))

    free_pct = 100 - snap.disk_pct
    if snap.disk_pct and free_pct < DISK_LOW_FREE_PCT:
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
    elif laptop and on_battery and (live.get("battery_pct") or 100) <= BATTERY_LOW_PCT and active_key != "eco" \
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
    rss_min = BG_RSS_MIN_MB_DEEP if deep else BG_RSS_MIN_MB
    for g in groups or []:
        if g.protected or g.windowed:
            continue
        if g.rss >= rss_min * MB or g.cpu >= BG_CPU_PCT:
            cat = "CPU" if g.cpu >= BG_CPU_PCT else "Background Applications"
            recs.append(_rec(
                f"bg:{g.name.lower()}", "background", cat,
                f"Background app: {g.name}" + (f" (x{g.count})" if g.count > 1 else ""),
                f"Using {human(g.rss)} RAM and {g.cpu:.1f}% CPU with no visible window",
                "Background apps compete with the things you are doing for CPU and memory.",
                "Frees memory/CPU if you don't need it running.", "low", f"Process: {g.name}",
                "Close it yourself if unused", side_effects="Closing an app may lose unsaved work in it, which is why "
                "X-Secure never closes apps for you.", uses=f"{human(g.rss)} RAM, {g.cpu:.1f}% CPU"))
    for g in [g for g in groups or [] if g.windowed and not g.protected and g.rss >= MEM_HEAVY_MB * MB][:MEM_HEAVY_MAX_SHOWN]:
        recs.append(_rec(
            f"mem:{g.name.lower()}", "memory", "RAM", f"Memory-heavy app: {g.name}" + (f" (x{g.count})" if g.count > 1 else ""),
            f"Using {human(g.rss)} of memory", "Large apps take memory other programs could use.",
            "Closing it when not needed frees memory.", "low", f"Process: {g.name}", "Close it yourself if unused",
            side_effects="Unsaved work in that app would be lost, so X-Secure leaves this to you.",
            uses=f"{human(g.rss)} RAM"))
    t_files, t_bytes = temp if temp else (0, 0)
    if t_bytes >= TEMP_MIN_BYTES:
        recs.append(_rec(
            "temp", "temp", "Storage", "Old temporary files", f"{human(t_bytes)} in {t_files:,} files older than "
            f"{TEMP_MAX_AGE_DAYS} days", "Leftover temp files from installers and apps just take up space.",
            f"Frees up to {human(t_bytes)} of disk space.", "low", "Temp folders on the system drive",
            "Delete (can't be undone)", True, side_effects="Deleted files cannot be recovered. Files in use are skipped.",
            restore=f"NOT reversible. Only files older than {TEMP_MAX_AGE_DAYS} days in your Temp folder are touched.",
            original=f"{t_files:,} files, {human(t_bytes)}", uses=f"{human(t_bytes)} in {t_files:,} files",
            target={"files": t_files}))
    recs += hardware_recommendations(hw, snap, live, active_key, plans)
    order = {"low": 0, "medium": 1, "high": 2}
    recs.sort(key=lambda r: (not r.actionable, order[r.risk]))
    return recs, protected_startup
