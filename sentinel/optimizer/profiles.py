"""Windows power-plan GUIDs and the user-visible optimizer profiles."""
from __future__ import annotations


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
