"""Small modern widget kit for Tkinter: sharp HiDPI rendering, rounded cards, buttons, ring gauge, switch, toast.

Tkinter on Windows is not DPI-aware by default, so Windows stretches the whole window as a low-resolution bitmap
(that is what makes it look blurry). enable_hidpi() must run BEFORE the first Tk() is created. All sizes passed to
these widgets are in "design pixels" (96 dpi); dp() converts them to real pixels for the current screen.

Layout: theme (colours, fonts, scaling), drawing, widgets, indicators, containers, charts. This package
re-exports every name, so callers keep using `ui_kit.X`; ICON_FONT and FONT are forwarded live from theme.
"""
from __future__ import annotations

from . import theme
from .theme import (
    ICONS,
    T,
    dp,
    ease,
    enable_hidpi,
    font,
    icon,
    init,
    mix,
    style_ttk,
)
from .drawing import (
    autowrap,
    dark_titlebar,
    make_focusable,
    oval,
    round_rect,
)
from .widgets import (
    Btn,
    Card,
    Field,
    NavItem,
    Switch,
    Toast,
    bind_click,
)
from .indicators import (
    Badge,
    Meter,
    Pill,
    Pulse,
    Ring,
)
from .containers import (
    Collapsible,
    ScrollFrame,
)
from .charts import (
    BarChart,
    LineChart,
    _Chart,
)


def __getattr__(name):  # ICON_FONT / FONT are set by init() at start-up, so never copy them
    if name in ("ICON_FONT", "FONT"):
        return getattr(theme, name)
    raise AttributeError(f"module {__name__!r} has no attribute {name!r}")


__all__ = [
    "Badge",
    "BarChart",
    "Btn",
    "Card",
    "Collapsible",
    "Field",
    "ICONS",
    "LineChart",
    "Meter",
    "NavItem",
    "Pill",
    "Pulse",
    "Ring",
    "ScrollFrame",
    "Switch",
    "T",
    "Toast",
    "_Chart",
    "autowrap",
    "bind_click",
    "dark_titlebar",
    "dp",
    "ease",
    "enable_hidpi",
    "font",
    "icon",
    "init",
    "make_focusable",
    "mix",
    "oval",
    "round_rect",
    "style_ttk",
]
