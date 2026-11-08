"""Colours, fonts, icon glyphs, HiDPI scaling and ttk styling shared by every widget."""
from __future__ import annotations

import ctypes
import tkinter as tk
from tkinter import font as tkfont
from tkinter import ttk

from ..platform_utils import IS_WIN

T = {
    "bg": "#0A0F1F", "sidebar": "#0D1326", "surface": "#131B33", "surface2": "#1A2442", "surface3": "#26335E",
    "border": "#222D52", "text": "#EEF2FF", "muted": "#98A4C7", "faint": "#63708F",
    "primary": "#5B8CFF", "primary_hover": "#4A78E8", "accent2": "#8B6CFF",
    "success": "#34D399", "success_hover": "#2BB583", "warning": "#FBBF24",
    "danger": "#FB7185", "danger_hover": "#E5586F",
    "on_primary": "#FFFFFF", "on_success": "#04251B", "knob": "#FFFFFF",   # text/knob colours drawn on top of fills
}

_scale = 1.0
FONT = "Segoe UI"
ICON_FONT = None
ICONS = {
    "home": 0xE80F, "search": 0xE721, "shield": 0xEA18, "lock": 0xE72E, "globe": 0xE774, "health": 0xEB51,
    "diagnostic": 0xE9D9, "check": 0xE73E, "warn": 0xE7BA, "folder": 0xE8B7, "play": 0xE768, "stop": 0xE71A,
    "refresh": 0xE72C, "delete": 0xE74D, "restore": 0xE777, "bulb": 0xEA80, "clock": 0xE121, "link": 0xE71B,
    "alert": 0xE783, "info": 0xE946, "block": 0xE733, "trust": 0xE8FB, "next": 0xE76C, "settings": 0xE713,
    "chevron_down": 0xE70D,
}


def enable_hidpi():
    """Make this process DPI-aware so Windows stops bitmap-scaling (blurring) the window. Call before Tk()."""
    if not IS_WIN:
        return
    try:
        ctypes.windll.shcore.SetProcessDpiAwareness(2)  # per-monitor
    except (OSError, AttributeError):
        try:
            ctypes.windll.user32.SetProcessDPIAware()
        except (OSError, AttributeError):
            pass


def init(root):
    """Read the screen scale and pick fonts. Call once, right after creating the root window."""
    global _scale, FONT, ICON_FONT
    try:
        dpi = root.winfo_fpixels("1i")
        _scale = max(1.0, dpi / 96.0)
        root.tk.call("tk", "scaling", dpi / 72.0)
    except tk.TclError:
        _scale = 1.0
    fams = set(tkfont.families(root))
    FONT = "Segoe UI" if "Segoe UI" in fams else tkfont.nametofont("TkDefaultFont").actual("family")
    ICON_FONT = next((f for f in ("Segoe Fluent Icons", "Segoe MDL2 Assets") if f in fams), None)


def dp(x) -> int:
    return int(round(x * _scale))


def font(size=10, bold=False):
    return (FONT, size, "bold") if bold else (FONT, size)


def icon(name) -> str:
    return chr(ICONS[name]) if ICON_FONT and name in ICONS else ""


def mix(c1: str, c2: str, t: float) -> str:
    """Blend hex colour c1 into c2 by t (0 = c2, 1 = c1)."""
    a = [int(c1[i:i + 2], 16) for i in (1, 3, 5)]
    b = [int(c2[i:i + 2], 16) for i in (1, 3, 5)]
    return "#%02X%02X%02X" % tuple(round(b[i] + (a[i] - b[i]) * t) for i in range(3))


def style_ttk(root):
    st = ttk.Style(root)
    try:
        st.theme_use("clam")
    except tk.TclError:
        pass
    st.configure("X.Treeview", background=T["surface"], fieldbackground=T["surface"], foreground=T["text"],
                 borderwidth=0, rowheight=dp(38), font=font(10), relief="flat")
    st.configure("X.Treeview.Heading", background=T["surface2"], foreground=T["muted"], font=font(9, True),
                 relief="flat", borderwidth=0, padding=(dp(10), dp(9)))
    st.map("X.Treeview", background=[("selected", T["surface3"])], foreground=[("selected", T["text"])])
    st.map("X.Treeview.Heading", background=[("active", T["surface3"])])
    st.layout("X.Treeview", [("Treeview.treearea", {"sticky": "nswe"})])
    try:
        st.layout("X.Vertical.TScrollbar", [("Vertical.Scrollbar.trough", {
            "children": [("Vertical.Scrollbar.thumb", {"expand": "1", "sticky": "nswe"})], "sticky": "ns"})])
        st.configure("X.Vertical.TScrollbar", background=T["surface3"], troughcolor=T["surface"], borderwidth=0,
                     relief="flat", width=dp(10), bordercolor=T["surface"], lightcolor=T["surface3"],
                     darkcolor=T["surface3"], arrowcolor=T["surface3"])
        st.map("X.Vertical.TScrollbar", background=[("active", T["faint"])])
    except tk.TclError:
        pass


def ease(t: float) -> float:
    """Ease in-out (smoothstep)."""
    t = max(0.0, min(1.0, t))
    return t * t * (3 - 2 * t)
