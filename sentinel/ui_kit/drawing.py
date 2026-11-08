"""Low-level drawing and window helpers (antialiased shapes, title bar, keyboard focus)."""
from __future__ import annotations

import ctypes
import tkinter as tk

from .. import aa
from ..platform_utils import IS_WIN
from .theme import dp

def round_rect(cv, x1, y1, x2, y2, r, **kw):
    """Rounded rectangle. Antialiased (smooth edges) when Pillow is available, plain Tk polygon otherwise."""
    if aa.available() and x2 - x1 >= 1 and y2 - y1 >= 1:
        fill = kw.get("fill") or None
        outline = kw.get("outline") or None
        width = kw.get("width", 1) if outline else 0
        if outline and outline == fill:
            outline, width = None, 0
        if fill is None and outline is None:
            return None
        img = aa.rrect_image(x2 - x1, y2 - y1, r, fill, outline, width)
        return aa.put(cv, x1, y1, img, kw.get("tags"))
    r = max(0, min(r, (x2 - x1) / 2, (y2 - y1) / 2))
    pts = [x1 + r, y1, x2 - r, y1, x2, y1, x2, y1 + r, x2, y2 - r, x2, y2, x2 - r, y2, x1 + r, y2,
           x1, y2, x1, y2 - r, x1, y1 + r, x1, y1]
    return cv.create_polygon(pts, smooth=True, **kw)


def oval(cv, x1, y1, x2, y2, fill=None, outline=None, width=0, tags=None):
    """Smooth circle (antialiased when Pillow is available)."""
    if aa.available():
        if outline == fill:
            outline, width = None, 0
        return aa.put(cv, x1, y1, aa.circle_image(x2 - x1, fill, outline, width), tags)
    return cv.create_oval(x1, y1, x2, y2, fill=fill or "", outline=outline or fill or "", width=width or 1,
                          tags=tags)


def dark_titlebar(win):
    """Windows 10/11: dark title bar so the window frame matches the app."""
    if not IS_WIN:
        return
    try:
        win.update_idletasks()
        hwnd = ctypes.windll.user32.GetParent(win.winfo_id())
        val = ctypes.c_int(1)
        for attr in (20, 19):
            ctypes.windll.dwmapi.DwmSetWindowAttribute(hwnd, attr, ctypes.byref(val), ctypes.sizeof(val))
    except (OSError, AttributeError, tk.TclError):    # cosmetic only: keep the default title bar
        pass


def autowrap(label, container, margin=0):
    """Keep a label's wrap width in step with its container's width."""
    container.bind("<Configure>",
                   lambda e: label.configure(wraplength=max(dp(120), e.width - dp(margin))), add="+")


def make_focusable(widget, command, ring=None):
    """Keyboard support: Tab reaches the widget, Enter/Space activate it. `ring(on)` draws the focus state."""
    widget.configure(takefocus=1)
    widget.bind("<Return>", lambda _e: (command(), "break")[1], add="+")
    widget.bind("<space>", lambda _e: (command(), "break")[1], add="+")
    if ring:
        widget.bind("<FocusIn>", lambda _e: ring(True), add="+")
        widget.bind("<FocusOut>", lambda _e: ring(False), add="+")
