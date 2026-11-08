"""Small modern widget kit for Tkinter: sharp HiDPI rendering, rounded cards, buttons, ring gauge, switch, toast.

Tkinter on Windows is not DPI-aware by default, so Windows stretches the whole window as a low-resolution bitmap
(that is what makes it look blurry). enable_hidpi() must run BEFORE the first Tk() is created. All sizes passed to
these widgets are in "design pixels" (96 dpi); dp() converts them to real pixels for the current screen.
"""
from __future__ import annotations

import ctypes
import sys
import tkinter as tk
from tkinter import font as tkfont
from tkinter import ttk

from . import aa

# ── theme ────────────────────────────────────────────────────────────────
T = {
    "bg": "#0A0F1F", "sidebar": "#0D1326", "surface": "#131B33", "surface2": "#1A2442", "surface3": "#26335E",
    "border": "#222D52", "text": "#EEF2FF", "muted": "#98A4C7", "faint": "#63708F",
    "primary": "#5B8CFF", "primary_hover": "#4A78E8", "accent2": "#8B6CFF",
    "success": "#34D399", "success_hover": "#2BB583", "warning": "#FBBF24",
    "danger": "#FB7185", "danger_hover": "#E5586F",
}

_scale = 1.0
FONT = "Segoe UI"
ICON_FONT = None
ICONS = {
    "home": 0xE80F, "search": 0xE721, "shield": 0xEA18, "lock": 0xE72E, "globe": 0xE774, "health": 0xEB51,
    "diagnostic": 0xE9D9, "check": 0xE73E, "warn": 0xE7BA, "folder": 0xE8B7, "play": 0xE768, "stop": 0xE71A,
    "refresh": 0xE72C, "delete": 0xE74D, "restore": 0xE777, "bulb": 0xEA80, "clock": 0xE121, "link": 0xE71B,
    "alert": 0xE783, "info": 0xE946, "block": 0xE733, "trust": 0xE8FB, "next": 0xE76C, "settings": 0xE713,
}


def enable_hidpi():
    """Make this process DPI-aware so Windows stops bitmap-scaling (blurring) the window. Call before Tk()."""
    if sys.platform != "win32":
        return
    try:
        ctypes.windll.shcore.SetProcessDpiAwareness(2)  # per-monitor
    except Exception:
        try:
            ctypes.windll.user32.SetProcessDPIAware()
        except Exception:
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
    if sys.platform != "win32":
        return
    try:
        win.update_idletasks()
        hwnd = ctypes.windll.user32.GetParent(win.winfo_id())
        val = ctypes.c_int(1)
        for attr in (20, 19):
            ctypes.windll.dwmapi.DwmSetWindowAttribute(hwnd, attr, ctypes.byref(val), ctypes.sizeof(val))
    except Exception:
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


def bind_click(widget, command):
    """Make a widget and everything inside it clickable (the outer widget is also keyboard-activatable)."""
    if isinstance(widget, Card) and not getattr(widget, "_kb", False):
        widget._kb = True
        saved = {}

        def ring(on):
            if on:
                saved["b"] = (widget.border, widget.border_w)
                widget.set_border(T["primary"], 2)
            elif "b" in saved:
                widget.set_border(*saved.pop("b"))
        make_focusable(widget, command, ring)
    widget.bind("<Button-1>", lambda _e: command())
    try:
        widget.configure(cursor="hand2")
    except tk.TclError:
        pass
    for child in widget.winfo_children():
        bind_click(child, command)


# ── card ────────────────────────────────────────────────────────────────
class Card(tk.Canvas):
    """Rounded panel. Put content in `.inner`. auto_height=True sizes the card to its content."""

    def __init__(self, parent, fill=None, radius=16, pad=18, border=None, border_w=1, auto_height=True):
        super().__init__(parent, bg=parent.cget("bg"), highlightthickness=0, bd=0, height=dp(40))
        self.fill = fill or T["surface"]
        self.border = border or T["border"]
        self.border_w, self.auto = border_w, auto_height
        self.radius, self.pad = dp(radius), dp(pad)
        self._size, self._last_h = (0, 0), 0
        self.inner = tk.Frame(self, bg=self.fill)
        self._win = self.create_window(self.pad, self.pad, window=self.inner, anchor="nw")
        self.bind("<Configure>", self._on_canvas)
        self.inner.bind("<Configure>", self._on_inner)

    def _on_inner(self, _e=None):
        if self.auto:
            h = self.inner.winfo_reqheight() + 2 * self.pad
            if h != self._last_h:
                self._last_h = h
                self.configure(height=h)

    def _on_canvas(self, e):
        self._size = (e.width, e.height)
        self._paint()
        w = max(1, e.width - 2 * self.pad)
        if self.auto:
            self.itemconfigure(self._win, width=w)
        else:
            self.itemconfigure(self._win, width=w, height=max(1, e.height - 2 * self.pad))

    def _paint(self):
        w, h = self._size
        if w < 4 or h < 4:
            return
        self.delete("card")
        bw = self.border_w
        round_rect(self, bw, bw, w - bw, h - bw, self.radius, fill=self.fill, outline=self.border, width=bw,
                   tags="card")
        self.tag_lower("card")

    def set_border(self, color, width=None):
        self.border = color
        if width is not None:
            self.border_w = width
        self._paint()


# ── buttons ─────────────────────────────────────────────────────────────
class Btn(tk.Canvas):
    STYLES = {
        "primary": ("primary", "primary_hover", "#FFFFFF"),
        "secondary": ("surface2", "surface3", "text"),
        "danger": ("danger", "danger_hover", "#FFFFFF"),
        "success": ("success", "success_hover", "#04251B"),
        "ghost": (None, "surface2", "muted"),
    }

    def __init__(self, parent, text, command=None, style="primary", icon=None, height=40, padx=18, size=10,
                 radius=12, min_width=0):
        self._bg = parent.cget("bg")
        super().__init__(parent, bg=self._bg, highlightthickness=0, bd=0, cursor="hand2")
        self.text, self.cmd, self.style, self.icon_name = text, command, style, icon
        self.h, self.padx, self.r, self.min_w = dp(height), dp(padx), dp(radius), dp(min_width)
        self.f = tkfont.Font(family=FONT, size=size, weight="bold")
        self.fi = tkfont.Font(family=ICON_FONT, size=size + 1) if (icon and ICON_FONT) else None
        self.enabled, self._hover, self._down, self._focus = True, False, False, False
        make_focusable(self, self._invoke, self._ring)
        self.bind("<Enter>", lambda _e: self._set(hover=True))
        self.bind("<Leave>", lambda _e: self._set(hover=False, down=False))
        self.bind("<ButtonPress-1>", lambda _e: self._set(down=True))
        self.bind("<ButtonRelease-1>", self._release)
        self.bind("<Configure>", lambda _e: self._draw())
        self._measure()

    def _measure(self):
        w = self.f.measure(self.text) + 2 * self.padx
        if self.fi:
            w += self.fi.measure(icon(self.icon_name)) + dp(8)
        self.configure(width=max(w, self.min_w), height=self.h)
        self._draw()

    def _set(self, hover=None, down=None):
        if hover is not None:
            self._hover = hover
        if down is not None:
            self._down = down
        self._draw()

    def _ring(self, on):
        self._focus = on and self.enabled
        self._draw()

    def _invoke(self):
        if self.enabled and self.cmd:
            self.cmd()

    def _release(self, e):
        was_down = self._down
        self._set(down=False)
        if was_down and self.enabled and 0 <= e.x <= self.winfo_width() and 0 <= e.y <= self.winfo_height():
            if self.cmd:
                self.cmd()

    def set_text(self, text):
        self.text = text
        self._measure()

    def set_command(self, command):
        self.cmd = command

    def set_look(self, style=None, icon_name=None):
        """Change colour style and/or icon after creation (e.g. a button that turns red on a threat)."""
        if style:
            self.style = style
        if icon_name and ICON_FONT:
            self.icon_name = icon_name
            if self.fi is None:
                self.fi = tkfont.Font(family=ICON_FONT, size=int(self.f.cget("size")) + 1)
        self._measure()

    def set_enabled(self, on: bool):
        self.enabled = on
        self.configure(cursor="hand2" if on else "arrow", takefocus=1 if on else 0)
        self._focus = self._focus and on
        self._draw()

    def _draw(self):
        self.delete("all")
        w = self.winfo_width() if self.winfo_width() > 2 else int(self.cget("width"))
        h = self.h
        base, hover, fg = self.STYLES[self.style]
        if not self.enabled:
            fill, color = T["surface2"], T["faint"]
        else:
            fill = T[hover] if (self._hover or self._down) else (T[base] if base else self._bg)
            color = T.get(fg, fg)
        if self.style == "ghost" and not (self._hover or self._down) and self.enabled:
            fill = self._bg
        round_rect(self, 1, 1, w - 1, h - 1, self.r, fill=fill, outline=fill)
        if self._focus:
            round_rect(self, 2, 2, w - 2, h - 2, self.r, fill="", outline=T["text"], width=2)
        glyph = icon(self.icon_name) if self.fi else ""
        tw = self.f.measure(self.text)
        iw = (self.fi.measure(glyph) + dp(8)) if glyph else 0
        x = (w - (tw + iw)) / 2
        if glyph:
            self.create_text(x, h / 2, text=glyph, font=self.fi, fill=color, anchor="w")
        self.create_text(x + iw, h / 2, text=self.text, font=self.f, fill=color, anchor="w")


class NavItem(tk.Canvas):
    """Sidebar entry: icon + label, hover and active states."""

    def __init__(self, parent, text, icon_name, command):
        self._bg = parent.cget("bg")
        super().__init__(parent, bg=self._bg, highlightthickness=0, bd=0, height=dp(46), cursor="hand2")
        self.text, self.icon_name, self.cmd = text, icon_name, command
        self.active, self._hover, self._focus = False, False, False
        make_focusable(self, lambda: self.cmd(), self._ring)
        self.f = tkfont.Font(family=FONT, size=11)
        self.fb = tkfont.Font(family=FONT, size=11, weight="bold")
        self.fi = tkfont.Font(family=ICON_FONT, size=13) if ICON_FONT else None
        self.bind("<Enter>", lambda _e: self._set(True))
        self.bind("<Leave>", lambda _e: self._set(False))
        self.bind("<Button-1>", lambda _e: self.cmd())
        self.bind("<Configure>", lambda _e: self._draw())

    def _set(self, hover):
        self._hover = hover
        self._draw()

    def _ring(self, on):
        self._focus = on
        self._draw()

    def set_active(self, on):
        self.active = on
        self._draw()

    def _draw(self):
        self.delete("all")
        w, h = self.winfo_width(), int(self.cget("height"))
        if w < 4:
            return
        if self.active:
            round_rect(self, 0, 2, w, h - 2, dp(12), fill=T["surface2"], outline=T["surface2"])
            round_rect(self, 0, h * 0.28, dp(4), h * 0.72, dp(2), fill=T["primary"], outline=T["primary"])
        elif self._hover or self._focus:
            round_rect(self, 0, 2, w, h - 2, dp(12), fill=mix(T["surface2"], self._bg, 0.5),
                       outline=mix(T["surface2"], self._bg, 0.5))
        if self._focus:
            round_rect(self, 1, 3, w - 1, h - 3, dp(12), fill="", outline=T["primary"], width=2)
        color = T["text"] if self.active else (T["text"] if self._hover else T["muted"])
        x = dp(18)
        if self.fi:
            self.create_text(x, h / 2, text=icon(self.icon_name), font=self.fi,
                             fill=T["primary"] if self.active else color, anchor="w")
            x += dp(36)
        self.create_text(x, h / 2, text=self.text, font=self.fb if self.active else self.f, fill=color, anchor="w")


# ── indicators ──────────────────────────────────────────────────────────
class Switch(tk.Canvas):
    def __init__(self, parent, value=False, command=None):
        self.w, self.h = dp(50), dp(28)
        super().__init__(parent, width=self.w, height=self.h, bg=parent.cget("bg"), highlightthickness=0, bd=0,
                         cursor="hand2")
        self.value, self.command, self._x, self._job = bool(value), command, 1.0 if value else 0.0, None
        self._focus = False
        make_focusable(self, lambda: self._click(None), self._ring)
        self.bind("<Button-1>", self._click)
        self._draw()

    def _ring(self, on):
        self._focus = on
        self._draw()

    def _click(self, _e):
        self.set(not self.value, animate=True)
        if self.command:
            self.command(self.value)

    def set(self, value, animate=False):
        self.value = bool(value)
        if self._job:
            self.after_cancel(self._job)
            self._job = None
        if animate:
            self._step()
        else:
            self._x = 1.0 if self.value else 0.0
            self._draw()

    def _step(self):
        target = 1.0 if self.value else 0.0
        if abs(target - self._x) < 0.05:
            self._x = target
            self._job = None
        else:
            self._x += (target - self._x) * 0.4
            self._job = self.after(16, self._step)
        self._draw()

    def _draw(self):
        self.delete("all")
        track = mix(T["success"], T["surface3"], self._x)
        round_rect(self, 1, 1, self.w - 1, self.h - 1, self.h / 2, fill=track, outline=track)
        r = self.h / 2 - dp(4)
        cx = dp(4) + r + self._x * (self.w - 2 * (dp(4) + r))
        oval(self, cx - r, self.h / 2 - r, cx + r, self.h / 2 + r, fill="#FFFFFF")
        if self._focus:
            round_rect(self, 0, 0, self.w, self.h, self.h / 2, fill="", outline=T["primary"], width=2)


class Ring(tk.Canvas):
    """Animated circular gauge with a big number in the middle."""

    def __init__(self, parent, size=170, thickness=14):
        self.s, self.t = dp(size), dp(thickness)
        self._big_font = font(max(16, int(size * 0.19)), True)   # number scales with the ring
        self._sub_off = dp(size * 0.15)
        super().__init__(parent, width=self.s, height=self.s, bg=parent.cget("bg"), highlightthickness=0, bd=0)
        self._cur, self._target, self._job = 0.0, 0.0, None
        self._big, self._small, self._color = "--", "", T["primary"]
        self._draw()

    def set(self, value, big, small="", color=None):
        self._target = max(0.0, min(100.0, float(value or 0)))
        self._big, self._small = big, small
        if color:
            self._color = color
        if self._job:
            self.after_cancel(self._job)
        self._animate()

    def _animate(self):
        diff = self._target - self._cur
        if abs(diff) < 0.4:
            self._cur, self._job = self._target, None
        else:
            self._cur += diff * 0.16
            self._job = self.after(16, self._animate)
        self._draw()

    def _draw(self):
        self.delete("all")
        pad = self.t / 2 + dp(2)
        if aa.available():
            inset = dp(2)
            img = aa.ring_image(self.s - 2 * inset, self.t, self._cur / 100 if self._cur > 0.3 else 0,
                                self._color, T["surface3"])
            aa.put(self, inset, inset, img)
        else:
            box = (pad, pad, self.s - pad, self.s - pad)
            self.create_oval(*box, outline=T["surface3"], width=self.t)
            if self._cur > 0.3:
                self.create_arc(*box, start=90, extent=-min(359.9, 360 * self._cur / 100), style="arc",
                                outline=self._color, width=self.t)
        c = self.s / 2
        self.create_text(c, c - dp(6), text=self._big, font=self._big_font, fill=T["text"])
        if self._small:
            self.create_text(c, c + self._sub_off + dp(6), text=self._small, font=font(9), fill=T["muted"])


class Pill(tk.Canvas):
    """Small rounded status badge with a coloured dot."""

    def __init__(self, parent):
        self._bg = parent.cget("bg")
        super().__init__(parent, bg=self._bg, highlightthickness=0, bd=0, height=dp(34))
        self.f = tkfont.Font(family=FONT, size=10, weight="bold")
        self.set("Ready", T["success"])

    def set(self, text, color):
        w = self.f.measure(text) + dp(50)
        self.configure(width=w)
        self.delete("all")
        fill = mix(color, self._bg, 0.16)
        round_rect(self, 1, 1, w - 1, dp(34) - 1, dp(17), fill=fill, outline=fill)
        oval(self, dp(14), dp(17) - dp(4), dp(22), dp(17) + dp(4), fill=color)
        self.create_text(dp(30), dp(17), text=text, font=self.f, fill=color, anchor="w")


class Meter(tk.Canvas):
    """Horizontal 0-100 bar."""

    def __init__(self, parent):
        self._bg = parent.cget("bg")
        super().__init__(parent, bg=self._bg, highlightthickness=0, bd=0, height=dp(10))
        self._v, self._c = 0, T["primary"]
        self.bind("<Configure>", lambda _e: self._draw())

    def set(self, value, color):
        self._v, self._c = max(0, min(100, value)), color
        self._draw()

    def _draw(self):
        self.delete("all")
        w, h = self.winfo_width(), dp(10)
        if w < 4:
            return
        round_rect(self, 0, 0, w, h, h / 2, fill=T["surface3"], outline=T["surface3"])
        fw = max(h, w * self._v / 100) if self._v > 0 else 0
        if fw:
            round_rect(self, 0, 0, fw, h, h / 2, fill=self._c, outline=self._c)


class Pulse(tk.Canvas):
    """Indeterminate progress bar (a bar sliding back and forth) for scans of unknown length."""

    def __init__(self, parent):
        self._bg = parent.cget("bg")
        super().__init__(parent, bg=self._bg, highlightthickness=0, bd=0, height=dp(8))
        self._running, self._pos, self._job = False, 0.0, None
        self.bind("<Configure>", lambda _e: self._draw())

    def start(self):
        if not self._running:
            self._running = True
            self._tick()

    def stop(self):
        self._running = False
        if self._job:
            self.after_cancel(self._job)
            self._job = None
        self._draw()

    def _tick(self):
        if not self._running:
            return
        self._pos = (self._pos + 0.012) % 1.0
        self._draw()
        self._job = self.after(16, self._tick)

    def _draw(self):
        self.delete("all")
        w, h = self.winfo_width(), dp(8)
        if w < 4:
            return
        round_rect(self, 0, 0, w, h, h / 2, fill=T["surface3"], outline=T["surface3"])
        if self._running:
            seg = w * 0.28
            x1 = -seg + (w + seg) * self._pos
            a, b = max(0, x1), min(w, x1 + seg)
            if b - a > h:
                round_rect(self, a, 0, b, h, h / 2, fill=T["primary"], outline=T["primary"])


class Badge(tk.Canvas):
    """Round icon badge tinted with `color`."""

    def __init__(self, parent, icon_name, color, size=44, base=None):
        self.px, self.size = dp(size), size
        self.base = base or parent.cget("bg")
        super().__init__(parent, width=self.px, height=self.px, bg=parent.cget("bg"), highlightthickness=0, bd=0)
        self.icon_name, self.color = icon_name, color
        self._draw()

    def update_badge(self, icon_name=None, color=None):
        self.icon_name = icon_name or self.icon_name
        self.color = color or self.color
        self._draw()

    def _draw(self):
        self.delete("all")
        tint = mix(self.color, self.base, 0.18)
        oval(self, 1, 1, self.px - 1, self.px - 1, fill=tint)
        if ICON_FONT:
            self.create_text(self.px / 2, self.px / 2, text=icon(self.icon_name),
                             font=(ICON_FONT, max(10, int(self.size * 0.36))), fill=self.color)
        else:
            self.create_text(self.px / 2, self.px / 2, text="•", font=font(14, True), fill=self.color)


class Field(Card):
    """Rounded text input with an optional leading icon."""

    def __init__(self, parent, textvariable, icon_name=None, size=11, on_return=None):
        super().__init__(parent, fill=T["surface2"], radius=12, pad=8)
        row = self.inner
        if icon_name and ICON_FONT:
            tk.Label(row, text=icon(icon_name), font=(ICON_FONT, size), bg=T["surface2"], fg=T["faint"]).pack(
                side="left", padx=(dp(6), dp(8)))
        self.entry = tk.Entry(row, textvariable=textvariable, relief="flat", bd=0, bg=T["surface2"], fg=T["text"],
                              insertbackground=T["text"], readonlybackground=T["surface2"],
                              disabledbackground=T["surface2"], disabledforeground=T["muted"],
                              highlightthickness=0, font=font(size))
        self.entry.pack(side="left", fill="x", expand=True, ipady=dp(6), padx=(0, dp(6)))
        self.entry.bind("<FocusIn>", lambda _e: self.set_border(T["primary"], 2))
        self.entry.bind("<FocusOut>", lambda _e: self.set_border(T["border"], 1))
        if on_return:
            self.entry.bind("<Return>", lambda _e: on_return())


# ── toast ───────────────────────────────────────────────────────────────
class Toast:
    COLORS = {"info": "primary", "success": "success", "warning": "warning", "danger": "danger"}

    def __init__(self, root):
        self.root, self.frame, self._job = root, None, None

    def show(self, text, kind="info", ms=3800):
        self.hide()
        accent = T[self.COLORS.get(kind, "primary")]
        self.frame = tk.Frame(self.root, bg=T["surface3"], highlightbackground=accent, highlightthickness=1)
        tk.Frame(self.frame, bg=accent, width=dp(5)).pack(side="left", fill="y")
        tk.Label(self.frame, text=text, bg=T["surface3"], fg=T["text"], font=font(10), justify="left",
                 wraplength=dp(340), padx=dp(14), pady=dp(12)).pack(side="left")
        self.frame.place(relx=1.0, rely=1.0, anchor="se", x=-dp(26), y=-dp(26))
        self.frame.lift()
        self._job = self.root.after(ms, self.hide)

    def hide(self):
        if self._job:
            self.root.after_cancel(self._job)
            self._job = None
        if self.frame is not None:
            self.frame.destroy()
            self.frame = None


# ── ttk styling (tables + scrollbars) ───────────────────────────────────
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


# ── scrolling, accordion, charts ────────────────────────────────────────
def ease(t: float) -> float:
    """Ease in-out (smoothstep)."""
    t = max(0.0, min(1.0, t))
    return t * t * (3 - 2 * t)


class ScrollFrame(tk.Frame):
    """Vertically scrolling container. Put content in `.body`. Keeps the pixel scroll position when the content
    height changes (so opening an accordion section doesn't make the page jump)."""

    def __init__(self, parent):
        super().__init__(parent, bg=parent.cget("bg"))
        self.cv = tk.Canvas(self, bg=parent.cget("bg"), highlightthickness=0, bd=0)
        self.sb = ttk.Scrollbar(self, orient="vertical", command=self._yview, style="X.Vertical.TScrollbar")
        self.cv.configure(yscrollcommand=self.sb.set)
        self.sb.pack(side="right", fill="y")
        self.cv.pack(side="left", fill="both", expand=True)
        self.body = tk.Frame(self.cv, bg=parent.cget("bg"))
        self._win = self.cv.create_window(0, 0, window=self.body, anchor="nw")
        self._y, self._h, self._target, self._anim = 0.0, 1, 0.0, None
        self.body.bind("<Configure>", self._on_body)
        self.cv.bind("<Configure>", self._on_canvas)
        self.bind("<Enter>", lambda _e: self.cv.bind_all("<MouseWheel>", self._wheel))
        self.bind("<Leave>", self._leave)

    def _leave(self, _e):
        # moving onto a child widget also fires <Leave>; only unbind when the pointer really left
        try:
            w = self.winfo_containing(*self.winfo_pointerxy())
        except (tk.TclError, KeyError):
            w = None
        while w is not None and w is not self:
            w = w.master
        if w is None:
            self.cv.unbind_all("<MouseWheel>")

    def _yview(self, *args):
        if self._anim:
            self.after_cancel(self._anim)
            self._anim = None
        self.cv.yview(*args)
        self._y = self._target = float(self.cv.canvasy(0))

    def _wheel(self, e):
        if not self.winfo_ismapped() or self._h <= self.cv.winfo_height():
            return
        top = max(0, self._h - self.cv.winfo_height())
        base = self._target if self._anim else self._y
        self._target = max(0.0, min(float(top), base - e.delta / 120 * dp(110)))
        if not self._anim:
            self._anim = self.after(0, self._glide)

    def _glide(self):
        """Ease toward the wheel target (~150 ms) instead of jumping in steps."""
        diff = self._target - self._y
        if abs(diff) < 0.75:
            self._y, self._anim = self._target, None
        else:
            self._y += diff * 0.3
            self._anim = self.after(12, self._glide)
        self.cv.yview_moveto(self._y / max(self._h, 1))

    def _on_body(self, _e=None):
        self._h = max(self.body.winfo_reqheight(), 1)
        self.cv.configure(scrollregion=(0, 0, 1, self._h))
        view = max(self.cv.winfo_height(), 1)
        self._y = max(0.0, min(self._y, float(max(0, self._h - view))))
        self.cv.yview_moveto(self._y / self._h)

    def _on_canvas(self, e):
        self.cv.itemconfigure(self._win, width=e.width)
        self._on_body()


class Collapsible(tk.Frame):
    """Accordion section: click the header to expand/collapse. Collapsed by default. Independent of siblings."""
    STEPS = 8

    def __init__(self, parent, title, count_text="", animate=True, on_toggle=None):
        super().__init__(parent, bg=T["surface"], highlightbackground=T["border"], highlightthickness=1)
        self.animate, self.on_toggle, self.open, self._job = animate, on_toggle, False, None
        self.head = tk.Frame(self, bg=T["surface"], cursor="hand2")
        self.head.pack(fill="x")
        self.arrow = tk.Label(self.head, text=icon("next") or ">", bg=T["surface"], fg=T["muted"],
                              font=(ICON_FONT, 10) if ICON_FONT else font(10), width=2)
        self.arrow.pack(side="left", padx=(dp(12), 0), pady=dp(11))
        self.title = tk.Label(self.head, text=title, bg=T["surface"], fg=T["text"], font=font(11, True))
        self.title.pack(side="left", padx=(dp(4), 0))
        self.count = tk.Label(self.head, text=count_text, bg=T["surface"], fg=T["muted"], font=font(9))
        self.count.pack(side="left", padx=(dp(10), 0))
        self.clip = tk.Frame(self, bg=T["surface"], height=0)
        self.body = tk.Frame(self.clip, bg=T["surface"])
        self.body.pack(fill="x")
        for w in (self.head, self.arrow, self.title, self.count):
            w.bind("<Button-1>", lambda _e: self.toggle())
        self.bind("<Enter>", lambda _e: None)

    def set_count(self, text, color=None):
        self.count.configure(text=text, fg=color or T["muted"])

    def toggle(self):
        self.set_open(not self.open)

    def set_open(self, want: bool):
        if want == self.open:
            return
        self.open = want
        self.arrow.configure(text=(icon("next") or ">") if not want else (chr(0xE70D) if ICON_FONT else "v"))
        if self._job:
            self.after_cancel(self._job)
            self._job = None
        self.update_idletasks()
        target = self.body.winfo_reqheight()
        if want:
            self.clip.pack(fill="x")
            if not self.animate:
                self.clip.pack_propagate(True)
                self._notify()
                return
            self.clip.pack_propagate(False)
            self._run(0, target, 0)
        else:
            if not self.animate:
                self.clip.pack_forget()
                self._notify()
                return
            self.clip.pack_propagate(False)
            self._run(self.clip.winfo_height(), 0, 0)

    def _run(self, a, b, i):
        i += 1
        self.clip.configure(height=max(1, int(a + (b - a) * ease(i / self.STEPS))))
        self._notify()
        if i < self.STEPS:
            self._job = self.after(18, lambda: self._run(a, b, i))
        else:
            self._job = None
            if self.open:
                self.clip.pack_propagate(True)       # follow content again (e.g. when a card is removed)
            else:
                self.clip.pack_forget()
            self._notify()

    def _notify(self):
        if self.on_toggle:
            self.on_toggle()


class _Chart(tk.Canvas):
    def __init__(self, parent, height=220):
        super().__init__(parent, bg=T["surface"], highlightthickness=0, bd=0, height=dp(height))
        self.tip = None
        self._hits: list = []
        self.bind("<Configure>", lambda _e: self.redraw())
        self.bind("<Motion>", self._hover)
        self.bind("<Leave>", lambda _e: self._hide())

    def _hide(self):
        self.delete("tip")

    def _hover(self, e):
        self.delete("tip")
        best = None
        for (x1, y1, x2, y2, text) in self._hits:
            if x1 <= e.x <= x2 and y1 <= e.y <= y2:
                best = text
                break
        if not best:
            return
        t = self.create_text(0, 0, text=best, font=font(9), fill=T["text"], anchor="nw", tags="tip", width=dp(260))
        x1, y1, x2, y2 = self.bbox(t)
        pad = dp(7)
        W = self.winfo_width()
        ox = min(e.x + dp(14), W - (x2 - x1) - pad * 2 - 2)
        self.move(t, ox + pad - x1, e.y + dp(10) + pad - y1)
        bx1, by1, bx2, by2 = self.bbox(t)
        r = round_rect(self, bx1 - pad, by1 - pad, bx2 + pad, by2 + pad, dp(8), fill=T["surface3"],
                       outline=T["primary"], tags="tip")
        self.tag_raise(t)

    def redraw(self):
        pass


class BarChart(_Chart):
    """Bars with value labels, a unit, hover details and a clear 'Not available' state per bar."""

    def __init__(self, parent, height=230):
        super().__init__(parent, height)
        self.data = {"title": "", "unit": "", "items": [], "note": ""}

    def set(self, title, unit, items, note=""):
        """items: [{label, value|None, color, tip, sub}]"""
        self.data = {"title": title, "unit": unit, "items": items, "note": note}
        self.redraw()

    def redraw(self):
        self.delete("all")
        self._hits = []
        W, H = self.winfo_width(), self.winfo_height()
        if W < 50:
            return
        d = self.data
        self.create_text(dp(4), dp(4), text=f"{d['title']}  ({d['unit']})" if d["unit"] else d["title"], anchor="nw",
                         font=font(10, True), fill=T["text"])
        items = d["items"]
        if not items:
            return
        top, bottom, left = dp(34), dp(46), dp(10)
        vals = [i["value"] for i in items if i["value"] is not None]
        vmax = max(vals) * 1.15 if vals else 1
        vmax = vmax or 1
        slot = (W - left * 2) / len(items)
        bw = min(dp(70), slot * 0.55)
        base = H - bottom
        self.create_line(left, base, W - left, base, fill=T["border"])
        for k, it in enumerate(items):
            cx = left + slot * (k + 0.5)
            if it["value"] is None:
                self.create_text(cx, base - dp(20), text="Not available", font=font(9), fill=T["faint"])
            else:
                h = (base - top) * (it["value"] / vmax)
                y = base - max(h, 2)
                round_rect(self, cx - bw / 2, y, cx + bw / 2, base, dp(6), fill=it["color"], outline=it["color"])
                self.create_text(cx, y - dp(4), text=f"{it['value']:.1f}", anchor="s", font=font(9, True),
                                 fill=T["text"])
            self.create_text(cx, base + dp(6), text=it["label"], anchor="n", font=font(9), fill=T["muted"])
            if it.get("sub"):
                self.create_text(cx, base + dp(22), text=it["sub"], anchor="n", font=font(8), fill=T["faint"])
            self._hits.append((cx - slot / 2, top, cx + slot / 2, base + dp(40), it.get("tip") or it["label"]))
        if d["note"]:
            self.create_text(W - dp(4), dp(6), text=d["note"], anchor="ne", font=font(8), fill=T["faint"])


class LineChart(_Chart):
    """Multi-series line chart with a legend and nearest-point hover."""

    def __init__(self, parent, height=200):
        super().__init__(parent, height)
        self.data = {"title": "", "unit": "", "series": [], "empty": "Not available"}

    def set(self, title, unit, series, empty="Not available"):
        """series: [{name, color, points:[(x,y)], tips:[str]}] with x in 0..1 or any numeric range."""
        self.data = {"title": title, "unit": unit, "series": series, "empty": empty}
        self.redraw()

    def redraw(self):
        self.delete("all")
        self._hits = []
        W, H = self.winfo_width(), self.winfo_height()
        if W < 50:
            return
        d = self.data
        self.create_text(dp(4), dp(4), text=f"{d['title']}  ({d['unit']})" if d["unit"] else d["title"], anchor="nw",
                         font=font(10, True), fill=T["text"])
        pts = [p for s in d["series"] for p in s["points"]]
        if not pts:
            self.create_text(W / 2, H / 2, text=d["empty"], font=font(10), fill=T["faint"])
            return
        left, right, top, bottom = dp(40), dp(12), dp(40), dp(22)
        xs, ys = [p[0] for p in pts], [p[1] for p in pts]
        x0, x1 = min(xs), max(xs)
        y1 = max(max(ys) * 1.1, 1e-9)
        x1 = x1 if x1 > x0 else x0 + 1

        def sx(x):
            return left + (x - x0) / (x1 - x0) * (W - left - right)

        def sy(y):
            return H - bottom - y / y1 * (H - top - bottom)
        for f in (0, 0.5, 1):
            yy = sy(y1 * f)
            self.create_line(left, yy, W - right, yy, fill=T["border"])
            self.create_text(left - dp(5), yy, text=f"{y1 * f:.0f}", anchor="e", font=font(8), fill=T["faint"])
        lx = left
        if aa.available():
            layer = [([(sx(p[0]), sy(p[1])) for p in s["points"]], s["color"], dp(2), False, 0)
                     for s in d["series"] if len(s["points"]) > 1]
            if layer:
                aa.put(self, 0, 0, aa.lines_image(W, H, layer))
        for s in d["series"]:
            if not s["points"]:
                continue
            flat = [c for p in s["points"] for c in (sx(p[0]), sy(p[1]))]
            if len(s["points"]) > 1 and not aa.available():
                self.create_line(*flat, fill=s["color"], width=dp(2), smooth=False)
            for i, p in enumerate(s["points"]):
                px, py = sx(p[0]), sy(p[1])
                if len(s["points"]) <= 60:
                    r0 = dp(3.5)
                    oval(self, px - r0, py - r0, px + r0, py + r0, fill=s["color"])
                tip = s["tips"][i] if i < len(s.get("tips", [])) else f"{s['name']}: {p[1]:.1f} {d['unit']}"
                self._hits.append((px - dp(7), py - dp(7), px + dp(7), py + dp(7), tip))
            oval(self, lx, H - dp(14), lx + dp(8), H - dp(6), fill=s["color"])
            t = self.create_text(lx + dp(14), H - dp(10), text=s["name"], anchor="w", font=font(8), fill=T["muted"])
            lx = self.bbox(t)[2] + dp(14)
