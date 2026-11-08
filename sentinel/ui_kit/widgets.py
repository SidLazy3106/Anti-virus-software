"""Interactive widgets: Card, Btn, NavItem, Switch, Field, Toast."""
from __future__ import annotations

import tkinter as tk
from tkinter import font as tkfont

from . import theme
from .drawing import make_focusable, oval, round_rect
from .theme import T, dp, font, icon, mix

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


class Btn(tk.Canvas):
    STYLES = {
        "primary": ("primary", "primary_hover", "on_primary"),
        "secondary": ("surface2", "surface3", "text"),
        "danger": ("danger", "danger_hover", "on_primary"),
        "success": ("success", "success_hover", "on_success"),
        "ghost": (None, "surface2", "muted"),
    }

    def __init__(self, parent, text, command=None, style="primary", icon=None, height=40, padx=18, size=10,
                 radius=12, min_width=0):
        self._bg = parent.cget("bg")
        super().__init__(parent, bg=self._bg, highlightthickness=0, bd=0, cursor="hand2")
        self.text, self.cmd, self.style, self.icon_name = text, command, style, icon
        self.h, self.padx, self.r, self.min_w = dp(height), dp(padx), dp(radius), dp(min_width)
        self.f = tkfont.Font(family=theme.FONT, size=size, weight="bold")
        self.fi = tkfont.Font(family=theme.ICON_FONT, size=size + 1) if (icon and theme.ICON_FONT) else None
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
        if icon_name and theme.ICON_FONT:
            self.icon_name = icon_name
            if self.fi is None:
                self.fi = tkfont.Font(family=theme.ICON_FONT, size=int(self.f.cget("size")) + 1)
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
        self.f = tkfont.Font(family=theme.FONT, size=11)
        self.fb = tkfont.Font(family=theme.FONT, size=11, weight="bold")
        self.fi = tkfont.Font(family=theme.ICON_FONT, size=13) if theme.ICON_FONT else None
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
        oval(self, cx - r, self.h / 2 - r, cx + r, self.h / 2 + r, fill=T["knob"])
        if self._focus:
            round_rect(self, 0, 0, self.w, self.h, self.h / 2, fill="", outline=T["primary"], width=2)


class Field(Card):
    """Rounded text input with an optional leading icon."""

    def __init__(self, parent, textvariable, icon_name=None, size=11, on_return=None):
        super().__init__(parent, fill=T["surface2"], radius=12, pad=8)
        row = self.inner
        if icon_name and theme.ICON_FONT:
            tk.Label(row, text=icon(icon_name), font=(theme.ICON_FONT, size), bg=T["surface2"], fg=T["faint"]).pack(
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
