"""Read-only indicators: Ring gauge, Pill, Meter, Pulse, Badge."""
from __future__ import annotations

import tkinter as tk
from tkinter import font as tkfont

from .. import aa
from . import theme
from .drawing import oval, round_rect
from .theme import T, dp, font, icon, mix

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
        self.f = tkfont.Font(family=theme.FONT, size=10, weight="bold")
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
        if theme.ICON_FONT:
            self.create_text(self.px / 2, self.px / 2, text=icon(self.icon_name),
                             font=(theme.ICON_FONT, max(10, int(self.size * 0.36))), fill=self.color)
        else:
            self.create_text(self.px / 2, self.px / 2, text="•", font=font(14, True), fill=self.color)
