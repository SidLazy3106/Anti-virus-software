"""Scrolling frame and accordion section."""
from __future__ import annotations

import tkinter as tk
from tkinter import ttk

from . import theme
from .theme import T, dp, ease, font, icon

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
                              font=(theme.ICON_FONT, 10) if theme.ICON_FONT else font(10), width=2)
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
        self.arrow.configure(text=(icon("next") or ">") if not want else (icon("chevron_down") or "v"))
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
