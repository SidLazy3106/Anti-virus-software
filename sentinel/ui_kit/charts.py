"""Bar and line charts with hover tooltips."""
from __future__ import annotations

import tkinter as tk

from .. import aa
from .drawing import oval, round_rect
from .theme import T, dp, font

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
        round_rect(self, bx1 - pad, by1 - pad, bx2 + pad, by2 + pad, dp(8), fill=T["surface3"],
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
