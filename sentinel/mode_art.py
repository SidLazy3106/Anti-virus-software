"""Conceptual mode illustrations for the mode-switch animation.

IMPORTANT: everything here is an *illustration of what a profile is designed to prioritize*. The curves are
fixed mathematical shapes, not PC measurements, benchmark results or promised gains. The UI labels them that way
(see DISCLAIMERS). Real numbers live only on the Performance Analytics page.
"""
from __future__ import annotations

import math

from . import aa
from . import ui_kit as ui
from .ui_kit import T, dp

CONCEPT_MS = 1200

TITLES = {"gaming": "Gaming performance profile", "balanced": "Balanced performance profile",
          "workspace": "Workspace performance profile", "eco": "Eco efficiency profile"}
DISCLAIMERS = {
    "gaming": "Illustration of intended behavior, not measured FPS or actual gaming performance.",
    "balanced": "Illustration of intended behavior, not live system measurements.",
    "workspace": "Illustration of intended behavior, not actual application performance.",
    "eco": "Illustration of intended behavior, not measured electricity savings or battery life.",
}
# (legend text, colour token) for each line, in the order curves() returns them
LEGEND = {
    "gaming": [("Performance priority", "accent2"), ("Background activity", "faint")],
    "balanced": [("Resource use", "primary"), ("Background activity", "faint")],
    "workspace": [("Workload A", "success"), ("Workload B", "primary"), ("Workload C", "warning")],
    "eco": [("Energy demand", "warning"), ("Background activity", "faint")],
}
CAPTIONS = {
    "gaming": "Steady frame pacing  ·  High priority  ·  Quiet background",
    "balanced": "Moderate use  ·  Balanced background  ·  Everyday responsiveness",
    "workspace": "Several apps at once  ·  Consistent availability",
    "eco": "Lower energy demand  ·  Reduced background activity",
}


def curves(key: str, x: float) -> list:
    """Illustrative y values (0..1) at x in 0..1, one per legend entry. Deterministic and smooth."""
    s = math.sin
    if key == "gaming":
        return [0.80 + 0.018 * s(9 * x), 0.30 - 0.16 * x + 0.015 * s(6 * x + 1)]
    if key == "balanced":
        return [0.52 + 0.07 * s(5 * x), 0.32 + 0.05 * s(3 * x + 1)]
    if key == "workspace":
        return [0.30 + 0.08 * s(6 * x), 0.52 + 0.08 * s(6 * x + 2), 0.74 + 0.08 * s(6 * x + 4)]
    if key == "eco":
        e = 0.28 + 0.42 * (1 - ui.ease(min(1.0, x * 1.1)))      # smooth fall to a low plateau
        return [e + 0.01 * s(6 * x), 0.14 + 0.01 * s(5 * x)]
    raise KeyError(key)


def draw(cv, key: str, box: tuple, progress: float):
    """Draw the illustration into box=(x0,y0,x1,y1) on canvas cv; `progress` 0..1 reveals the lines."""
    x0, y0, x1, y1 = box
    cv.create_line(x0, y1, x1, y1, fill=T["border"])            # one baseline, no gridlines
    cv.create_line(x0, y0, x0, y1, fill=T["border"])
    cv.create_text(x1, y1 + dp(10), text="time", anchor="ne", font=ui.font(8), fill=T["faint"])
    n = 48
    shown = max(2, int(n * ui.ease(progress)))
    names = LEGEND[key]
    W, H = int(x1 - x0) + dp(12), int(y1 - y0) + dp(12)      # small margin so caps/dots aren't clipped
    off = dp(6)
    layer, heads = [], []
    for idx, (_label, tok) in enumerate(names):
        pts = []
        for i in range(shown):
            x = i / (n - 1)
            y = curves(key, x)[idx]
            pts.append((off + (x1 - x0) * x, off + (y1 - y0) * (1 - y)))
        if len(pts) >= 2:
            layer.append((pts, T[tok], dp(2.4), True, 0))
            heads.append((pts[-1], T[tok]))
    if aa.available() and layer:
        ss = 3 if progress >= 1 else 2          # cheaper while moving, sharper once still
        img = aa.cached(("mode", key, W, H, shown, ss), lambda: aa.lines_image(W, H, layer, ss))
        aa.put(cv, x0 - off, y0 - off, img)
    elif layer:
        for pts, col, wd, _s, _a in layer:
            cv.create_line(*[c for p in pts for c in (x0 - off + p[0], y0 - off + p[1])], fill=col, width=wd,
                           smooth=True, capstyle="round", joinstyle="round")
    for (hx, hy), col in heads:
        ex, ey = x0 - off + hx, y0 - off + hy
        if progress < 1:                                     # soft leading dot while drawing
            ui.oval(cv, ex - dp(6), ey - dp(6), ex + dp(6), ey + dp(6), fill=ui.mix(col, T["surface"], 0.28))
        ui.oval(cv, ex - dp(3.5), ey - dp(3.5), ex + dp(3.5), ey + dp(3.5), fill=col)
    lx = x0
    for idx, (label, tok) in enumerate(names):
        col = T[tok]
        ui.oval(cv, lx, y1 + dp(26), lx + dp(8), y1 + dp(34), fill=col)
        t = cv.create_text(lx + dp(14), y1 + dp(30), text=label, anchor="w", font=ui.font(9), fill=T["muted"])
        lx = cv.bbox(t)[2] + dp(18)
