"""Antialiased drawing for Tk canvases.

Tk's own canvas on Windows draws polygons, arcs and lines without antialiasing, so curves look jagged and graph
lines look pixelated. Here shapes are drawn with Pillow at SS-times resolution, scaled down (which smooths every
edge), and placed on the canvas as transparent images. Tk blends the alpha channel, so the shapes sit cleanly on
any background. Text is still drawn by Tk, which already smooths fonts.

If Pillow is missing, `available()` is False and callers fall back to plain Tk drawing.
"""
from __future__ import annotations

import math
from collections import OrderedDict

try:
    from PIL import Image, ImageDraw, ImageTk
except ImportError:  # optional dependency
    Image = ImageDraw = ImageTk = None

SS = 4                     # supersampling factor for small shapes
LINE_SS = 3                # graph lines (larger images, redrawn often)
_cache: "OrderedDict[tuple, object]" = OrderedDict()
_CACHE_MAX = 256


def available() -> bool:
    return Image is not None


def rgba(color, alpha: int = 255):
    if not color:
        return (0, 0, 0, 0)
    c = color.lstrip("#")
    return (int(c[0:2], 16), int(c[2:4], 16), int(c[4:6], 16), alpha)


def cached(key, make):
    """Small LRU cache for rendered PIL images."""
    return _cached(key, make)


def _cached(key, make):
    img = _cache.get(key)
    if img is None:
        img = make()
        _cache[key] = img
        if len(_cache) > _CACHE_MAX:
            _cache.popitem(last=False)
    else:
        _cache.move_to_end(key)
    return img


# ── shape images (PIL, 1x, RGBA) ─────────────────────────────────────────
def _rrect_direct(w, h, r, fill, outline, width):
    s = SS
    big = Image.new("RGBA", (w * s, h * s), (0, 0, 0, 0))
    d = ImageDraw.Draw(big)
    d.rounded_rectangle((0, 0, w * s - 1, h * s - 1), radius=max(0, r * s), fill=rgba(fill) if fill else None,
                        outline=rgba(outline) if outline and width else None,
                        width=max(1, int(round(width * s))) if outline and width else 0)
    return big.resize((w, h), Image.LANCZOS)


def rrect_image(w: int, h: int, r: float, fill=None, outline=None, width: float = 0):
    """Smooth rounded rectangle. Large ones are built by nine-slicing a small supersampled tile, so a full-width
    card costs about as much as a button."""
    w, h = max(1, int(round(w))), max(1, int(round(h)))
    r = max(0.0, min(r, w / 2, h / 2))

    def make():
        c = int(math.ceil(r + max(width, 1))) + 1
        if w < 2 * c + 2 or h < 2 * c + 2:
            return _rrect_direct(w, h, r, fill, outline, width)
        size = 2 * c + 1
        tile = _rrect_direct(size, size, r, fill, outline, width)
        out = Image.new("RGBA", (w, h), (0, 0, 0, 0))
        mid = size - 2 * c                      # 1px strip that is uniform along its length
        # corners
        out.paste(tile.crop((0, 0, c, c)), (0, 0))
        out.paste(tile.crop((size - c, 0, size, c)), (w - c, 0))
        out.paste(tile.crop((0, size - c, c, size)), (0, h - c))
        out.paste(tile.crop((size - c, size - c, size, size)), (w - c, h - c))
        # edges
        out.paste(tile.crop((c, 0, c + mid, c)).resize((w - 2 * c, c), Image.NEAREST), (c, 0))
        out.paste(tile.crop((c, size - c, c + mid, size)).resize((w - 2 * c, c), Image.NEAREST), (c, h - c))
        out.paste(tile.crop((0, c, c, c + mid)).resize((c, h - 2 * c), Image.NEAREST), (0, c))
        out.paste(tile.crop((size - c, c, size, c + mid)).resize((c, h - 2 * c), Image.NEAREST), (w - c, c))
        # centre
        out.paste(tile.crop((c, c, c + mid, c + mid)).resize((w - 2 * c, h - 2 * c), Image.NEAREST), (c, c))
        return out
    return _cached(("rr", w, h, round(r, 2), fill, outline, round(width, 2)), make)


def circle_image(d: float, fill=None, outline=None, width: float = 0):
    d = max(1, int(round(d)))

    def make():
        s = SS
        big = Image.new("RGBA", (d * s, d * s), (0, 0, 0, 0))
        ImageDraw.Draw(big).ellipse((0, 0, d * s - 1, d * s - 1), fill=rgba(fill) if fill else None,
                                    outline=rgba(outline) if outline and width else None,
                                    width=max(1, int(round(width * s))) if outline and width else 0)
        return big.resize((d, d), Image.LANCZOS)
    return _cached(("ci", d, fill, outline, round(width, 2)), make)


def ring_image(size: int, thickness: float, frac: float, color, track):
    """Circular gauge: full track plus an arc from 12 o'clock, clockwise, with round caps."""
    size = max(4, int(round(size)))
    frac = max(0.0, min(1.0, frac))

    def make():
        s = SS
        S, t = size * s, thickness * s
        big = Image.new("RGBA", (S, S), (0, 0, 0, 0))
        d = ImageDraw.Draw(big)
        box = (0, 0, S - 1, S - 1)              # PIL grows arc/outline width inward from the box edge
        d.ellipse(box, outline=rgba(track), width=int(round(t)))
        if frac > 0.001:
            if frac >= 0.999:
                d.ellipse(box, outline=rgba(color), width=int(round(t)))
            else:
                start, end = -90, -90 + 360 * frac
                d.arc(box, start, end, fill=rgba(color), width=int(round(t)))
                rad = (S - t) / 2
                for ang in (start, end):          # round caps
                    a = math.radians(ang)
                    cx, cy = S / 2 + rad * math.cos(a), S / 2 + rad * math.sin(a)
                    d.ellipse((cx - t / 2, cy - t / 2, cx + t / 2, cy + t / 2), fill=rgba(color))
        return big.resize((size, size), Image.LANCZOS)
    return _cached(("ring", size, round(thickness, 2), round(frac, 3), color, track), make)


def smooth_points(pts: list, per_segment: int = 8) -> list:
    """Catmull-Rom spline through [(x, y)...]; returns a denser list that passes through every input point."""
    if len(pts) < 3:
        return list(pts)
    out = []
    p = [pts[0]] + list(pts) + [pts[-1]]
    for i in range(1, len(p) - 2):
        p0, p1, p2, p3 = p[i - 1], p[i], p[i + 1], p[i + 2]
        for k in range(per_segment):
            t = k / per_segment
            t2, t3 = t * t, t * t * t
            out.append(tuple(0.5 * ((2 * p1[j]) + (-p0[j] + p2[j]) * t + (2 * p0[j] - 5 * p1[j] + 4 * p2[j] - p3[j]) * t2
                                    + (-p0[j] + 3 * p1[j] - 3 * p2[j] + p3[j]) * t3) for j in (0, 1)))
    out.append(pts[-1])
    return out


def lines_image(w: int, h: int, series: list, ss: int = LINE_SS):
    """series: [(points[(x,y)...] in pixel coords of a w*h box, colour, width, smooth, fill_below_alpha)].
    Draws smooth polylines with round joins/caps (and optional soft area fill) into one transparent image."""
    w, h = max(1, int(w)), max(1, int(h))
    big = Image.new("RGBA", (w * ss, h * ss), (0, 0, 0, 0))
    d = ImageDraw.Draw(big)
    for pts, color, width, smooth, area in series:
        if len(pts) < 2:
            continue
        pp = smooth_points(pts) if smooth else pts
        sp = [(x * ss, y * ss) for x, y in pp]
        if area:
            poly = sp + [(sp[-1][0], h * ss), (sp[0][0], h * ss)]
            d.polygon(poly, fill=rgba(color, area))
        lw = max(1, int(round(width * ss)))
        d.line(sp, fill=rgba(color), width=lw, joint="curve")
        for x, y in (sp[0], sp[-1]):
            d.ellipse((x - lw / 2, y - lw / 2, x + lw / 2, y + lw / 2), fill=rgba(color))
    return big.reduce(ss) if hasattr(big, "reduce") else big.resize((w, h), Image.LANCZOS)


# ── canvas helpers ───────────────────────────────────────────────────────
def put(cv, x, y, pil_img, tags=None):
    """Place a PIL image on the canvas at (x, y) top-left and keep the Tk image alive while the item exists."""
    photo = ImageTk.PhotoImage(pil_img, master=cv)
    item = cv.create_image(int(round(x)), int(round(y)), image=photo, anchor="nw", tags=tags)
    refs = cv.__dict__.setdefault("_aa_refs", {})
    refs[item] = photo
    if len(refs) > 48:                            # drop images whose canvas items were deleted
        alive = set(cv.find_all())
        for k in [k for k in refs if k not in alive]:
            del refs[k]
    return item
