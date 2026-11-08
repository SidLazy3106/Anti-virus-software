"""Antialiased drawing helpers (Pillow) and the mode illustrations that use them."""
import tkinter as tk
import unittest
from unittest import mock

from sentinel import aa, mode_art, optimizer
from tests.tk_support import TkTestCase


class ColourAndCacheTests(unittest.TestCase):
    def test_rgba(self):
        self.assertEqual(aa.rgba("#FF8000"), (255, 128, 0, 255))
        self.assertEqual(aa.rgba("0A0B0C", 10), (10, 11, 12, 10))
        self.assertEqual(aa.rgba(None), (0, 0, 0, 0))
        self.assertEqual(aa.rgba(""), (0, 0, 0, 0))

    def test_cache_reuses_and_evicts_the_oldest(self):
        calls = []
        make = lambda: calls.append(1) or object()  # noqa: E731
        with mock.patch.object(aa, "_cache", aa.OrderedDict()), mock.patch.object(aa, "_CACHE_MAX", 2):
            a = aa.cached("a", make)
            self.assertIs(aa.cached("a", make), a)
            aa.cached("b", make)
            aa.cached("c", make)                                    # evicts "a" (least recently used)
            self.assertNotIn("a", aa._cache)
            self.assertEqual(len(calls), 3)

    def test_available_reflects_pillow(self):
        self.assertTrue(aa.available())
        with mock.patch.object(aa, "Image", None):
            self.assertFalse(aa.available())


class ShapeImageTests(unittest.TestCase):
    def test_small_and_large_rounded_rectangles(self):
        small = aa.rrect_image(20, 10, 4, fill="#112233", outline="#445566", width=1)
        self.assertEqual(small.size, (20, 10))
        large = aa.rrect_image(300, 120, 16, fill="#112233", outline="#445566", width=2)      # nine-sliced
        self.assertEqual(large.size, (300, 120))
        self.assertEqual(large.getpixel((150, 60))[3], 255)                                    # opaque centre
        self.assertEqual(large.getpixel((0, 0))[3], 0)                                         # transparent corner
        plain = aa.rrect_image(0, 0, 99, fill=None, outline=None)                              # degenerate sizes are clamped
        self.assertEqual(plain.size, (1, 1))

    def test_circles(self):
        self.assertEqual(aa.circle_image(12, fill="#FFFFFF").size, (12, 12))
        self.assertEqual(aa.circle_image(0.2, outline="#FFFFFF", width=2).size, (1, 1))

    def test_ring_gauge_empty_partial_and_full(self):
        for frac in (0.0, 0.4, 1.0, 5.0, -1.0):
            img = aa.ring_image(60, 6, frac, "#5B8CFF", "#222222")
            self.assertEqual(img.size, (60, 60))
        empty = aa.ring_image(60, 6, 0.0, "#5B8CFF", "#222222")
        full = aa.ring_image(60, 6, 1.0, "#5B8CFF", "#222222")
        self.assertNotEqual(empty.tobytes(), full.tobytes())

    def test_spline_passes_through_the_points(self):
        self.assertEqual(aa.smooth_points([(0, 0), (1, 1)]), [(0, 0), (1, 1)])
        pts = [(0, 0), (10, 10), (20, 0), (30, 10)]
        smooth = aa.smooth_points(pts, per_segment=4)
        self.assertEqual(smooth[-1], pts[-1])
        self.assertGreater(len(smooth), len(pts))
        for p in pts[:-1]:
            self.assertTrue(any(abs(p[0] - q[0]) < 1e-9 and abs(p[1] - q[1]) < 1e-9 for q in smooth))

    def test_line_images(self):
        series = [([(0, 10), (20, 30), (40, 5)], "#5B8CFF", 2, True, 60),
                  ([(0, 0), (40, 40)], "#FFFFFF", 1, False, 0),
                  ([(5, 5)], "#FFFFFF", 1, False, 0)]                       # a single point draws nothing
        img = aa.lines_image(41, 41, series, ss=2)
        self.assertEqual(img.size, (41, 41))
        self.assertIsNotNone(img.getbbox())                            # something was drawn

    def test_line_image_scaling_without_reduce(self):
        class Plain:
            def __init__(self, img):
                self.img = img

            def resize(self, size, resample):
                return self.img.resize(size, resample)
        real_new = aa.Image.new
        with mock.patch.object(aa.Image, "new", side_effect=lambda *a, **k: Plain(real_new(*a, **k))), \
                mock.patch.object(aa.ImageDraw, "Draw", side_effect=lambda im: aa.ImageDraw.ImageDraw(im.img)):
            img = aa.lines_image(10, 10, [([(0, 0), (9, 9)], "#FFFFFF", 1, False, 0)], ss=2)
        self.assertEqual(img.size, (10, 10))


class CanvasTests(TkTestCase):
    def test_put_places_an_image_and_prunes_references(self):
        cv = tk.Canvas(self.frame, width=100, height=100)
        cv.pack()
        img = aa.circle_image(10, fill="#FF0000")
        first = aa.put(cv, 5.4, 5.6, img, tags="x")
        self.assertIn(first, cv.find_withtag("x"))
        items = [aa.put(cv, 0, 0, img) for _ in range(60)]
        cv.delete(*items[:30])
        aa.put(cv, 0, 0, img)                                              # triggers the pruning of deleted items
        self.assertLess(len(cv._aa_refs), 62)


class ModeArtTests(TkTestCase):
    def test_every_illustration_draws_with_and_without_pillow(self):
        for key in optimizer.PROFILES:
            for use_aa in (True, False):
                for progress in (0.0, 0.5, 1.0):
                    cv = tk.Canvas(self.frame, width=400, height=240)
                    cv.pack()
                    with mock.patch.object(mode_art.aa, "available", return_value=use_aa):
                        mode_art.draw(cv, key, (30, 20, 370, 160), progress)
                    self.assertTrue(cv.find_all())
                    cv.destroy()

    def test_unknown_profile_is_rejected(self):
        with self.assertRaises(KeyError):
            mode_art.curves("turbo", 0.5)


if __name__ == "__main__":
    unittest.main()
