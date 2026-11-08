"""The widget kit: every widget is built in a real (invisible) window and driven through its states."""
import tkinter as tk
import unittest
from types import SimpleNamespace
from unittest import mock

from sentinel import aa, ui_kit as ui
from sentinel.ui_kit import charts, drawing, theme
from tests.tk_support import TkTestCase


class ThemeTests(unittest.TestCase):
    def test_scaling_fonts_icons_and_colour_mixing(self):
        self.assertIsInstance(ui.dp(10), int)
        self.assertEqual(ui.font(10), (theme.FONT, 10))
        self.assertEqual(ui.font(10, True), (theme.FONT, 10, "bold"))
        self.assertEqual(ui.mix("#FFFFFF", "#000000", 1.0), "#FFFFFF")
        self.assertEqual(ui.mix("#FFFFFF", "#000000", 0.0), "#000000")
        self.assertEqual(ui.ease(-1), 0.0)
        self.assertEqual(ui.ease(2), 1.0)
        with mock.patch.object(theme, "ICON_FONT", None):
            self.assertEqual(ui.icon("home"), "")
        with mock.patch.object(theme, "ICON_FONT", "Segoe MDL2 Assets"):
            self.assertEqual(ui.icon("home"), chr(0xE80F))
            self.assertEqual(ui.icon("not-an-icon"), "")

    def test_module_attributes_follow_the_theme_module(self):
        self.assertEqual(ui.FONT, theme.FONT)
        self.assertEqual(ui.ICON_FONT, theme.ICON_FONT)
        with self.assertRaises(AttributeError):
            ui.does_not_exist

    def test_hidpi_and_init_fallbacks(self):
        with mock.patch.object(theme, "IS_WIN", False):
            ui.enable_hidpi()                                           # nothing to do off Windows
        shcore = SimpleNamespace(SetProcessDpiAwareness=mock.Mock(side_effect=OSError("old Windows")))
        user32 = SimpleNamespace(SetProcessDPIAware=mock.Mock(side_effect=OSError("also unavailable")))
        with mock.patch.object(theme, "IS_WIN", True), \
                mock.patch.object(theme.ctypes, "windll", SimpleNamespace(shcore=shcore, user32=user32), create=True):
            ui.enable_hidpi()                                           # both attempts fail: silently continue
        user32.SetProcessDPIAware = mock.Mock()
        with mock.patch.object(theme, "IS_WIN", True), \
                mock.patch.object(theme.ctypes, "windll", SimpleNamespace(shcore=shcore, user32=user32), create=True):
            ui.enable_hidpi()
        user32.SetProcessDPIAware.assert_called_once()


class InitTests(TkTestCase):
    def test_init_survives_a_failing_scaling_query_and_picks_fonts(self):
        old = (theme._scale, theme.FONT, theme.ICON_FONT)
        self.addCleanup(lambda: (setattr(theme, "_scale", old[0]), setattr(theme, "FONT", old[1]),
                                 setattr(theme, "ICON_FONT", old[2])))
        broken = SimpleNamespace(winfo_fpixels=mock.Mock(side_effect=tk.TclError("no screen")), tk=self.root.tk)
        with mock.patch.object(theme.tkfont, "families", return_value=("Arial",)), \
                mock.patch.object(theme.tkfont, "nametofont", return_value=SimpleNamespace(actual=lambda k: "Fallback")):
            ui.init(broken)
        self.assertEqual((theme._scale, theme.FONT, theme.ICON_FONT), (1.0, "Fallback", None))


class DrawingTests(TkTestCase):
    def test_shapes_with_and_without_pillow(self):
        for available in (True, False):
            cv = tk.Canvas(self.frame, width=200, height=200)
            cv.pack()
            with mock.patch.object(aa, "available", return_value=available):
                ui.round_rect(cv, 5, 5, 100, 80, 10, fill="#112233", outline="#445566", width=2, tags="a")
                ui.round_rect(cv, 5, 5, 100, 80, 10, fill="#112233", outline="#112233")        # outline == fill
                self.assertIsNone(ui.round_rect(cv, 5, 5, 100, 80, 10)) if available else None
                ui.round_rect(cv, 0, 0, 0, 0, 5, fill="#112233")                              # degenerate size
                ui.oval(cv, 5, 5, 40, 40, fill="#FF0000", outline="#00FF00", width=2)
                ui.oval(cv, 5, 5, 40, 40, fill="#FF0000", outline="#FF0000", tags="b")
            cv.destroy()

    def test_title_bar_wrapping_and_focus_helpers(self):
        ui.dark_titlebar(self.root)
        with mock.patch.object(drawing, "IS_WIN", False):
            ui.dark_titlebar(self.root)
        with mock.patch.object(drawing, "IS_WIN", True), \
                mock.patch.object(drawing.ctypes, "windll", SimpleNamespace(user32=SimpleNamespace(GetParent=mock.Mock(side_effect=OSError("x")))), create=True):
            ui.dark_titlebar(self.root)
        label = tk.Label(self.frame, text="x" * 200)
        label.pack()
        ui.autowrap(label, self.frame, margin=10)
        self.frame.configure(width=300)
        self.frame.event_generate("<Configure>", width=300)
        self.pump()
        calls = []
        rings = []
        w = tk.Frame(self.frame, takefocus=0)
        w.pack()
        ui.make_focusable(w, lambda: calls.append(1), rings.append)
        w.focus_force()
        self.pump()
        w.event_generate("<Return>")
        w.event_generate("<space>")
        w.event_generate("<FocusOut>")
        self.pump()
        self.assertEqual(len(calls), 2)
        ui.make_focusable(tk.Frame(self.frame), lambda: None)           # no ring callback is fine


class ButtonTests(TkTestCase):
    def make(self, **kw):
        calls = []
        b = ui.Btn(self.frame, kw.pop("text", "Go"), command=lambda: calls.append(1), **kw)
        b.pack()
        self.pump()
        return b, calls

    def test_every_style_state_and_icon(self):
        for style in ("primary", "secondary", "danger", "success", "ghost"):
            b, _ = self.make(style=style, icon="check")
            b._set(hover=True)
            b._set(down=True)
            b._set(hover=False, down=False)
            b.set_enabled(False)
            b.set_enabled(True)
        with mock.patch.object(theme, "ICON_FONT", None):
            b, _ = self.make(icon="check")
            b.set_look("danger", "alert")                                 # no icon font: the icon request is ignored

    def test_click_inside_activates_and_dragging_out_does_not(self):
        b, calls = self.make()
        b._set(down=True)
        b._release(SimpleNamespace(x=5, y=5))
        b._set(down=True)
        b._release(SimpleNamespace(x=-50, y=5))
        b._release(SimpleNamespace(x=5, y=5))                              # not pressed: no click
        self.assertEqual(len(calls), 1)
        b.set_enabled(False)
        b._set(down=True)
        b._release(SimpleNamespace(x=5, y=5))
        b._invoke()
        self.assertEqual(len(calls), 1)
        b.set_command(None)
        b.set_enabled(True)
        b._set(down=True)
        b._release(SimpleNamespace(x=5, y=5))
        b._invoke()

    def test_text_command_look_and_focus_ring(self):
        b, calls = self.make(min_width=200)
        b.set_text("A much longer caption")
        b.set_command(lambda: calls.append("new"))
        b._invoke()
        self.assertEqual(calls, ["new"])
        b.set_look("success")
        b.set_look(icon_name="play")                                       # creates the icon font lazily
        b._ring(True)
        b._ring(False)
        b.set_enabled(False)
        b._ring(True)
        b.event_generate("<Enter>")
        b.event_generate("<Leave>")
        b.event_generate("<ButtonPress-1>")
        b.event_generate("<ButtonRelease-1>", x=2, y=2)
        self.pump()


class NavAndSwitchTests(TkTestCase):
    def test_nav_item(self):
        calls = []
        n = ui.NavItem(self.frame, "Home", "home", lambda: calls.append(1))
        n.pack(fill="x")
        self.pump()
        n._set(True)
        n._ring(True)
        n.set_active(True)
        n.set_active(False)
        n.event_generate("<Enter>")
        n.event_generate("<Leave>")
        n.event_generate("<Button-1>")
        self.assertEqual(calls, [1])
        with mock.patch.object(theme, "ICON_FONT", None):
            ui.NavItem(self.frame, "Plain", "home", lambda: None).pack()
        tiny = ui.NavItem(self.frame, "Tiny", "home", lambda: None)
        tiny._draw()                                                        # not laid out yet: nothing to draw

    def test_switch_animates_and_reports(self):
        seen = []
        s = ui.Switch(self.frame, False, seen.append)
        s.pack()
        s.set(True, animate=True)
        self.pump(400)
        self.assertEqual(s._x, 1.0)
        s._click(None)
        self.pump(10)
        s.set(True)                                                         # cancels the running animation
        s._ring(True)
        s._ring(False)
        self.assertEqual(seen, [False])
        ui.Switch(self.frame, True).pack()._click(None) if False else None
        plain = ui.Switch(self.frame, True)
        plain._click(None)                                                  # no command: fine


class FieldAndToastTests(TkTestCase):
    def test_field_focus_return_and_icon_variants(self):
        var = tk.StringVar()
        done = []
        f = ui.Field(self.frame, var, icon_name="folder", on_return=lambda: done.append(1))
        f.pack(fill="x")
        self.pump()
        f.entry.event_generate("<FocusIn>")
        self.assertEqual(f.border_w, 2)
        f.entry.event_generate("<FocusOut>")
        self.assertEqual(f.border_w, 1)
        f.entry.focus_force()
        self.pump()
        f.entry.event_generate("<Return>")
        self.pump()
        self.assertEqual(done, [1])
        with mock.patch.object(theme, "ICON_FONT", None):
            ui.Field(self.frame, var).pack()

    def test_toast_replaces_itself_and_expires(self):
        t = ui.Toast(self.root)
        t.show("one", "success")
        first = t.frame
        t.show("two", "unknown-kind", ms=30)
        self.assertIsNot(t.frame, first)
        self.pump(120)
        self.assertIsNone(t.frame)
        t.hide()

    def test_card_keyboard_activation_and_borders(self):
        card = ui.Card(self.frame, border="#123456")
        card.pack()
        calls = []
        ui.bind_click(card, lambda: calls.append(1))
        ui.bind_click(card, lambda: calls.append(2))                        # second call must not double-bind keys
        self.pump()
        card.event_generate("<FocusIn>")
        self.assertEqual(card.border_w, 2)
        card.event_generate("<FocusOut>")
        self.assertEqual(card.border_w, 1)
        card.event_generate("<Button-1>")
        card.set_border("#abcdef")
        self.assertTrue(calls)
        bare = ui.Card(self.frame, auto_height=False)
        bare.pack(fill="both", expand=True)
        self.pump()
        tiny = ui.Card(self.frame)
        tiny._size = (1, 1)
        tiny._paint()


class IndicatorTests(TkTestCase):
    def test_ring_animates_with_and_without_pillow(self):
        for available in (True, False):
            with mock.patch.object(aa, "available", return_value=available):
                r = ui.Ring(self.frame, size=100, thickness=10)
                r.pack()
                r.set(60, "60", "score", "#FF0000")
                r.set(0, "--")                                              # restarts the animation, no sub-label
                self.pump(300)
                r.set(None, "--", "")
                r.set(250, "max")
                self.pump(300)
                r.destroy()

    def test_pill_meter_pulse_and_badge(self):
        p = ui.Pill(self.frame)
        p.pack()
        p.set("Scanning", "#FBBF24")
        m = ui.Meter(self.frame)
        m.pack(fill="x")
        self.pump()
        m.set(50, "#5B8CFF")
        m.set(0, "#5B8CFF")
        m.set(500, "#5B8CFF")
        pulse = ui.Pulse(self.frame)
        pulse.pack(fill="x")
        self.pump()
        pulse.start()
        pulse.start()
        self.pump(120)
        pulse.stop()
        pulse.stop()
        pulse._tick()                                                       # stopped: does nothing
        tiny = ui.Meter(self.frame)
        tiny._draw()
        tinyp = ui.Pulse(self.frame)
        tinyp._draw()
        b = ui.Badge(self.frame, "shield", "#5B8CFF", size=40)
        b.pack()
        b.update_badge("lock")
        b.update_badge(color="#FF0000")
        with mock.patch.object(theme, "ICON_FONT", None):
            ui.Badge(self.frame, "shield", "#5B8CFF").pack()


class ContainerTests(TkTestCase):
    def test_scroll_frame_wheel_and_scrollbar(self):
        sf = ui.ScrollFrame(self.frame)
        sf.pack(fill="both", expand=True)
        for i in range(60):
            tk.Label(sf.body, text=f"row {i}").pack()
        self.pump(50)
        sf._wheel(SimpleNamespace(delta=-120))
        self.pump(250)
        self.assertGreater(sf._y, 0)
        sf._wheel(SimpleNamespace(delta=-120))
        sf._wheel(SimpleNamespace(delta=-120))                              # while gliding: retargets
        self.pump(250)
        sf._yview("moveto", 0)
        self.assertEqual(sf._y, 0.0)
        sf._wheel(SimpleNamespace(delta=120))
        sf._glide()
        sf._yview("moveto", 0.1)                                            # cancels a running glide
        sf.event_generate("<Enter>")
        sf._leave(None)
        with mock.patch.object(sf, "winfo_containing", side_effect=tk.TclError("gone")):
            sf._leave(None)
        short = ui.ScrollFrame(self.frame)
        short.pack(fill="both", expand=True)
        tk.Label(short.body, text="one").pack()
        self.pump(50)
        short._wheel(SimpleNamespace(delta=-120))                           # nothing to scroll

    def test_collapsible_with_and_without_animation(self):
        notes = []
        for animate in (True, False):
            c = ui.Collapsible(self.frame, "Section", "3 items", animate=animate, on_toggle=lambda: notes.append(1))
            c.pack(fill="x")
            tk.Label(c.body, text="content").pack()
            self.pump(30)
            c.set_count("5 items", "#FF0000")
            c.set_count("none")
            c.set_open(False)                                               # already closed: no-op
            c.toggle()
            self.pump(250)
            self.assertTrue(c.open)
            c.toggle()
            c.toggle()                                                      # interrupts a running animation
            c.toggle()
            self.pump(250)
            c.title.event_generate("<Button-1>")
            self.pump(250)
        self.assertTrue(notes)
        plain = ui.Collapsible(self.frame, "No callback", animate=False)
        plain.pack()
        plain.set_open(True)
        plain.set_open(False)
        with mock.patch.object(theme, "ICON_FONT", None):
            ui.Collapsible(self.frame, "No icons").pack()


class RemainingWidgetBranchTests(TkTestCase):
    def test_scroll_frame_pointer_inside_and_running_glide(self):
        sf = ui.ScrollFrame(self.frame)
        sf.pack(fill="both", expand=True)
        child = tk.Label(sf.body, text="x")
        child.pack()
        self.pump(30)
        with mock.patch.object(sf, "winfo_containing", return_value=child):
            sf._leave(None)                                                 # still inside: wheel stays bound
        sf._anim = sf.after(10000, lambda: None)
        sf._yview("moveto", 0)
        self.assertIsNone(sf._anim)

    def test_click_binding_on_a_widget_without_a_cursor_option(self):
        class NoCursor(tk.Frame):
            def configure(self, cnf=None, **kw):
                if "cursor" in kw:
                    raise tk.TclError("no cursor option")
                return super().configure(cnf, **kw)
        w = NoCursor(self.frame)
        w.pack()
        ui.bind_click(w, lambda: None)

    def test_nav_item_without_an_icon_font_draws_text_only(self):
        with mock.patch.object(theme, "ICON_FONT", None):
            n = ui.NavItem(self.frame, "Plain", "home", lambda: None)
            n.pack(fill="x")
            self.pump(30)
            n.set_active(True)

    def test_card_focus_ring_restores_the_original_border(self):
        card = ui.Card(self.frame)
        card.pack()
        ui.bind_click(card, lambda: None)
        card.event_generate("<FocusOut>")                                   # lost focus before ever gaining it
        self.assertEqual(card.border_w, 1)


class ChartTests(TkTestCase):
    def test_bar_chart_values_gaps_and_hover(self):
        bars = ui.BarChart(self.frame, height=200)
        bars.pack(fill="x")
        bars.configure(width=500)
        self.pump(50)
        bars.set("CPU", "%", [], note="")
        bars.set("CPU", "%", [{"label": "A", "value": 10.0, "color": "#5B8CFF", "sub": "2 runs", "tip": "A tip"},
                              {"label": "B", "value": None, "color": "#5B8CFF"},
                              {"label": "C", "value": 0.0, "color": "#5B8CFF"}], note="measured")
        bars.set("", "", [{"label": "Only none", "value": None, "color": "#FFFFFF"}])
        bars.set("CPU", "%", [{"label": "A", "value": 10.0, "color": "#5B8CFF", "tip": "A tip"}])
        self.pump()
        x1, y1, x2, y2, _ = bars._hits[0]
        bars._hover(SimpleNamespace(x=(x1 + x2) / 2, y=(y1 + y2) / 2))
        self.assertTrue(bars.find_withtag("tip"))
        bars._hover(SimpleNamespace(x=-100, y=-100))                        # off every bar: tooltip removed
        self.assertFalse(bars.find_withtag("tip"))
        bars._hover(SimpleNamespace(x=(x1 + x2) / 2, y=(y1 + y2) / 2))
        bars._hide()
        bars.event_generate("<Motion>", x=20, y=20)
        bars.event_generate("<Leave>")
        tiny = ui.BarChart(self.frame)
        tiny.redraw()                                                       # not laid out: nothing drawn

    def test_line_chart_with_and_without_pillow(self):
        series = [{"name": "Baseline", "color": "#98A4C7", "points": [(0, 1), (1, 3), (2, 2)], "tips": ["t0", "t1"]},
                  {"name": "Gaming", "color": "#8B6CFF", "points": [(0, 2)]},
                  {"name": "Empty", "color": "#FFFFFF", "points": []}]
        for available in (True, False):
            with mock.patch.object(aa, "available", return_value=available):
                lines = ui.LineChart(self.frame, height=180)
                lines.pack(fill="x")
                lines.configure(width=500)
                self.pump(50)
                lines.set("Trend", "%", [], empty="Nothing yet")
                lines.set("Trend", "", series)
                big = [{"name": "Many", "color": "#FFFFFF", "points": [(i, i % 5) for i in range(80)]}]
                lines.set("Trend", "%", big)
                lines.set("Trend", "%", series)
                self.pump()
                x1, y1, x2, y2, _ = lines._hits[0]
                lines._hover(SimpleNamespace(x=(x1 + x2) / 2, y=(y1 + y2) / 2))
                lines.destroy()
        tiny = ui.LineChart(self.frame)
        tiny.redraw()
        flat = ui.LineChart(self.frame)
        flat.pack(fill="x")
        flat.configure(width=400)
        self.pump(50)
        flat.set("Flat", "", [{"name": "Zero", "color": "#FFFFFF", "points": [(5, 0), (5, 0)]}])
        self.assertTrue(charts._Chart.redraw(flat) is None)


if __name__ == "__main__":
    unittest.main()
