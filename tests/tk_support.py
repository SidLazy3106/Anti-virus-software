"""Helpers for tests that need a real Tk window (skipped automatically when no display is available)."""
import tkinter as tk
import unittest

from sentinel import ui_kit


def make_root():
    """A fully transparent, initialised root window (so layout is real but nothing flashes on screen)."""
    ui_kit.enable_hidpi()
    try:
        root = tk.Tk()
    except tk.TclError as e:               # headless machine
        raise unittest.SkipTest(f"no display available: {e}")
    root.attributes("-alpha", 0.0)
    ui_kit.init(root)
    ui_kit.style_ttk(root)
    return root


_ROOT = None


class TkTestCase(unittest.TestCase):
    """One root window per test class; widgets are created inside `self.frame`, which is emptied between tests."""
    root: tk.Tk

    @classmethod
    def setUpClass(cls):
        global _ROOT
        if _ROOT is None:
            _ROOT = make_root()
        cls.root = _ROOT

    def setUp(self):
        self.frame = tk.Frame(self.root, bg=ui_kit.T["bg"], width=600, height=400)
        self.frame.pack(fill="both", expand=True)
        self.addCleanup(self.frame.destroy)

    def pump(self, ms=0):
        """Process pending Tk events (and optionally let timers run for `ms` milliseconds)."""
        import time
        end = time.time() + ms / 1000
        self.root.update()
        while time.time() < end:
            self.root.update()
            time.sleep(0.005)


def close_shared_root():
    global _ROOT
    if _ROOT is not None:
        _ROOT.destroy()
        _ROOT = None
