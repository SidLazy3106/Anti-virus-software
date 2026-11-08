"""Shared fixture for tests that drive the real X-Secure window (invisible, with slow or system-changing parts faked)."""
import shutil
import tempfile
import time
import tkinter as tk
import unittest
from pathlib import Path
from unittest import mock

from sentinel import schedule
from tests.tk_support import make_root


_APP = None


def _scheduler_fakes():
    from contextlib import ExitStack
    stack = ExitStack()
    stack.enter_context(mock.patch.object(schedule, "describe", return_value="Off"))
    stack.enter_context(mock.patch.object(schedule, "last_result", return_value=None))
    return stack


def shared_app():
    """One invisible window for the whole test session (creating Tk windows repeatedly is slow and, on some
    machines, eventually fails). Task Scheduler is replaced so no test reads or creates a real scheduled task."""
    global _APP
    if _APP is None:
        make_root().destroy()                       # skips cleanly on a machine without a display
        with _scheduler_fakes():                        # the window reads the schedule once while it is built
            pass
        from sentinel.gui import App
        try:
            _APP = App()
        except tk.TclError as e:
            raise unittest.SkipTest(f"cannot open a window: {e}")
        _APP.attributes("-alpha", 0.0)
        _APP.update()
    return _APP


def close_shared_app():
    global _APP
    if _APP is not None:
        _APP._close()
        _APP = None


class AppTestCase(unittest.TestCase):
    app = None

    @classmethod
    def setUpClass(cls):
        cls._fakes = _scheduler_fakes()                 # active only while this class runs, so schedule tests see the real module
        cls._fakes.__enter__()
        cls.app = shared_app()

    @classmethod
    def tearDownClass(cls):
        cls._fakes.__exit__(None, None, None)

    # ── helpers ──────────────────────────────────────────────────────────
    def settle(self, condition=lambda: False, timeout=15.0):
        """Run the UI event loop (which drains the worker-thread queue) until `condition()` or the timeout."""
        end = time.time() + timeout
        while time.time() < end:
            self.app.update()
            if condition():
                return True
            time.sleep(0.01)
        return condition()

    def temp_dir(self):
        d = Path(tempfile.mkdtemp())
        self.addCleanup(shutil.rmtree, d, True)
        return d
