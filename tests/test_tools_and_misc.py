"""The extension-rule sync tool's command line, and a couple of small engine/theme branches."""
import importlib.util
import tkinter as tk
from tkinter import ttk
import io
import contextlib
import shutil
import tempfile
import unittest
from pathlib import Path
from unittest import mock

from sentinel import engine
from tests.tk_support import TkTestCase


def load_tool():
    path = Path(__file__).resolve().parent.parent / "tools" / "sync_extension_rules.py"
    spec = importlib.util.spec_from_file_location("sync_tool_under_test", path)
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


class SyncToolTests(unittest.TestCase):
    def setUp(self):
        self.tool = load_tool()
        self.d = Path(tempfile.mkdtemp())
        self.addCleanup(shutil.rmtree, self.d, True)

    def test_check_mode_reports_stale_files(self):
        self.assertEqual(self.tool.main(["--check"]), 0)                 # the repository is in sync
        target = self.d / "url_rules.js"
        with mock.patch.object(self.tool, "expected_files", return_value={target: b"new"}), \
                mock.patch.object(self.tool, "ROOT", self.d):
            err = io.StringIO()
            with contextlib.redirect_stderr(err):
                self.assertEqual(self.tool.main(["--check"]), 1)
            self.assertIn("out of date", err.getvalue())

    def test_write_mode_creates_the_files(self):
        target = self.d / "out.js"
        with mock.patch.object(self.tool, "expected_files", return_value={target: b"data"}), \
                mock.patch.object(self.tool, "ROOT", self.d):
            out = io.StringIO()
            with contextlib.redirect_stdout(out):
                self.assertEqual(self.tool.main([]), 0)
        self.assertEqual(target.read_bytes(), b"data")
        self.assertIn("wrote out.js", out.getvalue())

    def test_generated_javascript_holds_the_shared_rules(self):
        js = self.tool.render_rules_js()
        self.assertTrue(js.startswith("// GENERATED"))
        self.assertIn('"brands"', js)
        self.assertNotIn("_comment", js)


class FingerprintTests(unittest.TestCase):
    def test_unreadable_rule_files_and_folders_are_tolerated(self):
        with mock.patch.object(Path, "stat", side_effect=OSError("denied")):
            self.assertIsInstance(engine.rules_fingerprint(), str)


class ThemeFallbackTests(TkTestCase):
    def test_scrollbar_style_without_the_custom_layout_is_tolerated(self):
        from sentinel import ui_kit
        real_layout = ttk.Style.layout
        calls = {"n": 0}

        def layout(self_, name, spec=None):
            calls["n"] += 1
            if calls["n"] == 2:                     # the scrollbar layout (the table layout is the first call)
                raise tk.TclError("no layout")
            return real_layout(self_, name, spec)
        with mock.patch("tkinter.ttk.Style.layout", layout):
            ui_kit.style_ttk(self.root)
        with mock.patch("tkinter.ttk.Style.theme_use", side_effect=tk.TclError("no theme")):
            ui_kit.style_ttk(self.root)
        ui_kit.style_ttk(self.root)                 # restore the normal look for the other tests


if __name__ == "__main__":
    unittest.main()
