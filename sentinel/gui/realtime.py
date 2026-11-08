"""Real-time shield page."""
from __future__ import annotations

import os
import tkinter as tk
from pathlib import Path
from tkinter import messagebox

from .. import ui_kit as ui
from ..monitor import ProcessWatcher, RealtimeMonitor
from ..ui_kit import T, dp


class RealtimePage:
    """Real-time shield page."""

    def _build_realtime(self):
        page = tk.Frame(self.content, bg=T["bg"])
        self.pages["realtime"] = page

        top = ui.Card(page, radius=20, pad=22)
        top.pack(fill="x", pady=(0, dp(14)))
        row = tk.Frame(top.inner, bg=T["surface"])
        row.pack(fill="x")
        self.rt_badge = ui.Badge(row, "shield", T["warning"], size=56)
        self.rt_badge.pack(side="left")
        txt = tk.Frame(row, bg=T["surface"])
        txt.pack(side="left", fill="x", expand=True, padx=dp(16))
        self.rt_title = self._label(txt, "Real-time shield is off", 16, True, anchor="w")
        self.rt_title.pack(anchor="w")
        d = self._label(txt, "Watches your folders for new or changed files, plants ransomware decoys, and flags "
                        "suspicious program chains such as Word starting PowerShell.", 10, color=T["muted"],
                        justify="left", anchor="w")
        d.pack(anchor="w", fill="x", pady=(dp(4), 0))
        ui.autowrap(d, top, 22 * 2 + 56 + 32 + 70 + 8)
        self.rt_switch = ui.Switch(row, False, self._on_rt_switch)
        self.rt_switch.pack(side="right")

        opts = ui.Card(page, radius=18, pad=18)
        opts.pack(fill="x", pady=(0, dp(14)))
        self._label(opts.inner, f"Folders to watch (separate with  {os.pathsep}  )", 10, color=T["muted"]).pack(
            anchor="w", pady=(0, dp(6)))
        self.rt_paths = tk.StringVar(value=str(Path.home() / "Downloads"))
        ui.Field(opts.inner, self.rt_paths, icon_name="folder").pack(fill="x", pady=(0, dp(14)))
        self.auto_q = tk.BooleanVar(value=False)
        self.canary = tk.BooleanVar(value=True)
        for var, title, desc in ((self.auto_q, "Quarantine dangerous files automatically",
                                  "Moves files that are clearly malicious out of reach as soon as they appear."),
                                 (self.canary, "Ransomware decoy files",
                                  "Hidden bait files in watched folders. If something changes them, you're alerted.")):
            line = tk.Frame(opts.inner, bg=T["surface"])
            line.pack(fill="x", pady=(0, dp(10)))
            sw = ui.Switch(line, var.get(), lambda v, var=var: var.set(v))
            sw.pack(side="left")
            col = tk.Frame(line, bg=T["surface"])
            col.pack(side="left", padx=(dp(14), 0))
            self._label(col, title, 10, True).pack(anchor="w")
            self._label(col, desc, 9, color=T["muted"]).pack(anchor="w")

        act = ui.Card(page, radius=18, pad=18, auto_height=False)
        act.configure(height=dp(200))
        act.pack(fill="both", expand=True)
        self._label(act.inner, "Live activity", 12, True).pack(anchor="w", pady=(0, dp(6)))
        fr, self.rt_log = self._log_box(act.inner, height=8)
        fr.pack(fill="both", expand=True)
        self._append(self.rt_log, "The shield is off. Switch it on to start watching.", "muted")

    def _on_rt_switch(self, value):
        if value != (self.monitor is not None):
            self._toggle_rt()
        self.rt_switch.set(self.rt_active)  # snap back if starting failed

    def _toggle_rt(self):
        if self.monitor:
            self.monitor.stop()
            self.procwatch.stop()
            self.monitor = self.procwatch = None
            self.rt_active = False
            self.rt_switch.set(False)
            self.rt_badge.update_badge(color=T["warning"])
            self.rt_title.configure(text="Real-time shield is off")
            self._append(self.rt_log, "Shield stopped.", "muted")
            self._update_side()
            self._refresh_home()
            return

        raw = self.rt_paths.get()
        paths = [p.strip() for p in raw.split(os.pathsep) if p.strip() and os.path.isdir(p.strip())]
        if not paths:
            messagebox.showerror("Real-time shield", "No valid folders to watch.")
            return
        emit = lambda a: self.msgs.put(("alert", a))
        try:
            self.monitor = RealtimeMonitor(self.scanner, paths, emit, self.auto_q.get(), self.canary.get())
            self.monitor.start()
            self.procwatch = ProcessWatcher(emit, scanner=self.scanner)
            self.procwatch.start()
        except RuntimeError as e:
            if self.monitor:
                self.monitor.stop()
            self.monitor = self.procwatch = None
            messagebox.showerror("Real-time shield", str(e))
            return
        self.rt_active = True
        self.rt_switch.set(True)
        self.rt_badge.update_badge(color=T["success"])
        self.rt_title.configure(text="Real-time shield is on")
        self._append(self.rt_log, f"Watching: {', '.join(paths)}", "ok")
        self._update_side()
        self._refresh_home()
        self.toast.show("Real-time shield is on.", "success")
