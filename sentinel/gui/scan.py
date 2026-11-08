"""Scan page: file/folder scans, results, schedule, quarantine/trust actions."""
from __future__ import annotations

import os
import threading
import time
import tkinter as tk
from tkinter import filedialog, messagebox

from .. import engine, quarantine, schedule, ui_kit as ui
from ..scanner import MALICIOUS, SUSPICIOUS, add_to_allowlist
from ..ui_kit import T, dp
from .text import ago


class ScanPage:
    """Scan page: file/folder scans, results, schedule, quarantine/trust actions."""

    MODE_TEXT = {"quick": "High-risk places: Startup, Temp, Downloads, Desktop, AppData and ProgramData",
                 "full": "Every drive on this PC, risky places first"}

    def _build_scan(self):
        page = tk.Frame(self.content, bg=T["bg"])
        self.pages["scan"] = page
        self.scan_mode = tk.StringVar(value="quick")
        self.scan_path = tk.StringVar(value=self.MODE_TEXT["quick"])

        row = tk.Frame(page, bg=T["bg"])
        row.pack(fill="x", pady=(0, dp(12)))
        for c in range(3):
            row.columnconfigure(c, weight=1, uniform="mode")
        self.mode_cards = {}
        modes = [("quick", "search", "Quick scan", "The places malware usually hides. Takes minutes.", T["primary"]),
                 ("full", "shield", "Full PC scan", "Every drive. Repeat scans skip unchanged files.", T["accent2"]),
                 ("custom", "folder", "Custom scan", "Pick a file or folder you're unsure about.", T["success"])]
        for i, (key, glyph, title, desc, color) in enumerate(modes):
            card = ui.Card(row, radius=16, pad=14)
            card.grid(row=0, column=i, sticky="nsew", padx=(0 if i == 0 else dp(6), 0 if i == 2 else dp(6)))
            top = tk.Frame(card.inner, bg=T["surface"])
            top.pack(fill="x")
            ui.Badge(top, glyph, color, size=36).pack(side="left")
            self._label(top, title, 12, True).pack(side="left", padx=(dp(10), 0))
            d = self._label(card.inner, desc, 9, color=T["muted"], justify="left", anchor="w")
            d.pack(anchor="w", fill="x", pady=(dp(8), 0))
            ui.autowrap(d, card, 28)
            ui.bind_click(card, lambda k=key: self._set_scan_mode(k))
            self.mode_cards[key] = card

        bar = tk.Frame(page, bg=T["bg"])
        bar.pack(fill="x", pady=(0, dp(12)))
        bar.columnconfigure(0, weight=1)
        self.scan_field = ui.Field(bar, self.scan_path, icon_name="folder")
        self.scan_field.grid(row=0, column=0, sticky="ew")
        self.browse_btn = ui.Btn(bar, "Browse", command=self._browse, style="secondary")
        self.browse_btn.grid(row=0, column=1, padx=(dp(10), 0))
        self.btn_scan = ui.Btn(bar, "Start scan", command=self._start_scan, icon="play", min_width=140)
        self.btn_scan.grid(row=0, column=2, padx=(dp(10), 0))
        self.btn_cancel = ui.Btn(bar, "Stop", command=self._cancel_scan, style="secondary", icon="stop")
        self.btn_cancel.grid(row=0, column=3, padx=(dp(10), 0))
        self.btn_cancel.set_enabled(False)

        prog = ui.Card(page, radius=16, pad=16)
        prog.pack(fill="x", pady=(0, dp(12)))
        self.scan_status = tk.StringVar(value="Ready. Pick a scan type and press Start.")
        tk.Label(prog.inner, textvariable=self.scan_status, bg=T["surface"], fg=T["muted"], font=ui.font(10),
                 anchor="w").pack(fill="x")
        self.pulse = ui.Pulse(prog.inner)
        self.pulse.pack(fill="x", pady=(dp(10), dp(12)))
        stats = tk.Frame(prog.inner, bg=T["surface"])
        stats.pack(fill="x")
        self.stat_vars = {}
        for i, (key, caption) in enumerate([("files", "Files checked"), ("cached", "Unchanged (skipped)"),
                                            ("threats", "Threats found"), ("time", "Time")]):
            col = tk.Frame(stats, bg=T["surface"])
            col.pack(side="left", expand=True, fill="x")
            var = tk.StringVar(value="0" if key != "time" else "0s")
            self.stat_vars[key] = var
            tk.Label(col, textvariable=var, bg=T["surface"], fg=T["text"], font=ui.font(16, True)).pack(anchor="w")
            self._label(col, caption, 9, color=T["faint"]).pack(anchor="w")

        # automatic (scheduled) scans through Windows Task Scheduler
        srow = tk.Frame(prog.inner, bg=T["surface"])
        srow.pack(fill="x", pady=(dp(14), 0))
        ui.Badge(srow, "clock", T["primary"], size=30).pack(side="left")
        self._label(srow, "Automatic scan", 10, True).pack(side="left", padx=(dp(10), 0))
        self.sched_lbl = self._label(srow, "", 9, color=T["muted"])
        self.sched_lbl.pack(side="left", padx=(dp(10), 0))
        self.btn_sched_off = ui.Btn(srow, "Turn off", command=self._sched_off, style="ghost", height=32, size=9)
        self.btn_sched_off.pack(side="right")
        self.btn_sched_on = ui.Btn(srow, "Scan daily", command=self._sched_on, style="secondary", height=32, size=9)
        self.btn_sched_on.pack(side="right", padx=(dp(6), dp(6)))
        self.sched_time = tk.StringVar(value="13:00")
        tk.Entry(srow, textvariable=self.sched_time, width=6, justify="center", relief="flat", font=ui.font(10),
                 bg=T["surface2"], fg=T["text"], insertbackground=T["text"], highlightthickness=1,
                 highlightbackground=T["border"], highlightcolor=T["primary"]).pack(side="right", ipady=dp(4))
        self._label(srow, "at", 9, color=T["muted"]).pack(side="right", padx=(0, dp(6)))
        self.after(800, self._sched_refresh)

        res = ui.Card(page, radius=16, pad=16, auto_height=False)
        res.configure(height=dp(240))
        res.pack(fill="both", expand=True)
        head = tk.Frame(res.inner, bg=T["surface"])
        head.pack(fill="x", pady=(0, dp(8)))
        self._label(head, "Results", 12, True).pack(side="left")
        self.res_count = self._label(head, "", 9, color=T["faint"])
        self.res_count.pack(side="left", padx=(dp(10), 0))
        self.btn_trust = ui.Btn(head, "Mark as safe", command=self._trust_selected, style="secondary", icon="trust",
                                height=34)
        self.btn_trust.pack(side="right")
        self.btn_quar = ui.Btn(head, "Quarantine selected", command=self._quarantine_selected, style="danger",
                               icon="lock", height=34)
        self.btn_quar.pack(side="right", padx=(0, dp(8)))
        self.detail = self._label(res.inner, "", 9, color=T["muted"], justify="left", anchor="w")
        self.detail.pack(side="bottom", anchor="w", fill="x", pady=(dp(8), 0))
        ui.autowrap(self.detail, res, 34)
        wrap, self.scan_tv = self._table(res.inner, [("Verdict", 110, False), ("Risk", 60, False),
                                                     ("File", 330, True), ("Why it was flagged", 470, True)],
                                         {"malicious": T["danger"], "suspicious": T["warning"]})
        wrap.pack(fill="both", expand=True)
        self.empty_lbl = self._label(wrap, "", 11, color=T["muted"])
        self.scan_tv.bind("<<TreeviewSelect>>", self._on_pick_result)
        self._set_scan_mode("quick")

    def _set_scan_mode(self, mode):
        if self.scanning:
            return
        self.scan_mode.set(mode)
        for k, card in self.mode_cards.items():
            card.set_border(T["primary"] if k == mode else T["border"], 2 if k == mode else 1)
        if mode == "custom":
            self.scan_field.entry.configure(state="normal")
            self.browse_btn.grid()
            if self.scan_path.get() in self.MODE_TEXT.values():
                self.scan_path.set("")
            self.scan_field.entry.focus_set()
        else:
            self.scan_field.entry.configure(state="readonly")
            self.browse_btn.grid_remove()
            self.scan_path.set(self.MODE_TEXT[mode])

    # scheduled scans -------------------------------------------------------
    def _sched_refresh(self):
        def work():
            text = schedule.describe()
            last = schedule.last_result()
            self.msgs.put(("call", lambda: self._sched_show(text, last)))
        threading.Thread(target=work, daemon=True).start()

    def _sched_show(self, text, last):
        extra = ""
        if last:
            extra = f" · last automatic run {ago(last['time'])}: {last['files']:,} files, {last['threats']} flagged"
            if not self.last_scan or last["time"] > self.last_scan["time"]:
                self.last_scan = {"time": last["time"], "files": last["files"], "threats": last["threats"]}
                self._refresh_home()
        self.sched_lbl.configure(text=f"{text}{extra}")
        self.btn_sched_off.set_enabled(text != "Off")

    def _sched_on(self):
        at = self.sched_time.get().strip()
        if not schedule.HHMM.match(at):
            self.toast.show("Type a 24-hour time such as 13:00.", "warning")
            return
        if not messagebox.askyesno("Automatic scan", f"Create a Windows scheduled task that runs a quick scan every "
                                   f"day at {at}?\n\nIt runs only for your account, without a window, and alerts you "
                                   f"only if something is found. Nothing is quarantined automatically. You can turn "
                                   f"it off here at any time."):
            return

        def work():
            ok, msg = schedule.create(at)
            self.msgs.put(("call", lambda: (self.toast.show(msg, "success" if ok else "danger"),
                                            self._sched_refresh())))
        threading.Thread(target=work, daemon=True).start()

    def _sched_off(self):
        def work():
            ok, msg = schedule.remove()
            self.msgs.put(("call", lambda: (self.toast.show(msg, "success" if ok else "danger"),
                                            self._sched_refresh())))
        threading.Thread(target=work, daemon=True).start()

    def _browse(self):
        d = filedialog.askdirectory()
        if d:
            self.scan_path.set(d)

    def _cancel_scan(self):
        self.cancel.set()
        self.scan_status.set("Stopping...")

    def _on_pick_result(self, _e=None):
        sel = self.scan_tv.selection()
        res = self.results.get(sel[0]) if sel else None
        if not res:
            self.detail.configure(text="")
            return
        why = "   •   ".join(res.reasons)
        self.detail.configure(text=f"Why: {why}")

    def _start_scan(self):
        if self.scanning:
            self.toast.show("A scan is already running.", "info")
            return
        mode = self.scan_mode.get()
        if mode == "quick":
            roots, exclude = engine.quick_scan_plan()
        elif mode == "full":
            roots, exclude = engine.full_scan_plan()
        else:
            path = self.scan_path.get().strip()
            if not path or not os.path.exists(path):
                messagebox.showerror("Scan", "That file or folder doesn't exist.")
                return
            roots, exclude = [path], engine.default_excludes()
        self.cancel.clear()
        self.scan_tv.delete(*self.scan_tv.get_children())
        self.results.clear()
        self.threat_count = 0
        self.empty_lbl.place_forget()
        self.detail.configure(text="")
        self.res_count.configure(text="")
        for var, val in (("files", "0"), ("cached", "0"), ("threats", "0"), ("time", "0s")):
            self.stat_vars[var].set(val)
        self.scan_status.set("Scanning...")
        self.pulse.start()
        self._set_pill("Scanning", T["warning"])
        self.btn_scan.set_enabled(False)
        self.btn_cancel.set_enabled(True)
        self.scanning = True
        self.scan_started = time.time()

        def work():
            eng = engine.ScanEngine()
            try:
                last = 0.0
                for res in eng.scan(roots, exclude, self.cancel):
                    if res.verdict in (SUSPICIOUS, MALICIOUS):
                        self.msgs.put(("scan_hit", res))
                    if time.time() - last > 0.3:
                        last = time.time()
                        self.msgs.put(("scan_progress", (eng.stats.files, eng.stats.cached, res.path)))
            except Exception as e:  # never leave the UI stuck in "Scanning"
                self.msgs.put(("scan_failed", f"{type(e).__name__}: {e}"))
                return
            self.msgs.put(("scan_done", (eng.stats, eng.workers, self.cancel.is_set())))
        threading.Thread(target=work, daemon=True).start()

    def _selected_results(self):
        return [(iid, self.results[iid]) for iid in self.scan_tv.selection() if iid in self.results]

    def _after_result_change(self):
        n = len(self.scan_tv.get_children())
        self.threat_count = n
        self.res_count.configure(text=f"{n} item(s)" if n else "")
        self.stat_vars["threats"].set(str(n))
        if not n and not self.scanning:
            self.empty_lbl.configure(text="No threats left. Your files look clean.")
            self.empty_lbl.place(relx=0.5, rely=0.5, anchor="center")
        self._refresh_home()

    def _quarantine_selected(self):
        picks = self._selected_results()
        if not picks:
            self.toast.show("Select one or more results first.", "info")
            return
        done = failed = 0
        for iid, res in picks:
            try:
                quarantine.quarantine_file(res.path, "; ".join(res.reasons), res.sha256)
                self.scan_tv.delete(iid)
                self.results.pop(iid, None)
                done += 1
            except Exception as e:
                failed += 1
                messagebox.showerror("Quarantine", f"{res.path}\n{e}")
        self._after_result_change()
        if done:
            self.toast.show(f"{done} file(s) moved to quarantine.", "success")

    def _trust_selected(self):
        picks = [(i, r) for i, r in self._selected_results() if r.sha256]
        if not picks:
            self.toast.show("Select one or more results first.", "info")
            return
        if not messagebox.askyesno("Mark as safe", "Trust the selected file(s)? They will no longer be flagged.\n"
                                   "Only do this if you're sure they're safe."):
            return
        for iid, res in picks:
            add_to_allowlist(res.sha256, res.path)
            self.scanner.allow.add(res.sha256)
            self.scan_tv.delete(iid)
            self.results.pop(iid, None)
        self._after_result_change()
        self.toast.show(f"{len(picks)} file(s) marked as safe.", "success")
