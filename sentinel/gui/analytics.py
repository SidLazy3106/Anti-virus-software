"""Performance analytics page."""
from __future__ import annotations

import threading
import time
import tkinter as tk
from tkinter import messagebox

from .. import analytics, optimizer, ui_kit as ui
from ..ui_kit import T, dp


class AnalyticsPage:
    """Performance analytics page."""

    AN_ORDER = ["baseline", "gaming", "balanced", "workspace", "eco", "custom"]
    AN_NAMES = {"baseline": "Baseline", "gaming": "Gaming", "balanced": "Balanced", "workspace": "Workspace",
                "eco": "Eco", "custom": "Custom plan"}

    def _build_analytics(self):
        page = tk.Frame(self.content, bg=T["bg"])
        self.pages["analytics"] = page
        sf = ui.ScrollFrame(page)
        sf.pack(fill="both", expand=True)
        body = sf.body
        self.an_metric, self.an_busy, self.an_secs = "cpu_avg", False, 30

        c = ui.Card(body, radius=16, pad=16)
        c.pack(fill="x", pady=(0, dp(12)))
        row = tk.Frame(c.inner, bg=T["surface"])
        row.pack(fill="x")
        self.an_switch = ui.Switch(row, analytics.has_consent(), command=self._an_consent)
        self.an_switch.pack(side="left")
        tt = tk.Frame(row, bg=T["surface"])
        tt.pack(side="left", padx=(dp(12), 0))
        self._label(tt, "Record performance measurements on this PC", 11, True).pack(anchor="w")
        self._label(tt, "Off by default. Measurements are real readings of this PC, saved only on this PC.", 9,
                    color=T["muted"]).pack(anchor="w")
        ctl = tk.Frame(c.inner, bg=T["surface"])
        ctl.pack(fill="x", pady=(dp(12), 0))
        self.btn_an_base = ui.Btn(ctl, "Record baseline", command=lambda: self._an_measure("baseline"),
                                  style="secondary", icon="clock", height=36)
        self.btn_an_base.pack(side="left")
        self.btn_an_now = ui.Btn(ctl, "Measure current mode", command=lambda: self._an_measure("mode"), icon="play",
                                 height=36)
        self.btn_an_now.pack(side="left", padx=(dp(8), 0))
        self.btn_an_dur = ui.Btn(ctl, "30 s", command=self._an_cycle, style="ghost", height=36)
        self.btn_an_dur.pack(side="left", padx=(dp(8), 0))
        self.btn_an_cancel = ui.Btn(ctl, "Cancel", command=self._an_cancel, style="ghost", height=36)
        self.btn_an_cancel.pack(side="left")
        self.btn_an_cancel.set_enabled(False)
        ui.Btn(ctl, "Delete my measurements", command=self._an_clear, style="ghost", height=36).pack(side="right")
        self.an_meter = ui.Meter(c.inner)
        self.an_meter.pack(fill="x", pady=(dp(10), dp(4)))
        self.an_status = self._label(c.inner, "", 9, color=T["muted"], justify="left", anchor="w")
        self.an_status.pack(anchor="w", fill="x")
        ui.autowrap(self.an_status, c, 34)
        tip = self._label(c.inner, "For a fair comparison: record the baseline first, then switch mode and measure "
                          "again while doing the same thing (for example an idle desktop, or the same game or app) "
                          "and in the same power conditions.", 9, color=T["faint"], justify="left", anchor="w")
        tip.pack(anchor="w", fill="x", pady=(dp(4), 0))
        ui.autowrap(tip, c, 34)

        ch = ui.Card(body, radius=16, pad=16)
        ch.pack(fill="x", pady=(0, dp(12)))
        self._label(ch.inner, "Compare modes", 12, True).pack(anchor="w")
        chips = tk.Frame(ch.inner, bg=T["surface"])
        chips.pack(fill="x", pady=(dp(8), dp(8)))
        self.an_chips = {}
        for i, (key, label, unit, _w) in enumerate(analytics.METRICS):
            short = {"cpu_avg": "CPU avg", "cpu_peak": "CPU peak", "ram_avg": "RAM", "procs": "Processes",
                     "disk": "Disk", "latency": "Responsiveness", "power": "Power", "fps": "FPS",
                     "frametime": "Frame time"}[key]
            b = ui.Btn(chips, short, command=lambda k=key: self._an_select(k), style="secondary" if key != self.an_metric
                       else "primary", height=30, size=9, padx=12)
            b.pack(side="left", padx=(0, dp(6)), pady=dp(2))
            self.an_chips[key] = b
        self.an_bars = ui.BarChart(ch.inner, height=250)
        self.an_bars.pack(fill="x")
        self.an_lines = ui.LineChart(ch.inner, height=190)
        self.an_lines.pack(fill="x", pady=(dp(8), 0))
        self.an_detail = self._label(ch.inner, "", 9, color=T["muted"], justify="left", anchor="w")
        self.an_detail.pack(anchor="w", fill="x", pady=(dp(8), 0))
        ui.autowrap(self.an_detail, ch, 34)

        ex = ui.Card(body, radius=16, pad=16)
        ex.pack(fill="x", pady=(0, dp(6)))
        self._label(ex.inner, "Public benchmark data", 12, True).pack(anchor="w")
        self.an_ext = self._label(ex.inner, "", 9, color=T["muted"], justify="left", anchor="w")
        self.an_ext.pack(anchor="w", fill="x", pady=(dp(4), 0))
        ui.autowrap(self.an_ext, ex, 34)

    def _an_enter(self):
        self.an_switch.set(analytics.has_consent())
        name = ((self.hw_profile or {}).get("cpu") or {}).get("name") or "this CPU"
        ext = analytics.external_benchmarks(name)
        self.an_ext.configure(text=(
            "Not available. X-Secure does not bundle or download public benchmark databases, so no external "
            f"numbers are shown for {name}. If a source is added later it will appear here only, labelled with its "
            "name, retrieval date and methodology, and never mixed into your measured results above.")
            if ext is None else str(ext))
        self._an_refresh()

    def _an_consent(self, on):
        analytics.set_consent(on)
        self.toast.show("Measurements are on." if on else "Measurements are off. Existing data stays until you "
                        "delete it.", "info")

    def _an_cycle(self):
        self.an_secs = {30: 60, 60: 120, 120: 30}[self.an_secs]
        self.btn_an_dur.set_text(f"{self.an_secs} s")

    def _an_select(self, key):
        self.an_metric = key
        for k, b in self.an_chips.items():
            b.set_look("primary" if k == key else "secondary")
        self._an_refresh()

    def _an_measure(self, kind):
        if self.an_busy:
            return
        if not analytics.has_consent():
            self.toast.show("Turn on 'Record performance measurements' first.", "warning")
            return
        if optimizer.psutil is None:
            self.toast.show("Install psutil first.", "warning")
            return
        prof = optimizer.current_profile()
        label = "baseline" if kind == "baseline" else (prof or "custom")
        self.an_busy, self.an_cancel_ev = True, threading.Event()
        for b in (self.btn_an_base, self.btn_an_now):
            b.set_enabled(False)
        self.btn_an_cancel.set_enabled(True)
        secs, ev = self.an_secs, self.an_cancel_ev

        def tick(i, n, cpu, ram):
            self.msgs.put(("call", lambda: (self.an_meter.set(i / n * 100, T["primary"]),
                                            self.an_status.configure(
                                                text=f"Measuring {self.AN_NAMES.get(label, label)}... {i}/{n} s · "
                                                     f"CPU {cpu:.0f}% · RAM {ram:.0f}%"))))

        def work():
            sess = analytics.measure(label, prof, secs, ev, tick)
            self.msgs.put(("call", lambda: self._an_done(sess, ev.is_set())))
        threading.Thread(target=work, daemon=True).start()

    def _an_cancel(self):
        if self.an_busy:
            self.an_cancel_ev.set()

    def _an_done(self, sess, cancelled):
        self.an_busy = False
        for b in (self.btn_an_base, self.btn_an_now):
            b.set_enabled(True)
        self.btn_an_cancel.set_enabled(False)
        self.an_meter.set(0, T["primary"])
        if sess is None:
            self.an_status.configure(text=f"Cancelled. A run shorter than {analytics.MIN_SECONDS} s is not saved.")
        else:
            self.an_status.configure(text=f"Saved: {sess['duration']:.0f} s, {len(sess['series']['cpu'])} samples.")
            if cancelled:
                self.an_status.configure(text=self.an_status.cget("text") + " (stopped early)")
        self._an_refresh()
        self._refresh_profiles()

    def _an_clear(self):
        if not analytics.sessions():
            self.toast.show("No measurements stored.", "info")
            return
        if messagebox.askyesno("Delete measurements", "Delete all recorded performance measurements? This cannot "
                               "be undone."):
            analytics.clear_sessions()
            self._an_refresh()
            self._refresh_profiles()

    def _an_refresh(self):
        key = self.an_metric
        meta = {k: (lab, unit) for k, lab, unit, _w in analytics.METRICS}
        label, unit = meta[key]
        colors = {"baseline": T["muted"], **self.PROFILE_COLORS, "custom": T["faint"]}
        if key in analytics.UNAVAILABLE:
            items = [{"label": self.AN_NAMES[k], "value": None, "color": colors[k]} for k in self.AN_ORDER[:5]]
            self.an_bars.set(label, unit, items)
            self.an_lines.set(label, unit, [], empty="Not available")
            self.an_detail.configure(text="Not available. " + analytics.UNAVAILABLE[key])
            return
        data = analytics.by_series(key)
        items = []
        for k in self.AN_ORDER:
            if k not in data and k == "custom":
                continue
            e = data.get(k)
            if e is None:
                items.append({"label": self.AN_NAMES[k], "value": None, "color": colors[k],
                              "tip": f"{self.AN_NAMES[k]}: no measurement yet"})
                continue
            last = e["last"]
            items.append({"label": self.AN_NAMES[k], "value": e["mean"], "color": colors[k],
                          "sub": f"{e['count']} run(s)",
                          "tip": (f"{self.AN_NAMES[k]}\nMean: {e['mean']:.1f} {unit}\nSamples: {e['n_total']} over "
                                  f"{e['seconds']:.0f} s\nWithin-run spread (SD): {last['std']:.1f}\n"
                                  f"{analytics.confidence_note(e)}")})
        self.an_bars.set(label, unit, items, note="measured on this PC")
        series = []
        for k in self.AN_ORDER:
            e = data.get(k)
            if not e:
                continue
            pts, tips = [], []
            for s in sorted(e["runs"], key=lambda s: s["time"]):
                m = s["metrics"][key]
                pts.append((s["time"], m["mean"]))
                tips.append(f"{self.AN_NAMES[k]} · {time.strftime('%d %b %H:%M', time.localtime(s['time']))}\n"
                            f"{m['mean']:.1f} {unit} (SD {m['std']:.1f}, {m['n']} samples, {s['duration']:.0f} s)")
            series.append({"name": self.AN_NAMES[k], "color": colors[k], "points": pts, "tips": tips})
        self.an_lines.set(f"{label} over time", unit, series, empty="Not available: no measurements yet")
        lines = []
        conds = set()
        for k in self.AN_ORDER:
            e = data.get(k)
            if e:
                lines.append(f"{self.AN_NAMES[k]}: mean {e['mean']:.1f} {unit} · {e['n_total']} samples over "
                             f"{e['seconds']:.0f} s · {analytics.confidence_note(e)}")
                conds |= {s["conditions"].get("on_ac") for s in e["runs"]}
        if len(conds) > 1:
            lines.append("Note: some runs were plugged in and some on battery. Compare with care.")
        total = len(analytics.sessions())
        other = total - len(analytics.comparable())
        if other:
            lines.append(f"{other} run(s) from different hardware are hidden from this comparison.")
        self.an_detail.configure(text="\n".join(lines) if lines else
                                 "Not available. Record a baseline, then measure each mode, to see results here.")
