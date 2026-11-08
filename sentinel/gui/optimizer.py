"""PC optimizer page: layout, hardware panel, live load."""
from __future__ import annotations

import os
import threading
import time
import tkinter as tk

from .. import hardware, optimizer, ui_kit as ui
from ..ui_kit import T, dp


class OptimizerPage:
    """PC optimizer page: layout, hardware panel, live load."""

    PROFILE_COLORS = {"gaming": T["accent2"], "balanced": T["primary"], "workspace": T["success"],
                      "eco": T["warning"]}
    RISK_LABEL = {"low": "Low", "medium": "Medium", "high": "High"}

    @staticmethod
    def _load_color(pct):
        return T["success"] if pct < 60 else T["warning"] if pct < 85 else T["danger"]

    def _build_optimizer(self):
        page = tk.Frame(self.content, bg=T["bg"])
        self.pages["optimizer"] = page
        sf = ui.ScrollFrame(page)
        self.opt_sf = sf
        sf.pack(fill="both", expand=True)
        body = sf.body

        # ── overview + scan controls ────────────────────────────────────
        top = ui.Card(body, radius=18, pad=16)
        top.pack(fill="x", pady=(0, dp(12)))
        row = tk.Frame(top.inner, bg=T["surface"])
        row.pack(fill="x")
        self.opt_rings = {}
        for key, caption in (("cpu", "CPU"), ("ram", "Memory"), ("disk", "Disk")):
            col = tk.Frame(row, bg=T["surface"])
            col.pack(side="left", padx=(0, dp(18)))
            ring = ui.Ring(col, size=84, thickness=9)
            ring.pack()
            ring.set(0, "--", "", T["primary"])
            self._label(col, caption, 9, color=T["muted"]).pack(pady=(dp(2), 0))
            self.opt_rings[key] = ring
        right = tk.Frame(row, bg=T["surface"])
        right.pack(side="left", fill="x", expand=True, padx=(dp(6), 0))
        self.opt_title = self._label(right, "System overview", 14, True, anchor="w")
        self.opt_title.pack(anchor="w")
        self.opt_sub = self._label(right, "Pick a scan. Scans only read information; nothing is changed until you "
                                   "approve it.", 10, color=T["muted"], justify="left", anchor="w")
        self.opt_sub.pack(anchor="w", fill="x", pady=(dp(4), dp(10)))
        ui.autowrap(self.opt_sub, top, 16 * 2 + 3 * (84 + 18) + 12)
        btns = tk.Frame(right, bg=T["surface"])
        btns.pack(anchor="w", fill="x")
        row1 = tk.Frame(btns, bg=T["surface"])
        row1.pack(anchor="w")
        row2 = tk.Frame(btns, bg=T["surface"])
        self.btn_scan_q = ui.Btn(btns, "Quick scan", command=lambda: self._opt_scan("quick"), icon="search",
                                 height=36, min_width=120)
        self.btn_scan_q.pack(side="left")
        self.btn_scan_s = ui.Btn(btns, "Standard", command=lambda: self._opt_scan("standard"), style="secondary",
                                 height=36)
        self.btn_scan_s.pack(side="left", padx=(dp(8), 0))
        self.btn_scan_d = ui.Btn(btns, "Deep scan", command=lambda: self._opt_scan("deep"), style="secondary",
                                 height=36)
        self.btn_scan_d.pack(side="left", padx=(dp(8), 0))
        self.btn_opt_scan = self.btn_scan_q
        self.btn_opt_cancel = ui.Btn(btns, "Cancel", command=self._opt_cancel, style="ghost", height=36)
        self.btn_opt_cancel.set_enabled(False)
        self.btn_opt_restore = ui.Btn(btns, "Restore", command=self._opt_restore, style="secondary", icon="restore",
                                      height=36)
        for b in (self.btn_scan_q, self.btn_scan_s, self.btn_scan_d, self.btn_opt_cancel, self.btn_opt_restore):
            b.pack(in_=row1, side="left", padx=(0 if b is self.btn_scan_q else dp(8), 0))

        def reflow(_e=None):
            """Keep every button visible: move Cancel/Restore to a second line when the row would clip."""
            need = sum(b.winfo_reqwidth() + dp(8) for b in (self.btn_scan_q, self.btn_scan_s, self.btn_scan_d,
                                                            self.btn_opt_cancel, self.btn_opt_restore))
            wrap = btns.winfo_width() > 20 and need > btns.winfo_width()
            target = row2 if wrap else row1
            if self.btn_opt_cancel.winfo_manager() and self.btn_opt_cancel.pack_info().get("in") is target:
                return
            if wrap:
                row2.pack(anchor="w", pady=(dp(8), 0))
            else:
                row2.pack_forget()
            for i, b in enumerate((self.btn_opt_cancel, self.btn_opt_restore)):
                b.pack_forget()
                b.pack(in_=target, side="left", padx=(0 if (wrap and i == 0) else dp(8), 0))
        btns.bind("<Configure>", reflow)
        self.opt_progress = tk.Frame(right, bg=T["surface"])
        self.opt_chips: dict = {}

        # ── hardware overview ───────────────────────────────────────────
        hw = ui.Card(body, radius=16, pad=14)
        hw.pack(fill="x", pady=(0, dp(12)))
        hh = tk.Frame(hw.inner, bg=T["surface"])
        hh.pack(fill="x")
        self._label(hh, "Your hardware", 12, True).pack(side="left")
        self.hw_note = self._label(hh, "Detecting...", 9, color=T["faint"])
        self.hw_note.pack(side="left", padx=(dp(10), 0))
        grid = tk.Frame(hw.inner, bg=T["surface"])
        grid.pack(fill="x", pady=(dp(8), 0))
        grid.columnconfigure(1, weight=1, uniform="hw")
        grid.columnconfigure(3, weight=1, uniform="hw")
        self.hw_vals: dict = {}

        def hw_wrap(e):
            for lab in self.hw_vals.values():
                lab.configure(wraplength=max(dp(150), e.width // 2 - dp(150)))
        grid.bind("<Configure>", hw_wrap)
        fields = [("Processor", "cpu"), ("Graphics", "gpu"), ("Memory", "ram"), ("Storage", "disk"),
                  ("System", "os"), ("Display / power", "misc")]
        for i, (cap, key) in enumerate(fields):
            r, c = divmod(i, 2)
            self._label(grid, cap, 9, color=T["muted"]).grid(row=r, column=c * 2, sticky="nw", padx=(0, dp(10)),
                                                             pady=dp(3))
            v = self._label(grid, "...", 9, justify="left", anchor="w")
            v.grid(row=r, column=c * 2 + 1, sticky="nw", padx=(0, dp(18)), pady=dp(3))
            self.hw_vals[key] = v
            v.configure(wraplength=dp(240))

        # ── performance modes ───────────────────────────────────────────
        mh = tk.Frame(body, bg=T["bg"])
        mh.pack(fill="x", pady=(0, dp(6)))
        self._label(mh, "Performance mode", 12, True, bg=T["bg"]).pack(side="left")
        self.mode_now = self._label(mh, "", 9, color=T["muted"], bg=T["bg"])
        self.mode_now.pack(side="left", padx=(dp(10), 0))
        prof = tk.Frame(body, bg=T["bg"])
        prof.pack(fill="x", pady=(0, dp(12)))
        self.prof_frame = prof
        for c in range(4):
            prof.columnconfigure(c, weight=1, uniform="prof")
        self.prof_cards, self.prof_metric = {}, {}
        for i, (key, p) in enumerate(optimizer.PROFILES.items()):
            card = ui.Card(prof, radius=16, pad=12)
            card.grid(row=0, column=i, sticky="nsew", padx=(0 if i == 0 else dp(6), 0 if i == 3 else dp(6)))
            head = tk.Frame(card.inner, bg=T["surface"])
            head.pack(fill="x")
            ui.Badge(head, p["icon"], self.PROFILE_COLORS[key], size=32).pack(side="left")
            self._label(head, p["name"].replace(" Mode", ""), 11, True).pack(side="left", padx=(dp(8), 0))
            d = self._label(card.inner, p["short"], 9, color=T["muted"], justify="left", anchor="w")
            d.pack(anchor="w", fill="x", pady=(dp(6), 0))
            ui.autowrap(d, card, 24)
            status = self._label(card.inner, "", 9, True, color=T["muted"], anchor="w")
            status.pack(anchor="w", fill="x", pady=(dp(2), 0))
            metric = self._label(card.inner, "", 8, color=T["faint"], anchor="w", justify="left")
            metric.pack(anchor="w", fill="x")
            ui.autowrap(metric, card, 24)
            ui.bind_click(card, lambda k=key: self._activate_profile(k))
            self.prof_cards[key] = (card, status)
            self.prof_metric[key] = metric

        # ── recommendations accordion ───────────────────────────────────
        rh = tk.Frame(body, bg=T["bg"])
        rh.pack(fill="x", pady=(0, dp(6)))
        self._label(rh, "Recommendations", 12, True, bg=T["bg"]).pack(side="left")
        self.opt_count = self._label(rh, "Run a scan to see recommendations", 9, color=T["faint"], bg=T["bg"])
        self.opt_count.pack(side="left", padx=(dp(10), 0))
        lk = self._label(rh, "Show skipped again", 9, color=T["primary"], bg=T["bg"])
        lk.pack(side="right")
        lk.configure(cursor="hand2")
        lk.bind("<Button-1>", lambda _e: self._opt_unskip())
        self.opt_sections: dict = {}
        self.opt_sig: dict = {}
        for cat in optimizer.CATEGORIES:
            sec = ui.Collapsible(body, cat, "", animate=not self.reduced_motion, on_toggle=None)
            sec.pack(fill="x", pady=dp(3))
            self.opt_sections[cat] = sec
            self.opt_sig[cat] = None
            self._label(sec.body, "Run a scan to check this area.", 9, color=T["faint"]).pack(
                anchor="w", padx=dp(16), pady=dp(10))
        self.opt_report = self._label(body, "", 9, color=T["muted"], justify="left", anchor="w", bg=T["bg"])
        self.opt_report.pack(anchor="w", fill="x", pady=(dp(10), 0))
        ui.autowrap(self.opt_report, body, 10)

        # ── analytics shortcut + recent history ─────────────────────────
        foot = ui.Card(body, radius=16, pad=14)
        foot.pack(fill="x", pady=(dp(12), dp(6)))
        fr = tk.Frame(foot.inner, bg=T["surface"])
        fr.pack(fill="x")
        self._label(fr, "Recent changes", 12, True).pack(side="left")
        ui.Btn(fr, "Performance Analytics", command=lambda: self._show_page("analytics"), style="secondary",
               icon="diagnostic", height=34).pack(side="right")
        self.opt_hist_lbl = self._label(foot.inner, "", 9, color=T["muted"], justify="left", anchor="w")
        self.opt_hist_lbl.pack(anchor="w", fill="x", pady=(dp(6), 0))
        ui.autowrap(self.opt_hist_lbl, foot, 30)
        self._opt_report_default()

    def _opt_report_default(self):
        n = len(self.opt_history.pending())
        self.opt_report.configure(
            text=f"Rollback: {n} change(s) can be restored." if n else "Rollback: no changes made yet.")
        recent = [e for e in self.opt_history.all()][-5:]
        lines = [f"•  {time.strftime('%d %b %H:%M', time.localtime(e['time']))}  {e['title']}"
                 + ("  (restored)" if e.get("restored") else "") for e in reversed(recent)]
        self.opt_hist_lbl.configure(text="\n".join(lines) if lines else "Nothing yet. Changes you approve are listed here.")

    # live gauges -------------------------------------------------------
    def _opt_enter(self):
        ps = optimizer.psutil
        if ps is None:
            self.toast.show("Install psutil (pip install psutil) to see live CPU and memory.", "warning")
            return
        ps.cpu_percent(None)  # prime the counter so the first real reading is meaningful
        self._refresh_profiles()
        self._opt_report_default() if not self.opt_busy else None
        if not self.hw_loaded and not self.hw_loading:
            self.hw_loading = True

            def work():
                prof = hardware.get_profile()
                self.msgs.put(("call", lambda: self._show_hardware(prof)))
            threading.Thread(target=work, daemon=True).start()
        if not self._opt_tick_on:
            self._opt_tick_on = True
            self.after(1200, self._opt_tick)

    def _show_hardware(self, prof):
        self.hw_loaded, self.hw_loading, self.hw_profile = True, False, prof
        c, ram = prof.get("cpu") or {}, prof.get("ram") or {}
        live = hardware.live_status()
        na = "Not available"
        cpu = c.get("name") or na
        if c.get("cores"):
            cpu += f"\n{c['cores']} cores / {c.get('threads') or '?'} threads" + (
                f", up to {c['max_mhz'] / 1000:.1f} GHz" if c.get("max_mhz") else "")
        gpu = "\n".join(
            (g.get("name") or na) + (f" ({hardware.gb(g['vram'])}{'+' if g.get('vram_approx') else ''})"
                                     if g.get("vram") else "") for g in prof.get("gpus") or []) or na
        mem = hardware.gb(ram.get("total"))
        if live.get("ram_available"):
            mem += f"  ({hardware.gb(live['ram_available'])} free)"
        if ram.get("modules"):
            mem += f"\n{ram['modules']} module(s)" + (f", {ram['speed_mhz']} MHz" if ram.get("speed_mhz") else "")
        disks = "\n".join(
            f"{d.get('name') or 'Drive'} · {d.get('type') or 'type unknown'} · "
            f"{hardware.gb(d.get('size'))}" for d in prof.get("disks") or []) or na
        rates = [g["refresh_hz"] for g in prof.get("gpus") or [] if g.get("refresh_hz")]
        form = (prof.get("form_factor") or "form factor unknown").capitalize()
        bat = (f"battery {live['battery_pct']}% ({'plugged in' if live['on_ac'] else 'on battery'})"
               if live.get("battery_pct") is not None else "no battery")
        misc = f"{form}, {bat}\nRefresh rate: {max(rates)} Hz" if rates else f"{form}, {bat}\nRefresh rate: {na}"
        for k, v in (("cpu", cpu), ("gpu", gpu), ("ram", mem), ("disk", disks), ("os", prof.get("os") or na),
                     ("misc", misc)):
            self.hw_vals[k].configure(text=v)
        note = "from saved profile" if prof.get("from_cache") else "freshly detected"
        if prof.get("changed"):
            note = "hardware change detected; profile refreshed"
        self.hw_note.configure(text=f"{note} · stays on this PC")

    def _opt_tick(self):
        if self.current_page != "optimizer":
            self._opt_tick_on = False
            return
        self._opt_live()
        self.after(2000, self._opt_tick)

    def _opt_live(self):
        ps = optimizer.psutil
        if ps is None:
            return
        cpu = ps.cpu_percent(None)
        ram = ps.virtual_memory().percent
        try:
            disk = ps.disk_usage(os.environ.get("SystemDrive", "C:") + "\\").percent
        except OSError:
            disk = 0
        for key, val in (("cpu", cpu), ("ram", ram), ("disk", disk)):
            self.opt_rings[key].set(val, f"{val:.0f}%", "", self._load_color(val))
