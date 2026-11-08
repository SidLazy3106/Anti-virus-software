"""X-Secure desktop app.

A calm "Am I safe?" dashboard: one big protection level, one obvious next step, plain-English wording, and
rounded modern cards. Worker threads push messages onto a queue and the UI thread drains it, so the window
stays responsive during scans and audits. Widgets live in ui_kit.py (sharp HiDPI rendering, cards, buttons...).
"""
from __future__ import annotations

import os
import queue
import threading
import time
import tkinter as tk
from pathlib import Path
from tkinter import filedialog, messagebox, ttk

from . import aa, analytics, config, engine, hardware, mode_art, optimizer, quarantine, schedule, sysaudit, webguard
from . import ui_kit as ui
from .monitor import ProcessWatcher, RealtimeMonitor
from .scanner import MALICIOUS, SUSPICIOUS, Scanner, add_to_allowlist
from .ui_kit import T, dp

TIPS = [
    ("Pause before you click", "Scam links look real. Paste any link you're unsure about into Web guard first."),
    ("Turn on two-step login", "A stolen password is useless without your second step. Start with email and banking."),
    ("Keep Windows updated", "Most attacks use bugs that already have a fix. Install updates when they appear."),
    ("Back up what matters", "Ransomware can lock every file. Keep a copy on a drive that isn't always plugged in."),
    ("Careful on public Wi-Fi", "Avoid banking on café or airport networks, or use a VPN you trust."),
    ("Use a password manager", "A different password for every site stops one breach from becoming ten."),
    ("Doubt surprise attachments", "Invoices or résumés that ask you to 'enable macros' are a classic trick."),
    ("Download from official sites", "Cracked software and key generators are a very common way malware arrives."),
]
VERDICT_LABEL = {MALICIOUS: "Dangerous", SUSPICIOUS: "Suspicious"}
SEVERITY_LABEL = {"high": "High", "medium": "Medium", "low": "Low", "info": "Info"}


def _ago(ts: float) -> str:
    d = time.time() - ts
    if d < 60:
        return "just now"
    if d < 3600:
        return f"{int(d // 60)} min ago"
    if d < 86400:
        return f"{int(d // 3600)} h ago"
    return f"{int(d // 86400)} d ago"


class App(tk.Tk):
    NAV = [("home", "Home", "home"), ("scan", "Scan", "search"), ("realtime", "Real-time shield", "shield"),
           ("quarantine", "Quarantine", "lock"), ("web", "Web guard", "globe"),
           ("audit", "Health check", "diagnostic"), ("optimizer", "PC optimizer", "settings"),
           ("analytics", "Performance Analytics", "health")]
    TITLES = {"home": "Home", "scan": "Scan your PC", "realtime": "Real-time shield", "quarantine": "Quarantine",
              "web": "Web guard", "audit": "Health check", "optimizer": "PC optimizer",
              "analytics": "Performance Analytics"}
    SUBS = {"home": "Your device's security at a glance",
            "scan": "Look for viruses, ransomware and risky files",
            "realtime": "Stay protected while you work",
            "quarantine": "Suspicious files, safely locked away",
            "web": "Paste a link before you click it",
            "audit": "Check your PC's security settings",
            "optimizer": "Find safe ways to free memory and speed up start-up",
            "analytics": "Real measurements of this PC, mode by mode"}

    def __init__(self):
        ui.enable_hidpi()  # must run before the first Tk window exists, or Windows blurs the whole UI
        super().__init__()
        ui.init(self)
        self.title(f"{config.APP_NAME}  -  Antivirus & Security")
        sw, sh = self.winfo_screenwidth(), self.winfo_screenheight()
        w, h = min(dp(1240), sw - dp(60)), min(dp(840), sh - dp(110))
        self.geometry(f"{w}x{h}+{max(0, (sw - w) // 2)}+{max(0, (sh - h) // 2 - dp(24))}")
        self.minsize(min(dp(1040), w), min(dp(700), h))
        self.configure(bg=T["bg"])
        ui.dark_titlebar(self)
        config.ensure_dirs()

        # state
        self.scanner = Scanner()
        self.msgs: queue.Queue = queue.Queue()
        self.cancel = threading.Event()
        self.monitor = None
        self.procwatch = None
        self.results: dict = {}
        self.audit_items: dict = {}
        self.current_page = "home"
        self.rt_active = False
        self.last_score = None
        self.last_scan = None          # {"time", "files", "threats"} of the latest finished scan
        self.threat_count = 0          # threats currently listed in the scan results
        self.scanning = False
        self.scan_started = 0.0
        self.audit_running = False
        self.tip_index = 0
        self._hero_action = lambda: None
        self.opt_history = optimizer.History()
        self.opt_analysis = None
        self.opt_baseline = None
        self.opt_recs: dict = {}
        self.opt_busy = False
        self._opt_tick_on = False
        self.reduced_motion = hardware.reduced_motion()
        self.hw_loaded = self.hw_loading = False
        self.hw_profile = None
        self._mode = None
        self.opt_scan_kind = "standard"
        self.opt_cancel_ev = threading.Event()

        ui.style_ttk(self)
        self.toast = ui.Toast(self)
        self._build_layout()
        self._show_page("home")
        self.after(120, self._drain)
        # warm the 160k-domain blocklist off the UI thread so the first link check does not pause the window
        threading.Thread(target=webguard._bad_domains, daemon=True).start()
        self.after(25000, self._rotate_tip)
        self.protocol("WM_DELETE_WINDOW", self._close)

    # ── small helpers ────────────────────────────────────────────────────
    def _label(self, parent, text="", size=10, bold=False, color=None, **kw):
        kw.setdefault("bg", parent.cget("bg"))
        return tk.Label(parent, text=text, font=ui.font(size, bold), fg=color or T["text"], **kw)

    def _log_box(self, parent, height=8):
        wrap = tk.Frame(parent, bg=parent.cget("bg"))
        t = tk.Text(wrap, height=height, state="disabled", wrap="word", bg=parent.cget("bg"), fg=T["text"],
                    insertbackground=T["text"], font=("Consolas", 10), relief="flat", bd=0, highlightthickness=0,
                    padx=dp(4), pady=dp(4), cursor="arrow", selectbackground=T["surface3"])
        sb = ttk.Scrollbar(wrap, orient="vertical", command=t.yview, style="X.Vertical.TScrollbar")
        t.configure(yscrollcommand=sb.set)
        sb.pack(side="right", fill="y")
        t.pack(side="left", fill="both", expand=True)
        t.tag_configure("muted", foreground=T["faint"])
        t.tag_configure("info", foreground=T["muted"])
        t.tag_configure("warning", foreground=T["warning"])
        t.tag_configure("high", foreground=T["danger"])
        t.tag_configure("critical", foreground=T["danger"], font=("Consolas", 10, "bold"))
        t.tag_configure("ok", foreground=T["success"])
        return wrap, t

    @staticmethod
    def _append(text: tk.Text, line: str, tag=None):
        text.configure(state="normal")
        text.insert("end", line + "\n", tag or ())
        text.see("end")
        text.configure(state="disabled")

    def _table(self, parent, columns, tags):
        """columns: [(name, design-width, stretch)]; tags: {tag: colour}."""
        wrap = tk.Frame(parent, bg=T["surface"])
        tv = ttk.Treeview(wrap, columns=[c[0] for c in columns], show="headings", style="X.Treeview",
                          selectmode="extended")
        for name, width, stretch in columns:
            tv.heading(name, text=name, anchor="w")
            tv.column(name, width=dp(width), minwidth=dp(50), stretch=stretch, anchor="w")
        sb = ttk.Scrollbar(wrap, orient="vertical", command=tv.yview, style="X.Vertical.TScrollbar")
        tv.configure(yscrollcommand=sb.set)
        sb.pack(side="right", fill="y")
        tv.pack(side="left", fill="both", expand=True)
        for tag, colour in tags.items():
            tv.tag_configure(tag, foreground=colour)
        return wrap, tv

    def _set_pill(self, text, color):
        self.status_pill.set(text, color)

    # ── shell ────────────────────────────────────────────────────────────
    def _build_layout(self):
        sb = tk.Frame(self, bg=T["sidebar"], width=dp(248))
        sb.pack(side="left", fill="y")
        sb.pack_propagate(False)

        brand = tk.Frame(sb, bg=T["sidebar"])
        brand.pack(fill="x", padx=dp(22), pady=(dp(28), dp(26)))
        ui.Badge(brand, "shield", T["primary"], size=44).pack(side="left")
        names = tk.Frame(brand, bg=T["sidebar"])
        names.pack(side="left", padx=(dp(12), 0))
        self._label(names, "X-Secure", 16, True).pack(anchor="w")
        self._label(names, "Stay safe online", 9, color=T["faint"]).pack(anchor="w")

        self.nav = {}
        for key, label, glyph in self.NAV:
            item = ui.NavItem(sb, label, glyph, lambda k=key: self._show_page(k))
            item.pack(fill="x", padx=dp(14), pady=dp(2))
            self.nav[key] = item

        foot = tk.Frame(sb, bg=T["sidebar"])
        foot.pack(side="bottom", fill="x", padx=dp(22), pady=(0, dp(22)))
        row = tk.Frame(foot, bg=T["sidebar"])
        row.pack(anchor="w")
        self.side_dot = tk.Canvas(row, width=dp(10), height=dp(10), bg=T["sidebar"], highlightthickness=0)
        self.side_dot.pack(side="left", padx=(0, dp(8)))
        self.side_status = self._label(row, "Real-time shield: off", 9, color=T["muted"])
        self.side_status.pack(side="left")
        self._label(foot, f"Version {config.VERSION}", 8, color=T["faint"]).pack(anchor="w", pady=(dp(6), 0))
        self._update_side()

        self.main = tk.Frame(self, bg=T["bg"])
        self.main.pack(side="left", fill="both", expand=True)

        head = tk.Frame(self.main, bg=T["bg"])
        head.pack(fill="x", padx=dp(34), pady=(dp(22), dp(4)))
        titles = tk.Frame(head, bg=T["bg"])
        titles.pack(side="left")
        self.page_title = self._label(titles, "Home", 22, True)
        self.page_title.pack(anchor="w")
        self.page_sub = self._label(titles, "", 10, color=T["muted"])
        self.page_sub.pack(anchor="w", pady=(dp(2), 0))
        self.status_pill = ui.Pill(head)
        self.status_pill.pack(side="right", anchor="n")

        self.content = tk.Frame(self.main, bg=T["bg"])
        self.content.pack(fill="both", expand=True, padx=dp(34), pady=(dp(10), dp(22)))

        self.pages: dict[str, tk.Frame] = {}
        self._build_home()
        self._build_scan()
        self._build_realtime()
        self._build_quarantine()
        self._build_web()
        self._build_audit()
        self._build_optimizer()
        self._build_analytics()

    def _update_side(self):
        self.side_dot.delete("all")
        color = T["success"] if self.rt_active else T["faint"]
        ui.oval(self.side_dot, 1, 1, dp(9), dp(9), fill=color)
        self.side_status.configure(text="Real-time shield: on" if self.rt_active else "Real-time shield: off")

    def _show_page(self, key: str):
        self.current_page = key
        self.page_title.configure(text=self.TITLES[key])
        self.page_sub.configure(text=self.SUBS[key])
        for k, item in self.nav.items():
            item.set_active(k == key)
        for k, page in self.pages.items():
            if k == key:
                page.pack(fill="both", expand=True)
            else:
                page.pack_forget()
        if key == "quarantine":
            self._refresh_q()
        if key == "home":
            self._refresh_home()
        if key == "optimizer":
            self._opt_enter()
        if key == "analytics":
            self._an_enter()

    # ═════════════════════════════════════════════════════════════════════
    # HOME
    # ═════════════════════════════════════════════════════════════════════
    def _build_home(self):
        page = tk.Frame(self.content, bg=T["bg"])
        self.pages["home"] = page

        hero = ui.Card(page, radius=22, pad=22)
        hero.pack(fill="x", pady=(0, dp(14)))
        h = hero.inner
        self.ring = ui.Ring(h, size=150, thickness=13)
        self.ring.pack(side="left", padx=(0, dp(30)))
        right = tk.Frame(h, bg=T["surface"])
        right.pack(side="left", fill="x", expand=True)
        self.hero_title = self._label(right, "", 22, True, anchor="w")
        self.hero_title.pack(anchor="w")
        self.hero_sub = self._label(right, "", 11, color=T["muted"], justify="left", anchor="w")
        self.hero_sub.pack(anchor="w", fill="x", pady=(dp(6), dp(16)))
        ui.autowrap(self.hero_sub, hero, 22 * 2 + 150 + 30 + 8)
        btns = tk.Frame(right, bg=T["surface"])
        btns.pack(anchor="w")
        self.hero_btn = ui.Btn(btns, "Scan now", command=lambda: self._hero_action(), icon="search", min_width=150)
        self.hero_btn.pack(side="left")
        ui.Btn(btns, "Health check", command=self._go_audit, style="secondary", icon="diagnostic").pack(
            side="left", padx=(dp(10), 0))

        tiles = tk.Frame(page, bg=T["bg"])
        tiles.pack(fill="x", pady=(0, dp(14)))
        for c in range(4):
            tiles.columnconfigure(c, weight=1, uniform="tile")
        self.tile = {}
        defs = [("scan", "search", "Virus & malware", T["primary"], "scan"),
                ("rt", "shield", "Real-time shield", T["accent2"], "realtime"),
                ("web", "globe", "Web protection", T["success"], "web"),
                ("audit", "diagnostic", "System health", T["warning"], "audit")]
        for i, (key, glyph, title, color, target) in enumerate(defs):
            card = ui.Card(tiles, radius=18, pad=14)
            card.grid(row=0, column=i, sticky="nsew", padx=(0 if i == 0 else dp(7), 0 if i == 3 else dp(7)))
            inner = card.inner
            ui.Badge(inner, glyph, color, size=38).pack(anchor="w")
            self._label(inner, title, 11, True).pack(anchor="w", pady=(dp(8), 0))
            status = self._label(inner, "", 10, True, color=color)
            status.pack(anchor="w", pady=(dp(2), 0))
            hint = self._label(inner, "", 9, color=T["muted"], justify="left", anchor="w")
            hint.pack(anchor="w", fill="x", pady=(dp(2), 0))
            ui.autowrap(hint, card, 32)
            self.tile[key] = (status, hint)
            ui.bind_click(card, lambda t=target: self._show_page(t))

        bottom = tk.Frame(page, bg=T["bg"])
        bottom.pack(fill="both", expand=True)
        bottom.columnconfigure(0, weight=3, uniform="b")
        bottom.columnconfigure(1, weight=2, uniform="b")
        bottom.rowconfigure(0, weight=1)

        act = ui.Card(bottom, radius=18, pad=16, auto_height=False)
        act.configure(height=dp(190))
        act.grid(row=0, column=0, sticky="nsew", padx=(0, dp(8)))
        self._label(act.inner, "Recent activity", 12, True).pack(anchor="w", pady=(0, dp(6)))
        fr, self.alert_log = self._log_box(act.inner, height=5)
        fr.pack(fill="both", expand=True)
        self._append(self.alert_log, "Nothing to report yet. Run a scan or turn on the real-time shield.", "muted")

        tipc = ui.Card(bottom, radius=18, pad=16, auto_height=False)
        tipc.grid(row=0, column=1, sticky="nsew", padx=(dp(8), 0))
        top = tk.Frame(tipc.inner, bg=T["surface"])
        top.pack(fill="x")
        ui.Badge(top, "bulb", T["warning"], size=30).pack(side="left")
        self._label(top, "Stay safe tip", 12, True).pack(side="left", padx=(dp(10), 0))
        ui.Btn(top, "Next", command=self._next_tip, style="ghost", icon="next", height=30, size=9, padx=12).pack(
            side="right")
        self.tip_title = self._label(tipc.inner, "", 13, True, anchor="w", justify="left")
        self.tip_title.pack(anchor="w", fill="x", pady=(dp(10), dp(4)))
        self.tip_body = self._label(tipc.inner, "", 10, color=T["muted"], anchor="w", justify="left")
        self.tip_body.pack(anchor="w", fill="x")
        ui.autowrap(self.tip_body, tipc, 32)
        self._show_tip()

    def _show_tip(self):
        title, body = TIPS[self.tip_index % len(TIPS)]
        self.tip_title.configure(text=title)
        self.tip_body.configure(text=body)

    def _next_tip(self):
        self.tip_index += 1
        self._show_tip()

    def _rotate_tip(self):
        if self.current_page == "home":
            self._next_tip()
        self.after(25000, self._rotate_tip)

    def _go_scan(self):
        self._show_page("scan")

    def _go_audit(self):
        self._show_page("audit")
        self._run_audit()

    def _quick_scan_nav(self):
        self._set_scan_mode("quick")
        self._show_page("scan")
        self._start_scan()

    def _protection_level(self) -> int:
        lvl = 20
        if self.rt_active:
            lvl += 30
        if self.last_scan and time.time() - self.last_scan["time"] < 7 * 86400:
            lvl += 20
        if self.last_score is not None:
            lvl += round(30 * self.last_score / 100)
        if self.threat_count:
            lvl -= 30
        return max(5, min(100, lvl))

    def _next_step(self):
        """(title, sub, button text, button icon, action, colour) for the hero card."""
        if self.threat_count:
            n = self.threat_count
            return ("Action needed", f"{n} threat{'s' if n != 1 else ''} found. Review and remove "
                    f"{'them' if n != 1 else 'it'} now.", "Review threats", "alert", self._go_scan, T["danger"])
        if not self.last_scan:
            return ("Run your first scan", "Check your PC for hidden threats. A quick scan takes only a few minutes.",
                    "Scan now", "search", self._quick_scan_nav, T["warning"])
        if not self.rt_active:
            return ("Turn on the real-time shield", "Catch threats the moment they appear, not after the damage.",
                    "Turn it on", "shield", lambda: self._show_page("realtime"), T["warning"])
        if self.last_score is None:
            return ("Check your PC's health", "See if Windows settings like the firewall and updates are safe.",
                    "Health check", "diagnostic", self._go_audit, T["primary"])
        return ("You're protected", "Everything looks good. Keep Windows updated and scan now and then.",
                "Scan now", "search", self._quick_scan_nav, T["success"])

    def _refresh_home(self):
        title, sub, btn, glyph, action, color = self._next_step()
        lvl = self._protection_level()
        self.ring.set(lvl, f"{lvl}", "protection level", color)
        self.hero_title.configure(text=title)
        self.hero_sub.configure(text=sub)
        self.hero_btn.set_look("danger" if color == T["danger"] else "primary", glyph)
        self.hero_btn.set_text(btn)
        self.hero_btn.set_command(action)
        self._hero_action = action

        qn = len(quarantine.list_items())
        s, hnt = self.tile["scan"]
        if self.last_scan:
            s.configure(text=f"{self.threat_count} threat(s)" if self.threat_count else "No threats",
                        fg=T["danger"] if self.threat_count else T["success"])
            hnt.configure(text=f"Last scan {_ago(self.last_scan['time'])} · {qn} in quarantine")
        else:
            s.configure(text="Not scanned yet", fg=T["warning"])
            hnt.configure(text=f"{qn} in quarantine")
        s, hnt = self.tile["rt"]
        s.configure(text="Active" if self.rt_active else "Off", fg=T["success"] if self.rt_active else T["warning"])
        hnt.configure(text="Watching your folders live" if self.rt_active else "Tap to turn on live protection")
        s, hnt = self.tile["web"]
        s.configure(text="Ready", fg=T["success"])
        hnt.configure(text="Check any link before you click")
        s, hnt = self.tile["audit"]
        if self.last_score is None:
            s.configure(text="Not checked", fg=T["warning"])
            hnt.configure(text="Run a health check")
        else:
            s.configure(text=f"{self.last_score} / 100",
                        fg=T["success"] if self.last_score >= 80 else T["warning"] if self.last_score >= 50
                        else T["danger"])
            hnt.configure(text="Your latest security score")
        if not self.scanning:
            if self.threat_count:
                self._set_pill("Action needed", T["danger"])
            elif self.rt_active:
                self._set_pill("Protected", T["success"])
            else:
                self._set_pill("Limited protection", T["warning"])

    # ═════════════════════════════════════════════════════════════════════
    # SCAN
    # ═════════════════════════════════════════════════════════════════════
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
            extra = f" · last automatic run {_ago(last['time'])}: {last['files']:,} files, {last['threats']} flagged"
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

    # ═════════════════════════════════════════════════════════════════════
    # REAL-TIME
    # ═════════════════════════════════════════════════════════════════════
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

    # ═════════════════════════════════════════════════════════════════════
    # QUARANTINE
    # ═════════════════════════════════════════════════════════════════════
    def _build_quarantine(self):
        page = tk.Frame(self.content, bg=T["bg"])
        self.pages["quarantine"] = page

        info = ui.Card(page, radius=16, pad=16)
        info.pack(fill="x", pady=(0, dp(12)))
        row = tk.Frame(info.inner, bg=T["surface"])
        row.pack(fill="x")
        ui.Badge(row, "lock", T["primary"], size=40).pack(side="left")
        d = self._label(row, "Quarantined files are moved out of reach and encrypted so they can't run. You can "
                        "restore a file if it was a false alarm, or delete it for good.", 10, color=T["muted"],
                        justify="left", anchor="w")
        d.pack(side="left", fill="x", expand=True, padx=(dp(14), 0))
        ui.autowrap(d, info, 16 * 2 + 40 + 14 + 8)

        bar = tk.Frame(page, bg=T["bg"])
        bar.pack(fill="x", pady=(0, dp(10)))
        ui.Btn(bar, "Refresh", command=self._refresh_q, style="secondary", icon="refresh").pack(side="left")
        ui.Btn(bar, "Restore selected", command=self._restore_q, style="success", icon="restore").pack(
            side="left", padx=(dp(10), 0))
        ui.Btn(bar, "Delete permanently", command=self._delete_q, style="danger", icon="delete").pack(
            side="left", padx=(dp(10), 0))

        card = ui.Card(page, radius=16, pad=10, auto_height=False)
        card.configure(height=dp(240))
        card.pack(fill="both", expand=True)
        wrap, self.q_tv = self._table(card.inner, [("Original location", 430, True), ("Why", 330, True),
                                                   ("Locked away", 130, False)], {})
        wrap.pack(fill="both", expand=True)
        self.q_empty = self._label(wrap, "Nothing in quarantine.\nThreats you lock away will appear here.", 11,
                                   color=T["muted"], justify="center")

    def _refresh_q(self):
        self.q_tv.delete(*self.q_tv.get_children())
        items = quarantine.list_items()
        for it in items:
            self.q_tv.insert("", "end", iid=it["id"],
                             values=(it["original_path"], it["reason"], _ago(it["time"])))
        if items:
            self.q_empty.place_forget()
        else:
            self.q_empty.place(relx=0.5, rely=0.5, anchor="center")
        self._refresh_home()

    def _restore_q(self):
        sel = self.q_tv.selection()
        if not sel:
            self.toast.show("Select one or more items first.", "info")
            return
        if messagebox.askyesno("Restore", "Restore the selected file(s)?\nThey may still be malicious."):
            for qid in sel:
                try:
                    quarantine.restore(qid)
                except Exception as e:
                    messagebox.showerror("Restore", str(e))
            self._refresh_q()
            self.toast.show("File(s) restored.", "warning")

    def _delete_q(self):
        sel = self.q_tv.selection()
        if not sel:
            self.toast.show("Select one or more items first.", "info")
            return
        if messagebox.askyesno("Delete", "Permanently delete the selected file(s)?"):
            for qid in sel:
                try:
                    quarantine.delete(qid)
                except Exception as e:
                    messagebox.showerror("Delete", str(e))
            self._refresh_q()
            self.toast.show("File(s) deleted.", "success")

    # ═════════════════════════════════════════════════════════════════════
    # WEB GUARD
    # ═════════════════════════════════════════════════════════════════════
    VERDICTS = {"clean": ("Looks safe", "No warning signs found. Still, only enter passwords on sites you trust.",
                          T["success"], "check"),
                "suspicious": ("Be careful", "This link has warning signs. Don't enter passwords or payment details.",
                               T["warning"], "warn"),
                "malicious": ("Dangerous, don't open it", "This link matches known scam or malware patterns. "
                              "Close it and don't sign in.", T["danger"], "block")}

    def _build_web(self):
        page = tk.Frame(self.content, bg=T["bg"])
        self.pages["web"] = page

        bar = tk.Frame(page, bg=T["bg"])
        bar.pack(fill="x", pady=(0, dp(10)))
        bar.columnconfigure(0, weight=1)
        self.url_var = tk.StringVar()
        ui.Field(bar, self.url_var, icon_name="link", size=12, on_return=self._check_url).grid(
            row=0, column=0, sticky="ew")
        ui.Btn(bar, "Check link", command=self._check_url, icon="search", min_width=140).grid(
            row=0, column=1, padx=(dp(10), 0))

        chips = tk.Frame(page, bg=T["bg"])
        chips.pack(fill="x", pady=(0, dp(14)))
        self._label(chips, "Try:", 9, color=T["faint"]).pack(side="left", padx=(dp(4), dp(6)))
        for ex in ("paypa1-secure-login.xyz/verify", "https://github.com/login", "http://185.1.2.3/login"):
            ui.Btn(chips, ex, command=lambda e=ex: (self.url_var.set(e), self._check_url()), style="ghost",
                   height=30, size=9, padx=12).pack(side="left", padx=(0, dp(6)))

        card = ui.Card(page, radius=20, pad=26)
        card.pack(fill="x")
        row = tk.Frame(card.inner, bg=T["surface"])
        row.pack(fill="x")
        self.url_badge = ui.Badge(row, "globe", T["primary"], size=64)
        self.url_badge.pack(side="left")
        col = tk.Frame(row, bg=T["surface"])
        col.pack(side="left", fill="x", expand=True, padx=(dp(20), 0))
        self.url_verdict = self._label(col, "Paste a link to check it", 18, True, anchor="w")
        self.url_verdict.pack(anchor="w")
        self.url_advice = self._label(col, "We look for look-alike names, hidden addresses, risky endings and other "
                                      "tricks used in scams.", 10, color=T["muted"], justify="left", anchor="w")
        self.url_advice.pack(anchor="w", fill="x", pady=(dp(4), 0))
        ui.autowrap(self.url_advice, card, 26 * 2 + 64 + 20 + 8)
        self.url_meter = ui.Meter(card.inner)
        self.url_meter.pack(fill="x", pady=(dp(20), dp(4)))
        self.url_score = self._label(card.inner, "", 9, color=T["faint"], anchor="w")
        self.url_score.pack(anchor="w", fill="x")
        self.url_reasons = self._label(card.inner, "", 10, justify="left", anchor="w")
        self.url_reasons.pack(anchor="w", fill="x", pady=(dp(12), 0))
        ui.autowrap(self.url_reasons, card, 26 * 2 + 8)

    def _check_url(self):
        url = self.url_var.get().strip()
        if not url:
            self.toast.show("Paste a link first.", "info")
            return
        v = webguard.analyze_url(url)
        title, advice, color, glyph = self.VERDICTS.get(v.verdict, self.VERDICTS["suspicious"])
        self.url_badge.update_badge(glyph, color)
        self.url_verdict.configure(text=title, fg=color)
        self.url_advice.configure(text=advice)
        self.url_meter.set(v.score, color)
        self.url_score.configure(text=f"Risk score {v.score} / 100")
        self.url_reasons.configure(text="\n".join(f"•  {r}" for r in v.reasons)
                                   or "•  No risk signals found")

    # ═════════════════════════════════════════════════════════════════════
    # HEALTH CHECK (system audit)
    # ═════════════════════════════════════════════════════════════════════
    def _build_audit(self):
        page = tk.Frame(self.content, bg=T["bg"])
        self.pages["audit"] = page

        top = ui.Card(page, radius=20, pad=22)
        top.pack(fill="x", pady=(0, dp(14)))
        row = tk.Frame(top.inner, bg=T["surface"])
        row.pack(fill="x")
        self.audit_ring = ui.Ring(row, size=130, thickness=12)
        self.audit_ring.pack(side="left")
        self.audit_ring.set(0, "--", "out of 100", T["primary"])
        col = tk.Frame(row, bg=T["surface"])
        col.pack(side="left", fill="x", expand=True, padx=dp(24))
        self.audit_title = self._label(col, "Check your PC's health", 16, True, anchor="w")
        self.audit_title.pack(anchor="w")
        self.audit_status = self._label(col, "We'll review the firewall, Defender, startup programs, scheduled "
                                        "tasks, network exposure and more. It only reads settings, it changes "
                                        "nothing.", 10, color=T["muted"], justify="left", anchor="w")
        self.audit_status.pack(anchor="w", fill="x", pady=(dp(4), 0))
        ui.autowrap(self.audit_status, top, 22 * 2 + 130 + 48 + 190 + 8)
        self.audit_btn = ui.Btn(row, "Run health check", command=self._run_audit, icon="diagnostic", min_width=170)
        self.audit_btn.pack(side="right")

        res = ui.Card(page, radius=16, pad=16, auto_height=False)
        res.configure(height=dp(240))
        res.pack(fill="both", expand=True)
        self._label(res.inner, "Findings", 12, True).pack(anchor="w", pady=(0, dp(8)))
        self.audit_detail = self._label(res.inner, "", 9, color=T["muted"], justify="left", anchor="w")
        self.audit_detail.pack(side="bottom", anchor="w", fill="x", pady=(dp(8), 0))
        ui.autowrap(self.audit_detail, res, 34)
        wrap, self.audit_tv = self._table(res.inner, [("Importance", 100, False), ("Area", 110, False),
                                                      ("What we found", 440, True), ("How to fix it", 360, True)],
                                          {"high": T["danger"], "medium": T["warning"], "low": T["primary"],
                                           "info": T["muted"]})
        wrap.pack(fill="both", expand=True)
        self.audit_empty = self._label(wrap, "Run a health check to see findings here.", 11, color=T["muted"])
        self.audit_empty.place(relx=0.5, rely=0.5, anchor="center")
        self.audit_tv.bind("<<TreeviewSelect>>", self._on_pick_finding)

    def _on_pick_finding(self, _e=None):
        sel = self.audit_tv.selection()
        fd = self.audit_items.get(sel[0]) if sel else None
        parts = [p for p in (fd.detail, f"Fix: {fd.fix}" if fd.fix else "") if p] if fd else []
        self.audit_detail.configure(text="   •   ".join(parts))

    def _run_audit(self):
        if self.audit_running:
            return
        self.audit_running = True
        self.audit_btn.set_enabled(False)
        self.audit_ring.set(0, "...", "checking", T["primary"])
        self.audit_title.configure(text="Checking your PC...")
        self._set_pill("Checking", T["warning"])
        threading.Thread(target=lambda: self.msgs.put(("audit", sysaudit.run_audit())), daemon=True).start()

    # ═════════════════════════════════════════════════════════════════════
    # PC OPTIMIZER
    # ═════════════════════════════════════════════════════════════════════
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

    # profiles ----------------------------------------------------------
    def _refresh_profiles(self):
        plans = optimizer.available_plans()
        cur = optimizer.current_profile()
        for key, (card, status) in self.prof_cards.items():
            ok, _why = optimizer.profile_support(key, plans)
            if key == cur:
                status.configure(text="Active", fg=T["success"])
                card.set_border(T["primary"], 2)
            elif not ok:
                status.configure(text="Not supported on this PC", fg=T["faint"])
                card.set_border(T["border"], 1)
            else:
                status.configure(text="Click to activate", fg=T["muted"])
                card.set_border(T["border"], 1)
        self.mode_now.configure(text=f"Active: {optimizer.PROFILES[cur]['name']}" if cur else "Active: custom power plan")
        measured = analytics.by_series("cpu_avg")
        for key, lab in self.prof_metric.items():
            best = measured.get(key)
            lab.configure(text=f"Measured CPU avg {best['mean']:.0f}% ({best['count']} run(s))" if best
                          else "No measurements yet")

    def _activate_profile(self, key):
        p = optimizer.PROFILES[key]
        ok, why = optimizer.profile_support(key)
        if not ok:
            self.toast.show(f"{p['name']} isn't available. {why}", "warning", 6500)
            return
        if self._mode is not None:
            return
        cur = optimizer.current_profile()
        if cur == key:
            self.toast.show(f"{p['name']} is already active.", "info")
            return
        plan = optimizer.active_plan()[1]
        live = hardware.live_status()
        warn = ""
        if key == "gaming" and live.get("on_ac") is False:
            warn = "\n\nYou're on battery. Gaming Mode will drain it faster and run warmer."
        msg = (f"{p['name']}\n\nCurrent setting: {optimizer.PROFILES[cur]['name'] if cur else 'custom'} "
               f"(power plan: {plan})\nWhat changes: {p['applies']}\nSide effects: {p['side_effects']}\n"
               f"Not changed: {p['not_automated']}{warn}\n\nYou can undo this with 'Restore previous settings'.\n\n"
               f"Continue?")
        if not messagebox.askyesno("Activate profile", msg):
            return
        if self.reduced_motion:
            self._mode = {"key": key, "plain": True}
            self._mode_apply_thread(key)
        else:
            self._mode_animate(key)

    # animated mode switch ----------------------------------------------
    EXPAND_MS, GRAPH_MS, SHRINK_MS = 300, mode_art.CONCEPT_MS, 300

    def _mode_apply_thread(self, key):
        def work():
            res = optimizer.apply_profile(key, self.opt_history)
            verified = bool(res.ok and optimizer.current_profile() == key)
            self.msgs.put(("call", lambda: self._mode_result(key, res, verified)))
        threading.Thread(target=work, daemon=True).start()

    def _mode_result(self, key, res, verified):
        m = self._mode
        name = optimizer.PROFILES[key]["name"]
        ok = res.ok and verified
        if m is not None:
            m["result"] = (ok, f"{name} is active. Verified with Windows." if ok else
                           (res.message if not res.ok else "Windows did not confirm the change.")
                           + " Your previous settings were kept.")
        if m is None or m.get("plain"):
            self._mode = None
            self.toast.show(m["result"][1] if m else res.message, "success" if ok else "danger")
        self._refresh_profiles()
        self._opt_report_default()

    def _mode_animate(self, key):
        card = self.prof_cards[key][0]
        self.update_idletasks()
        cx, cy = card.winfo_rootx() - self.content.winfo_rootx(), card.winfo_rooty() - self.content.winfo_rooty()
        cw, ch = card.winfo_width(), card.winfo_height()
        W, H = self.content.winfo_width(), self.content.winfo_height()
        tw, th = min(dp(640), W - dp(40)), min(dp(340), H - dp(40))
        cv = tk.Canvas(self.content, bg=T["surface"], highlightthickness=0, bd=0)
        cv.place(x=cx, y=cy, width=cw, height=ch)
        tk.Misc.lift(cv)
        self._mode = {"key": key, "cv": cv, "t0": time.perf_counter(), "src": (cx, cy, cw, ch),
                      "dst": ((W - tw) // 2, (H - th) // 2, tw, th), "phase": "expand", "cancel": False, "result": None, "applied": False,
                      "hold_until": 0.0, "shrink_t0": None}
        cv.bind("<Button-1>", self._mode_click)
        self.bind("<Escape>", lambda _e: self._mode_cancel())
        self._mode_step()

    def _mode_click(self, e):
        m = self._mode
        if m and m["phase"] in ("expand", "graph") and e.x > m["cv"].winfo_width() - dp(110) and e.y < dp(44):
            self._mode_cancel()

    def _mode_cancel(self):
        m = self._mode
        if m and m["phase"] in ("expand", "graph") and not m["applied"]:
            m["cancel"] = True

    def _mode_step(self):
        m = self._mode
        if m is None:
            return
        now = time.perf_counter()
        t = (now - m["t0"]) * 1000
        cv, key = m["cv"], m["key"]
        sx, sy, sw, sh = m["src"]
        dx, dy, dw, dh = m["dst"]

        def geom(f):
            f = ui.ease(f)
            return (int(sx + (dx - sx) * f), int(sy + (dy - sy) * f), int(sw + (dw - sw) * f),
                    int(sh + (dh - sh) * f))
        phase = m["phase"]
        if m["cancel"] and phase in ("expand", "graph"):
            m["phase"], m["shrink_t0"], m["result"] = "shrink", now, (None, "Cancelled. Nothing was changed.")
            m["from_f"] = min(1.0, t / self.EXPAND_MS)
            phase = "shrink"
        if phase == "expand":
            f = t / self.EXPAND_MS
            x, y, w, h = geom(f)
            cv.place(x=x, y=y, width=w, height=h)
            if f >= 1:
                m["phase"], m["g0"] = "graph", now
        elif phase == "graph":
            g = (now - m["g0"]) * 1000
            if g >= self.GRAPH_MS:
                m["phase"] = "apply"
                self._mode_apply_thread(key)
        elif phase == "apply":
            m["applied"] = True
            if m["result"] is not None:
                m["phase"], m["hold_until"] = "result", now + (0.9 if m["result"][0] else 2.2)
        elif phase == "result":
            if now >= m["hold_until"]:
                m["phase"], m["shrink_t0"], m["from_f"] = "shrink", now, 1.0
        elif phase == "shrink":
            f = m["from_f"] * (1 - (now - m["shrink_t0"]) * 1000 / self.SHRINK_MS)
            if f <= 0:
                cv.destroy()
                self.unbind("<Escape>")
                res = m["result"]
                self._mode = None
                if res:
                    self.toast.show(res[1], "success" if res[0] else "warning" if res[0] is None else "danger")
                self._refresh_profiles()
                self._opt_report_default()
                return
            x, y, w, h = geom(f)
            cv.place(x=x, y=y, width=w, height=h)
        try:
            self._mode_draw(m, now)
        except tk.TclError:
            pass      # window closing
        except Exception:      # a drawing bug must never leave the overlay stuck on screen
            from . import logger
            logger.get().exception('mode animation draw failed')
        self.after(16 if m["phase"] != "apply" else 40, self._mode_step)

    def _mode_draw(self, m, now):
        cv, key = m["cv"], m["key"]
        pi = cv.place_info()                                # the size we just set; avoids a forced layout pass
        w, h = int(pi.get("width") or cv.winfo_width()), int(pi.get("height") or cv.winfo_height())
        color = self.PROFILE_COLORS[key]
        if m.get("bg_size") != (w, h):                     # card + glow only change when the size changes
            cv.delete("bg")
            if aa.available():                              # one composited image: glow rings + card
                img = aa.Image.new("RGBA", (w, h), (0, 0, 0, 0))
                for i, a in enumerate((0.10, 0.18, 0.30)):  # subtle glow
                    img.alpha_composite(aa.rrect_image(w - i * 4, h - i * 4, dp(18), None,
                                                       ui.mix(color, T["surface"], a), 2), (i * 2, i * 2))
                img.alpha_composite(aa.rrect_image(w - dp(6), h - dp(6), dp(16), T["surface"], color, 2),
                                    (dp(3), dp(3)))
                aa.put(cv, 0, 0, img, "bg")
            else:
                for i, a in enumerate((0.10, 0.18, 0.30)):
                    ui.round_rect(cv, i * 2, i * 2, w - i * 2, h - i * 2, dp(18),
                                  outline=ui.mix(color, T["surface"], a), fill="", width=2, tags="bg")
                ui.round_rect(cv, dp(3), dp(3), w - dp(3), h - dp(3), dp(16), fill=T["surface"], outline=color,
                              width=2, tags="bg")
            cv.tag_lower("bg")
            m["bg_size"] = (w, h)
        cv.delete("dyn")
        before = set(cv.find_all())
        name = optimizer.PROFILES[key]["name"]
        big = m["phase"] != "expand" or (now - m["t0"]) * 1000 > self.EXPAND_MS * 0.5
        cv.create_text(dp(20), dp(24), text=name, anchor="w", font=ui.font(16 if big else 11, True), fill=T["text"])
        if m["phase"] in ("expand", "graph") and not m["applied"] and w > dp(300):
            cv.create_text(w - dp(16), dp(24), text="Cancel  (Esc)", anchor="e", font=ui.font(9), fill=T["muted"])
        if m["phase"] in ("expand", "shrink") or h < dp(200):   # only the card moves; skip the graph
            self._mode_tag_dyn(cv, before)
            return
        # conceptual illustration (NOT measurements); see mode_art.py
        cv.create_text(dp(20), dp(48), text=mode_art.TITLES[key], anchor="w", font=ui.font(10), fill=T["muted"])
        prog = 1.0 if m["phase"] != "graph" else min(1.0, (now - m["g0"]) * 1000 / self.GRAPH_MS)
        box = (dp(28), dp(76), w - dp(28), h - dp(150))
        if box[3] - box[1] > dp(40):
            mode_art.draw(cv, key, box, prog)
        cv.create_text(dp(20), h - dp(96), text=mode_art.CAPTIONS[key], anchor="w", font=ui.font(9), fill=T["text"])
        cv.create_text(dp(20), h - dp(14), anchor="sw", font=ui.font(8), fill=T["faint"], width=w - dp(40),
                       text=mode_art.DISCLAIMERS[key])
        if m["phase"] in ("apply", "result"):
            r = m["result"]
            if r is None:
                dots = "." * (1 + int(now * 3) % 3)
                msg, col = f"Applying and verifying{dots}", T["warning"]
            else:
                msg, col = r[1], (T["success"] if r[0] else T["danger"])
            cv.create_rectangle(dp(10), h - dp(70), w - dp(10), h - dp(34), fill=T["surface"], outline=T["surface"])
            tx = dp(20)
            if r is not None and ui.ICON_FONT:               # status glyph from the icon font (no font fallback)
                cv.create_text(tx, h - dp(52), text=ui.icon("check" if r[0] else "block"), anchor="w",
                               font=(ui.ICON_FONT, 12), fill=col)
                tx += dp(26)
            elif r is not None:
                msg = ("OK  " if r[0] else "Failed  ") + msg
            cv.create_text(tx, h - dp(52), text=msg, anchor="w", font=ui.font(11, True), fill=col,
                           width=w - tx - dp(20))
        self._mode_tag_dyn(cv, before)

    @staticmethod
    def _mode_tag_dyn(cv, before):
        for item in set(cv.find_all()) - before:
            cv.addtag_withtag("dyn", item)

    # scan --------------------------------------------------------------
    def _opt_scan(self, kind="standard"):
        if self.opt_busy:
            self.toast.show("A scan is already running.", "info")
            return
        if optimizer.psutil is None:
            self.toast.show("Install psutil (pip install psutil) first.", "warning")
            return
        cfg = optimizer.SCAN_KINDS[kind]
        self.opt_busy, self.opt_scan_kind = True, kind
        self.opt_cancel_ev = threading.Event()
        for b in (self.btn_scan_q, self.btn_scan_s, self.btn_scan_d):
            b.set_enabled(False)
        self.btn_opt_cancel.set_enabled(True)
        self.opt_title.configure(text=f"{cfg['label']} running...")
        self.opt_sub.configure(text=f"{cfg['what']} ({cfg['target']}). Results appear as they arrive; nothing is "
                               "being changed.")
        for w in self.opt_progress.winfo_children():
            w.destroy()
        self.opt_chips.clear()
        self.opt_progress.pack(anchor="w", fill="x", pady=(dp(8), 0))
        self._set_pill("Analyzing", T["warning"])
        self.opt_scan_t0 = time.time()
        ev = self.opt_cancel_ev

        def progress(event, name, partial):
            self.msgs.put(("call", lambda: self._opt_progress(event, name, partial, ev)))

        def work():
            try:
                a = optimizer.scan(kind, progress=progress, cancel=ev)
                self.msgs.put(("opt_scan", a))
            except optimizer.ScanBusy:
                self.msgs.put(("opt_scan_failed", "A scan was already running."))
            except Exception as e:
                self.msgs.put(("opt_scan_failed", f"{type(e).__name__}: {e}"))
        threading.Thread(target=work, daemon=True).start()
        self._opt_scan_tick()

    def _opt_scan_tick(self):
        if self.opt_busy:
            self.opt_title.configure(text=f"{optimizer.SCAN_KINDS[self.opt_scan_kind]['label']} running... "
                                     f"{time.time() - self.opt_scan_t0:.0f}s")
            self.after(500, self._opt_scan_tick)

    def _opt_progress(self, event, name, partial, ev):
        if ev is not self.opt_cancel_ev or not self.opt_busy:
            return
        chip = self.opt_chips.get(name)
        if chip is None:
            chip = self._label(self.opt_progress, "", 9, color=T["muted"])
            chip.pack(side="left", padx=(0, dp(12)))
            self.opt_chips[name] = chip
        if event == "start":
            chip.configure(text=f"…  {name}", fg=T["muted"])
        else:
            chip.configure(text=f"✓  {name}", fg=T["success"])
            if partial is not None:
                self._opt_render(partial, partial=True)

    def _opt_cancel(self):
        if self.opt_busy:
            self.opt_cancel_ev.set()
            self.btn_opt_cancel.set_enabled(False)
            self.opt_title.configure(text="Cancelling...")

    def _opt_finish_scan_ui(self):
        self.opt_busy = False
        for b in (self.btn_scan_q, self.btn_scan_s, self.btn_scan_d):
            b.set_enabled(True)
        self.btn_opt_cancel.set_enabled(False)
        self.opt_progress.pack_forget()

    def _opt_show_analysis(self, a):
        self._opt_finish_scan_ui()
        self.opt_analysis, self.opt_baseline = a, a.snapshot
        if a.hardware and not self.hw_loaded:
            self._show_hardware(a.hardware)
        self._opt_render(a, partial=False)
        s = a.snapshot
        n = sum(len(v) for v in self._opt_visible(a).values())
        if a.cancelled:
            self.opt_title.configure(text="Scan cancelled")
            self.opt_sub.configure(text="Showing what was found before you cancelled. Nothing was changed.")
        else:
            self.opt_title.configure(text=f"{optimizer.SCAN_KINDS[a.kind]['label']} complete in {a.duration:.1f}s"
                                     if n else "Your PC looks well tuned")
            extra = f" · disk {a.disk_mb_s:.1f} MB/s" if a.disk_mb_s is not None else ""
            self.opt_sub.configure(text=(
                f"{optimizer.human(s.ram_used)} of {optimizer.human(s.ram_total)} memory in use · {s.process_count} "
                f"processes · power plan: {s.power_plan}{extra}. {a.protected_startup} protected startup item(s) were "
                f"left alone. Open a category to see details."))
        self._opt_live()
        self._opt_report_default()
        self._refresh_home()

    # accordion ---------------------------------------------------------
    def _opt_visible(self, a):
        out = {c: [] for c in optimizer.CATEGORIES}
        skipped = set(optimizer.get_state().get("skipped", []))
        for r in a.recommendations:
            if r.key in skipped:
                continue
            out.setdefault(r.category or "Hardware-Specific Recommendations", []).append(r)
        return out

    def _opt_render(self, a, partial):
        vis = self._opt_visible(a)
        total = 0
        for cat, sec in self.opt_sections.items():
            recs = vis.get(cat, [])
            total += len(recs)
            sig = tuple((r.key, r.issue) for r in recs) + (partial,)
            if sig != self.opt_sig.get(cat):          # only rebuild what changed
                self.opt_sig[cat] = sig
                for w in sec.body.winfo_children():
                    w.destroy()
                for r in recs:
                    self._rec_card(sec.body, r)
                if not recs:
                    self._label(sec.body, "Scanning..." if partial else "Nothing to improve here.", 9,
                                color=T["faint"]).pack(anchor="w", padx=dp(16), pady=dp(10))
            risk_hi = any(r.risk == "high" for r in recs)
            sec.set_count(f"{len(recs)} recommendation(s)" if recs else ("scanning..." if partial else "all good"),
                          T["danger"] if risk_hi else T["warning"] if recs else T["muted"])
        self.opt_recs = {r.key: r for r in a.recommendations}
        self.opt_count.configure(text=f"{total} found" + (" so far" if partial else ""))

    def _rec_card(self, parent, r):
        card = tk.Frame(parent, bg=T["surface2"])
        card.pack(fill="x", padx=dp(12), pady=(dp(6), dp(2)))
        inner = tk.Frame(card, bg=T["surface2"])
        inner.pack(fill="x", padx=dp(14), pady=dp(10))
        riskc = {"low": T["success"], "medium": T["warning"], "high": T["danger"]}[r.risk]
        head = tk.Frame(inner, bg=T["surface2"])
        head.pack(fill="x")
        tk.Label(head, text=f"{self.RISK_LABEL[r.risk].upper()} RISK", bg=T["surface2"], fg=riskc,
                 font=ui.font(8, True)).pack(side="left")
        tk.Label(head, text=r.title, bg=T["surface2"], fg=T["text"], font=ui.font(10, True)).pack(
            side="left", padx=(dp(10), 0))
        rows = [("Detected", r.issue), ("Why it matters", r.why), ("Expected benefit", r.benefit),
                ("Affects", r.component), ("Possible side effects", r.side_effects)]
        grid = tk.Frame(inner, bg=T["surface2"])
        grid.pack(fill="x", pady=(dp(6), 0))
        grid.columnconfigure(1, weight=1)
        for i, (k, v) in enumerate(rows):
            tk.Label(grid, text=k, bg=T["surface2"], fg=T["muted"], font=ui.font(9), anchor="nw").grid(
                row=i, column=0, sticky="nw", padx=(0, dp(12)), pady=dp(1))
            lab = tk.Label(grid, text=v or "-", bg=T["surface2"], fg=T["text"], font=ui.font(9), anchor="w",
                           justify="left")
            lab.grid(row=i, column=1, sticky="ew", pady=dp(1))
            grid.bind("<Configure>", lambda e, l=lab: l.configure(wraplength=max(dp(160), e.width - dp(150))), add="+")
        detail = tk.Frame(inner, bg=T["surface2"])
        det_rows = [("Original setting", r.original or "Nothing is changed by this tip."),
                    ("Rollback", r.restore or "-"), ("Suggested action", r.action)]
        for i, (k, v) in enumerate(det_rows):
            tk.Label(detail, text=k, bg=T["surface2"], fg=T["muted"], font=ui.font(9)).grid(
                row=i, column=0, sticky="nw", padx=(0, dp(12)), pady=dp(1))
            l2 = tk.Label(detail, text=v, bg=T["surface2"], fg=T["text"], font=ui.font(9), anchor="w", justify="left")
            l2.grid(row=i, column=1, sticky="ew", pady=dp(1))
            detail.bind("<Configure>", lambda e, l=l2: l.configure(wraplength=max(dp(160), e.width - dp(150))), add="+")
        detail.columnconfigure(1, weight=1)
        bar = tk.Frame(inner, bg=T["surface2"])
        bar.pack(fill="x", pady=(dp(8), 0))
        if r.actionable:
            ui.Btn(bar, "Apply", command=lambda: self._opt_apply_rec(r), style="success", icon="check", height=32,
                   size=9).pack(side="left")
        else:
            tk.Label(bar, text=f"Manual step: {r.action}", bg=T["surface2"], fg=T["muted"], font=ui.font(9)).pack(
                side="left")
        ui.Btn(bar, "Skip", command=lambda: self._opt_skip(r), style="ghost", height=32, size=9).pack(
            side="left", padx=(dp(8), 0))
        more = ui.Btn(bar, "Learn more", command=lambda: None, style="ghost", height=32, size=9)
        more.pack(side="left")

        def toggle():
            if detail.winfo_ismapped():
                detail.pack_forget()
                more.set_text("Learn more")
            else:
                detail.pack(fill="x", pady=(dp(6), 0), before=bar)
                more.set_text("Hide details")
        more.set_command(toggle)

    def _opt_skip(self, r):
        st = optimizer.get_state()
        st.setdefault("skipped", [])
        if r.key not in st["skipped"]:
            st["skipped"].append(r.key)
        optimizer._save_state(st)
        if self.opt_analysis:
            self.opt_sig = {c: None for c in self.opt_sig}
            self._opt_render(self.opt_analysis, partial=False)
        self.toast.show("Skipped. It won't be suggested again until you choose 'Show skipped again'.", "info")

    def _opt_unskip(self):
        st = optimizer.get_state()
        if not st.get("skipped"):
            self.toast.show("Nothing has been skipped.", "info")
            return
        st["skipped"] = []
        optimizer._save_state(st)
        if self.opt_analysis:
            self.opt_sig = {c: None for c in self.opt_sig}
            self._opt_render(self.opt_analysis, partial=False)
        self.toast.show("Skipped recommendations are visible again.", "success")

    # apply -------------------------------------------------------------
    def _opt_apply_rec(self, r):
        if not r.actionable or self.opt_analysis is None:
            self.toast.show("This one is a manual step.", "info")
            return
        if r.kind == "profile":
            self._activate_profile(r.target["profile"])
            return
        reversible = r.kind == "startup"
        note = "Can be restored" if reversible else "CANNOT be undone"
        if not messagebox.askyesno(
                "Apply change", f"{r.title}\n\nCurrent (original) setting:\n  {r.original or r.issue}\n\n"
                f"What will change:\n  {r.action}\n\nPossible side effects:\n  {r.side_effects}\n\n"
                f"Rollback: {r.restore}\n\n{note}. Continue?"):
            return
        items = {(i.source, i.name): i for i in self.opt_analysis.startup}
        before = self.opt_baseline
        self.opt_report.configure(text="Applying change...")

        def work():
            applied, errors = [], []
            if r.kind == "startup":
                it = items.get((r.target["source"], r.target["name"]))
                res = (optimizer.apply_startup_disable(it, self.opt_history) if it
                       else optimizer.ApplyResult(False, "That startup item no longer exists."))
                (applied if res.ok else errors).append((r.key, res.message))
            elif r.kind == "temp":
                d, f, sk = optimizer.clean_temp()
                optimizer._temp_cache.clear()
                applied.append((r.key, f"Deleted {d:,} old temp files, freed {optimizer.human(f)}"
                                + (f" ({sk} in use, left alone)" if sk else "")))
            after = optimizer.take_snapshot(1.0)
            self.msgs.put(("opt_applied", {"applied": applied, "errors": errors, "skipped": 0,
                                           "compare": optimizer.compare(before, after) if before else ""}))
        threading.Thread(target=work, daemon=True).start()

    def _opt_show_applied(self, d):
        done = {k for k, _ in d["applied"]}
        if self.opt_analysis:
            self.opt_analysis.recommendations = [r for r in self.opt_analysis.recommendations if r.key not in done]
            self.opt_sig = {c: None for c in self.opt_sig}
            self._opt_render(self.opt_analysis, partial=False)
        text = [f"Applied {len(d['applied'])} · Errors {len(d['errors'])}"]
        text += [m for _, m in d["applied"]] + [f"Not applied: {m}" for _, m in d["errors"]]
        if any(k.startswith("startup:") for k in done):
            text.append("Start-up changes take effect at your next sign-in, so no difference shows right now.")
        if d["compare"]:
            text.append(d["compare"])
        n = len(self.opt_history.pending())
        text.append(f"Rollback: {n} change(s) can be restored with 'Restore previous settings'.")
        self.opt_report.configure(text="\n".join(text))
        self._opt_report_default_recent()
        self.toast.show(f"{len(d['applied'])} change(s) applied." if d["applied"] else "No changes were applied.",
                        "success" if d["applied"] and not d["errors"] else "warning")

    def _opt_report_default_recent(self):
        recent = [e for e in self.opt_history.all()][-5:]
        lines = [f"•  {time.strftime('%d %b %H:%M', time.localtime(e['time']))}  {e['title']}"
                 + ("  (restored)" if e.get("restored") else "") for e in reversed(recent)]
        self.opt_hist_lbl.configure(text="\n".join(lines) if lines else "Nothing yet. Changes you approve are listed here.")

    def _opt_restore(self):
        pending = self.opt_history.pending()
        if not pending:
            self.toast.show("There is nothing to restore yet.", "info")
            return
        listing = "\n".join(f"•  {e['title']}" for e in reversed(pending[-12:]))
        if not messagebox.askyesno("Restore previous settings", f"{len(pending)} change(s) will be put back "
                                   f"exactly as they were:\n\n{listing}\n\nContinue?"):
            return
        results = optimizer.undo_all(self.opt_history)
        ok = sum(1 for _, r in results if r.ok)
        bad = [f"{t}: {r.message}" for t, r in results if not r.ok]
        self._refresh_profiles()
        self._opt_report_default()
        if bad:
            self.opt_report.configure(text=f"Restored {ok}; could not restore {len(bad)}:\n" + "\n".join(bad))
        else:
            self.opt_report.configure(text=f"Restored {ok} change(s). Your previous settings are back.")
        self.toast.show(f"Restored {ok} change(s)." + (f" {len(bad)} failed." if bad else ""),
                        "success" if not bad else "warning")

    # ═════════════════════════════════════════════════════════════════════
    # PERFORMANCE ANALYTICS
    # ═════════════════════════════════════════════════════════════════════
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

    # ═════════════════════════════════════════════════════════════════════
    # MESSAGE QUEUE (UI thread)
    # ═════════════════════════════════════════════════════════════════════
    def _finish_scan_ui(self):
        self.scanning = False
        self.pulse.stop()
        self.btn_scan.set_enabled(True)
        self.btn_cancel.set_enabled(False)

    def _drain(self):
        try:
            while True:
                kind, data = self.msgs.get_nowait()
                if kind == "scan_hit":
                    tag = data.verdict
                    iid = self.scan_tv.insert("", "end", tags=(tag,), values=(
                        VERDICT_LABEL.get(data.verdict, data.verdict), data.score, data.path,
                        "; ".join(data.reasons)))
                    self.results[iid] = data
                    self.threat_count += 1
                    self.stat_vars["threats"].set(str(self.threat_count))
                    self.res_count.configure(text=f"{self.threat_count} item(s)")
                elif kind == "scan_progress":
                    n, cached, path = data
                    shown = path if len(path) <= 80 else "..." + path[-77:]
                    self.scan_status.set(f"Checking: {shown}")
                    self.stat_vars["files"].set(f"{n:,}")
                    self.stat_vars["cached"].set(f"{cached:,}")
                elif kind == "scan_failed":
                    self._finish_scan_ui()
                    self.scan_status.set(f"Scan failed: {data}")
                    self._set_pill("Scan failed", T["danger"])
                elif kind == "scan_done":
                    st, workers, cancelled = data
                    self._finish_scan_ui()
                    self.stat_vars["files"].set(f"{st.files:,}")
                    self.stat_vars["cached"].set(f"{st.cached:,}")
                    self.stat_vars["time"].set(f"{st.elapsed:.0f}s")
                    extra = ""
                    if st.errors or st.dirs_denied:
                        extra = (f" {st.errors:,} file(s) couldn't be read and {st.dirs_denied:,} folder(s) were "
                                 f"off-limits (run as Administrator to cover more).")
                    if cancelled:
                        self.scan_status.set(f"Stopped after {st.files:,} files.{extra}")
                    elif self.threat_count:
                        self.scan_status.set(f"Done. {self.threat_count} thing(s) need your attention.{extra}")
                    else:
                        self.scan_status.set(f"Done. {st.files:,} files checked and no threats found.{extra}")
                        self.empty_lbl.configure(text="No threats found. Your files look clean.")
                        self.empty_lbl.place(relx=0.5, rely=0.5, anchor="center")
                    if not cancelled:
                        self.last_scan = {"time": time.time(), "files": st.files, "threats": self.threat_count}
                    if self.threat_count:
                        self._append(self.alert_log, f"[scan] {self.threat_count} threat(s) found in {st.files:,} files.",
                                     "warning")
                        self.toast.show(f"{self.threat_count} threat(s) found. Review them below.", "danger")
                    elif not cancelled:
                        self.toast.show("Scan finished. No threats found.", "success")
                    self._refresh_home()
                elif kind == "alert":
                    line = str(data) + (f" | {data.detail}" if getattr(data, "detail", "") else "")
                    sev = getattr(data, "severity", "info")
                    self._append(self.alert_log, line, sev)
                    self._append(self.rt_log, line, sev)
                    if sev in ("high", "critical"):
                        self.bell()
                        self._set_pill("Threat detected", T["danger"])
                        self.toast.show(getattr(data, "message", "Threat detected"), "danger", 6000)
                elif kind == "audit":
                    self.audit_running = False
                    self.audit_btn.set_enabled(True)
                    self.last_score = data.score
                    color = T["success"] if data.score >= 80 else T["warning"] if data.score >= 50 else T["danger"]
                    self.audit_ring.set(data.score, f"{data.score}", "out of 100", color)
                    verdict = ("Your PC is in good shape" if data.score >= 80
                               else "A few things need attention" if data.score >= 50 else "Your PC needs attention")
                    self.audit_title.configure(text=verdict)
                    self.audit_status.configure(text=f"{len(data.findings)} finding(s). Select one to see how to fix it.")
                    self.audit_tv.delete(*self.audit_tv.get_children())
                    self.audit_items.clear()
                    for fd in data.findings:
                        iid = self.audit_tv.insert("", "end", tags=(fd.severity,), values=(
                            SEVERITY_LABEL.get(fd.severity, fd.severity), fd.category, fd.title, fd.fix))
                        self.audit_items[iid] = fd
                    if data.findings:
                        self.audit_empty.place_forget()
                    else:
                        self.audit_empty.configure(text="No problems found.")
                        self.audit_empty.place(relx=0.5, rely=0.5, anchor="center")
                    self._refresh_home()
                elif kind == "opt_scan":
                    self._opt_show_analysis(data)
                elif kind == "call":
                    data()
                elif kind == "opt_scan_failed":
                    self._opt_finish_scan_ui()
                    self.opt_title.configure(text="Scan failed")
                    self.opt_sub.configure(text=str(data))
                elif kind == "opt_applied":
                    self._opt_show_applied(data)
        except queue.Empty:
            pass
        if self.scanning:
            self.stat_vars["time"].set(f"{time.time() - self.scan_started:.0f}s")
        self.after(120, self._drain)

    def _close(self):
        # stop background work so no worker keeps running (or touches a destroyed window) after shutdown
        for ev in (self.cancel, self.opt_cancel_ev, getattr(self, "an_cancel_ev", None)):
            if ev is not None:
                ev.set()
        if self._mode is not None:
            self._mode["cancel"] = True
        for part in (self.monitor, self.procwatch):
            if part:
                try:
                    part.stop()
                except Exception:
                    pass
        self.destroy()


def run():
    app = App()
    app.mainloop()
