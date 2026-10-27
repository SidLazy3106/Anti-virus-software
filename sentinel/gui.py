"""
X-Secure GUI — McAfee-inspired professional antivirus interface.

Layout:
  ┌──────────┬────────────────────────────────────────────┐
  │ Sidebar  │  Header (page title + status pill)         │
  │  logo    ├────────────────────────────────────────────┤
  │  nav     │  Main content (cards / tables / actions)   │
  │  items   │                                            │
  │          │                                            │
  └──────────┴────────────────────────────────────────────┘

Worker threads push messages onto a queue; the UI thread drains it
so Tkinter stays responsive during scans and audits.
"""
from __future__ import annotations

import os
import queue
import threading
import time
import tkinter as tk
from pathlib import Path
from tkinter import filedialog, messagebox, ttk

from . import config, quarantine, sysaudit, webguard
from .monitor import ProcessWatcher, RealtimeMonitor
from .scanner import CLEAN, ERROR, MALICIOUS, Scanner

# ── colour palette (dark security / McAfee-inspired) ─────────────────────
C = {
    "bg":         "#0B1220",      # app background
    "sidebar":    "#0A0F1A",      # left nav
    "card":       "#121A2B",      # cards / panels
    "card_alt":   "#162033",
    "border":     "#1E293B",
    "accent":     "#E11D48",      # McAfee-like red
    "accent_dim": "#9F1239",
    "cyan":       "#00E5FF",
    "green":      "#22C55E",
    "orange":     "#F59E0B",
    "yellow":     "#EAB308",
    "text":       "#F1F5F9",
    "muted":      "#94A3B8",
    "faint":      "#64748B",
    "nav_active": "#1E293B",
    "white":      "#FFFFFF",
}


def _hex_to_rgb(h):
    h = h.lstrip("#")
    return tuple(int(h[i:i + 2], 16) for i in (0, 2, 4))


class App(tk.Tk):
    """Main application window."""

    NAV = [
        ("home",       "Home"),
        ("scan",       "Scan"),
        ("realtime",   "Real-time"),
        ("quarantine", "Quarantine"),
        ("web",        "Web Guard"),
        ("audit",      "System Audit"),
    ]

    def __init__(self):
        super().__init__()
        self.title(f"{config.APP_NAME}  —  Antivirus & Security")
        self.geometry("1180x720")
        self.minsize(980, 620)
        self.configure(bg=C["bg"])
        config.ensure_dirs()

        # state
        self.scanner = Scanner()
        self.msgs: queue.Queue = queue.Queue()
        self.cancel = threading.Event()
        self.monitor = None
        self.procwatch = None
        self.results: dict = {}
        self.current_page = "home"
        self.rt_active = False
        self.last_score = None
        self.threat_count = 0
        self.scan_count = 0

        self._build_style()
        self._build_layout()
        self._show_page("home")
        self.after(120, self._drain)
        self.protocol("WM_DELETE_WINDOW", self._close)

    # ── ttk style ────────────────────────────────────────────────────────
    def _build_style(self):
        style = ttk.Style(self)
        try:
            style.theme_use("clam")
        except tk.TclError:
            pass

        style.configure(".", background=C["bg"], foreground=C["text"],
                        fieldbackground=C["card"], borderwidth=0)
        style.configure("TFrame", background=C["bg"])
        style.configure("Card.TFrame", background=C["card"])
        style.configure("Sidebar.TFrame", background=C["sidebar"])
        style.configure("TLabel", background=C["bg"], foreground=C["text"],
                        font=("Segoe UI", 10))
        style.configure("Muted.TLabel", foreground=C["muted"], background=C["bg"])
        style.configure("Card.TLabel", background=C["card"], foreground=C["text"])
        style.configure("CardMuted.TLabel", background=C["card"], foreground=C["muted"])
        style.configure("Title.TLabel", font=("Segoe UI", 20, "bold"),
                        background=C["bg"], foreground=C["text"])
        style.configure("Score.TLabel", font=("Segoe UI", 42, "bold"),
                        background=C["card"], foreground=C["cyan"])
        style.configure("Nav.TButton", font=("Segoe UI", 11), padding=(14, 10),
                        background=C["sidebar"], foreground=C["muted"])
        style.map("Nav.TButton",
                  background=[("active", C["nav_active"])],
                  foreground=[("active", C["text"])])
        style.configure("Accent.TButton", font=("Segoe UI", 11, "bold"),
                        padding=(16, 10), background=C["accent"], foreground=C["white"])
        style.map("Accent.TButton",
                  background=[("active", C["accent_dim"]), ("disabled", C["border"])])
        style.configure("Secondary.TButton", font=("Segoe UI", 10),
                        padding=(12, 8), background=C["card_alt"], foreground=C["text"])
        style.map("Secondary.TButton",
                  background=[("active", C["border"])])
        style.configure("Green.TButton", font=("Segoe UI", 11, "bold"),
                        padding=(16, 10), background=C["green"], foreground="#06220f")
        style.map("Green.TButton", background=[("active", "#16A34A")])
        style.configure("TEntry", fieldbackground=C["card_alt"], foreground=C["text"],
                        insertcolor=C["text"], padding=6)
        style.configure("TCheckbutton", background=C["bg"], foreground=C["text"],
                        font=("Segoe UI", 10))
        style.map("TCheckbutton", background=[("active", C["bg"])])
        style.configure("Treeview", background=C["card"], foreground=C["text"],
                        fieldbackground=C["card"], rowheight=28, font=("Segoe UI", 10),
                        borderwidth=0)
        style.configure("Treeview.Heading", background=C["card_alt"],
                        foreground=C["muted"], font=("Segoe UI", 10, "bold"),
                        relief="flat")
        style.map("Treeview",
                  background=[("selected", C["accent_dim"])],
                  foreground=[("selected", C["white"])])
        style.configure("Horizontal.TProgressbar", troughcolor=C["card_alt"],
                        background=C["accent"], thickness=8)
        style.configure("TScrollbar", background=C["card"], troughcolor=C["bg"],
                        arrowcolor=C["muted"])

    # ── shell layout ─────────────────────────────────────────────────────
    def _build_layout(self):
        # sidebar
        self.sidebar = tk.Frame(self, bg=C["sidebar"], width=200)
        self.sidebar.pack(side="left", fill="y")
        self.sidebar.pack_propagate(False)

        logo_fr = tk.Frame(self.sidebar, bg=C["sidebar"])
        logo_fr.pack(fill="x", pady=(24, 8), padx=16)
        tk.Label(logo_fr, text="X-SECURE", bg=C["sidebar"], fg=C["accent"],
                 font=("Segoe UI", 16, "bold")).pack(anchor="w")
        tk.Label(logo_fr, text="Antivirus & Security", bg=C["sidebar"],
                 fg=C["faint"], font=("Segoe UI", 9)).pack(anchor="w")

        self.nav_btns = {}
        for key, label in self.NAV:
            b = tk.Button(
                self.sidebar, text=f"  {label}", anchor="w",
                bg=C["sidebar"], fg=C["muted"],
                activebackground=C["nav_active"], activeforeground=C["text"],
                relief="flat", bd=0, font=("Segoe UI", 11),
                cursor="hand2", padx=16, pady=12,
                command=lambda k=key: self._show_page(k),
            )
            b.pack(fill="x", padx=8, pady=2)
            self.nav_btns[key] = b

        # bottom status in sidebar
        tk.Frame(self.sidebar, bg=C["border"], height=1).pack(fill="x",
                                                              side="bottom", pady=(0, 48))
        self.side_status = tk.Label(
            self.sidebar, text="Real-time: OFF", bg=C["sidebar"],
            fg=C["faint"], font=("Segoe UI", 9), anchor="w", padx=16,
        )
        self.side_status.pack(side="bottom", fill="x", pady=(0, 12))

        # main area
        self.main = tk.Frame(self, bg=C["bg"])
        self.main.pack(side="left", fill="both", expand=True)

        # header bar
        self.header = tk.Frame(self.main, bg=C["bg"], height=64)
        self.header.pack(fill="x", padx=28, pady=(18, 0))
        self.header.pack_propagate(False)
        self.page_title = tk.Label(
            self.header, text="Home", bg=C["bg"], fg=C["text"],
            font=("Segoe UI", 22, "bold"),
        )
        self.page_title.pack(side="left", anchor="w")
        self.status_pill = tk.Label(
            self.header, text="  ●  Ready  ", bg=C["card"], fg=C["green"],
            font=("Segoe UI", 10, "bold"), padx=10, pady=4,
        )
        self.status_pill.pack(side="right", anchor="e")

        # content host (pages are swapped here)
        self.content = tk.Frame(self.main, bg=C["bg"])
        self.content.pack(fill="both", expand=True, padx=28, pady=16)

        self.pages: dict[str, tk.Frame] = {}
        self._build_home()
        self._build_scan()
        self._build_realtime()
        self._build_quarantine()
        self._build_web()
        self._build_audit()

    def _show_page(self, key: str):
        self.current_page = key
        titles = {
            "home": "Home",
            "scan": "Scan Your PC",
            "realtime": "Real-time Protection",
            "quarantine": "Quarantine",
            "web": "Web Guard",
            "audit": "System Audit",
        }
        self.page_title.configure(text=titles.get(key, key))
        for k, btn in self.nav_btns.items():
            if k == key:
                btn.configure(bg=C["nav_active"], fg=C["text"])
            else:
                btn.configure(bg=C["sidebar"], fg=C["muted"])
        for k, fr in self.pages.items():
            if k == key:
                fr.pack(fill="both", expand=True)
            else:
                fr.pack_forget()
        if key == "quarantine":
            self._refresh_q()
        if key == "home":
            self._refresh_home_stats()

    # ── helpers ──────────────────────────────────────────────────────────
    def _card(self, parent, **pack) -> tk.Frame:
        fr = tk.Frame(parent, bg=C["card"], highlightbackground=C["border"],
                      highlightthickness=1)
        fr.pack(**pack)
        return fr

    def _section_label(self, parent, text):
        tk.Label(parent, text=text, bg=C["bg"], fg=C["muted"],
                 font=("Segoe UI", 10, "bold")).pack(anchor="w", pady=(0, 6))

    def _tree(self, parent, cols, widths, height=12):
        wrap = tk.Frame(parent, bg=C["card"])
        tv = ttk.Treeview(wrap, columns=cols, show="headings", height=height,
                          selectmode="extended")
        for c, w in zip(cols, widths):
            tv.heading(c, text=c)
            tv.column(c, width=w, anchor="w")
        sb = ttk.Scrollbar(wrap, orient="vertical", command=tv.yview)
        tv.configure(yscrollcommand=sb.set)
        tv.pack(side="left", fill="both", expand=True)
        sb.pack(side="right", fill="y")
        return wrap, tv

    def _log_box(self, parent, height=10):
        wrap = tk.Frame(parent, bg=C["card"])
        t = tk.Text(wrap, height=height, state="disabled", wrap="word",
                    bg=C["card"], fg=C["text"], insertbackground=C["text"],
                    font=("Consolas", 10), relief="flat", bd=0,
                    highlightthickness=0)
        sb = ttk.Scrollbar(wrap, command=t.yview)
        t.configure(yscrollcommand=sb.set)
        t.pack(side="left", fill="both", expand=True, padx=8, pady=8)
        sb.pack(side="right", fill="y")
        return wrap, t

    @staticmethod
    def _append(text: tk.Text, line: str):
        text.configure(state="normal")
        text.insert("end", line + "\n")
        text.see("end")
        text.configure(state="disabled")

    def _set_pill(self, text, color):
        self.status_pill.configure(text=f"  ●  {text}  ", fg=color)

    # ═════════════════════════════════════════════════════════════════════
    # HOME
    # ═════════════════════════════════════════════════════════════════════
    def _build_home(self):
        page = tk.Frame(self.content, bg=C["bg"])
        self.pages["home"] = page

        # status banner
        self.banner = tk.Frame(page, bg=C["card"], highlightbackground=C["border"],
                               highlightthickness=1)
        self.banner.pack(fill="x", pady=(0, 16))
        inner = tk.Frame(self.banner, bg=C["card"])
        inner.pack(fill="x", padx=20, pady=18)
        self.banner_icon = tk.Label(inner, text="●", bg=C["card"], fg=C["green"],
                                    font=("Segoe UI", 28))
        self.banner_icon.pack(side="left", padx=(0, 14))
        txt = tk.Frame(inner, bg=C["card"])
        txt.pack(side="left", fill="x", expand=True)
        self.banner_title = tk.Label(
            txt, text="Your PC is protected", bg=C["card"], fg=C["text"],
            font=("Segoe UI", 16, "bold"),
        )
        self.banner_title.pack(anchor="w")
        self.banner_sub = tk.Label(
            txt, text="Real-time protection is off. Start it for continuous monitoring.",
            bg=C["card"], fg=C["muted"], font=("Segoe UI", 10),
        )
        self.banner_sub.pack(anchor="w", pady=(2, 0))
        tk.Button(
            inner, text="Quick Scan", bg=C["accent"], fg=C["white"],
            activebackground=C["accent_dim"], activeforeground=C["white"],
            relief="flat", font=("Segoe UI", 10, "bold"), padx=18, pady=8,
            cursor="hand2", command=self._quick_scan_nav,
        ).pack(side="right")

        # metric cards row
        row = tk.Frame(page, bg=C["bg"])
        row.pack(fill="x", pady=(0, 16))
        self.metric_vars = {}
        metrics = [
            ("score", "Security Score", "--/100", C["cyan"]),
            ("threats", "Threats Found", "0", C["accent"]),
            ("quarantine", "In Quarantine", "0", C["orange"]),
            ("realtime", "Real-time", "OFF", C["faint"]),
        ]
        for i, (key, label, default, color) in enumerate(metrics):
            card = tk.Frame(row, bg=C["card"], highlightbackground=C["border"],
                            highlightthickness=1)
            card.pack(side="left", fill="both", expand=True,
                      padx=(0 if i == 0 else 8, 0))
            tk.Label(card, text=label, bg=C["card"], fg=C["muted"],
                     font=("Segoe UI", 9)).pack(anchor="w", padx=16, pady=(14, 0))
            var = tk.StringVar(value=default)
            self.metric_vars[key] = var
            tk.Label(card, textvariable=var, bg=C["card"], fg=color,
                     font=("Segoe UI", 22, "bold")).pack(anchor="w", padx=16, pady=(4, 16))

        # quick actions + recent alerts
        bottom = tk.Frame(page, bg=C["bg"])
        bottom.pack(fill="both", expand=True)

        left = tk.Frame(bottom, bg=C["card"], highlightbackground=C["border"],
                        highlightthickness=1)
        left.pack(side="left", fill="both", expand=True, padx=(0, 8))
        tk.Label(left, text="Quick Actions", bg=C["card"], fg=C["text"],
                 font=("Segoe UI", 12, "bold")).pack(anchor="w", padx=16, pady=(14, 8))
        actions = [
            ("Scan Downloads folder", self._quick_scan_nav),
            ("Run system security audit", lambda: (self._show_page("audit"), self._run_audit())),
            ("Open quarantine", lambda: self._show_page("quarantine")),
            ("Check a suspicious URL", lambda: self._show_page("web")),
        ]
        for label, cmd in actions:
            b = tk.Button(
                left, text=f"  ›  {label}", anchor="w",
                bg=C["card"], fg=C["text"], activebackground=C["card_alt"],
                activeforeground=C["cyan"], relief="flat", bd=0,
                font=("Segoe UI", 11), cursor="hand2", padx=12, pady=10,
                command=cmd,
            )
            b.pack(fill="x", padx=8, pady=2)
        tk.Label(left, text="", bg=C["card"]).pack(pady=8)

        right = tk.Frame(bottom, bg=C["card"], highlightbackground=C["border"],
                         highlightthickness=1)
        right.pack(side="left", fill="both", expand=True)
        tk.Label(right, text="Recent Alerts", bg=C["card"], fg=C["text"],
                 font=("Segoe UI", 12, "bold")).pack(anchor="w", padx=16, pady=(14, 4))
        fr, self.alert_log = self._log_box(right, height=9)
        fr.pack(fill="both", expand=True, padx=8, pady=(0, 8))
        self._append(self.alert_log, "No alerts yet. Start real-time protection or run a scan.")

    def _refresh_home_stats(self):
        qn = len(quarantine.list_items())
        self.metric_vars["quarantine"].set(str(qn))
        self.metric_vars["threats"].set(str(self.threat_count))
        if self.last_score is not None:
            self.metric_vars["score"].set(f"{self.last_score}/100")
        if self.rt_active:
            self.metric_vars["realtime"].set("ON")
            self.banner_icon.configure(fg=C["green"])
            self.banner_title.configure(text="Your PC is protected")
            self.banner_sub.configure(
                text="Real-time protection is active. Scans run on new and changed files.")
            self._set_pill("Protected", C["green"])
        else:
            self.metric_vars["realtime"].set("OFF")
            self.banner_icon.configure(fg=C["orange"])
            self.banner_title.configure(text="Protection is limited")
            self.banner_sub.configure(
                text="Real-time protection is off. Start it for continuous monitoring.")
            self._set_pill("Ready", C["orange"])

    def _quick_scan_nav(self):
        self.scan_path.set(str(Path.home() / "Downloads"))
        self._show_page("scan")
        self._start_scan()

    # ═════════════════════════════════════════════════════════════════════
    # SCAN
    # ═════════════════════════════════════════════════════════════════════
    def _build_scan(self):
        page = tk.Frame(self.content, bg=C["bg"])
        self.pages["scan"] = page

        # scan type cards
        types = tk.Frame(page, bg=C["bg"])
        types.pack(fill="x", pady=(0, 12))
        self.scan_mode = tk.StringVar(value="custom")

        def mode_card(parent, key, title, desc, pad):
            fr = tk.Frame(parent, bg=C["card"], highlightbackground=C["border"],
                          highlightthickness=1, cursor="hand2")
            fr.pack(side="left", fill="both", expand=True, padx=10)
            tk.Label(fr, text=title, bg=C["card"], fg=C["text"],
                     font=("Segoe UI", 12, "bold")).pack(anchor="w", padx=14, pady=(12, 2))
            tk.Label(fr, text=desc, bg=C["card"], fg=C["muted"],
                     font=("Segoe UI", 9), wraplength=200, justify="left").pack(
                anchor="w", padx=14, pady=(0, 12))

            def select(_e=None, k=key, frame=fr):
                self.scan_mode.set(k)
                if k == "quick":
                    self.scan_path.set(str(Path.home() / "Downloads"))
                elif k == "full":
                    # common user roots; on Windows often C:\Users\<name>
                    self.scan_path.set(str(Path.home()))
            fr.bind("<Button-1>", select)
            for child in fr.winfo_children():
                child.bind("<Button-1>", select)

        mode_card(types, "quick", "Quick Scan",
                  "Scans Downloads — fast check for common threats.", (0, 6, 0, 0))
        mode_card(types, "custom", "Custom Scan",
                  "Choose any file or folder to scan.", (0, 6, 0, 0))
        mode_card(types, "full", "Full Scan",
                  "Scans your user profile for a deeper check.", (0, 0, 0, 0))

        # path row
        path_row = tk.Frame(page, bg=C["bg"])
        path_row.pack(fill="x", pady=(4, 8))
        self.scan_path = tk.StringVar(value=str(Path.home() / "Downloads"))
        entry = ttk.Entry(path_row, textvariable=self.scan_path)
        entry.pack(side="left", fill="x", expand=True, ipady=4)
        tk.Button(path_row, text="Browse", bg=C["card_alt"], fg=C["text"],
                  activebackground=C["border"], relief="flat", padx=14, pady=6,
                  font=("Segoe UI", 10), cursor="hand2",
                  command=self._browse).pack(side="left", padx=(8, 0))
        self.btn_scan = tk.Button(
            path_row, text="Start Scan", bg=C["accent"], fg=C["white"],
            activebackground=C["accent_dim"], relief="flat", padx=18, pady=6,
            font=("Segoe UI", 10, "bold"), cursor="hand2",
            command=self._start_scan,
        )
        self.btn_scan.pack(side="left", padx=(8, 0))
        tk.Button(path_row, text="Cancel", bg=C["card_alt"], fg=C["text"],
                  activebackground=C["border"], relief="flat", padx=14, pady=6,
                  font=("Segoe UI", 10), cursor="hand2",
                  command=self.cancel.set).pack(side="left", padx=(8, 0))

        # progress + status
        self.scan_status = tk.StringVar(value="Idle — choose a location and start a scan")
        tk.Label(page, textvariable=self.scan_status, bg=C["bg"], fg=C["muted"],
                 font=("Segoe UI", 10)).pack(anchor="w", pady=(0, 4))
        self.progress = ttk.Progressbar(page, mode="indeterminate")
        self.progress.pack(fill="x", pady=(0, 10))

        # results
        tk.Label(page, text="Scan Results", bg=C["bg"], fg=C["muted"],
                 font=("Segoe UI", 10, "bold")).pack(anchor="w")
        fr, self.scan_tv = self._tree(
            page, ("Verdict", "Score", "File", "Reasons"),
            (100, 60, 320, 420), height=11,
        )
        fr.pack(fill="both", expand=True, pady=(4, 8))
        tk.Button(
            page, text="Quarantine selected threats",
            bg=C["accent"], fg=C["white"], activebackground=C["accent_dim"],
            relief="flat", padx=16, pady=8, font=("Segoe UI", 10, "bold"),
            cursor="hand2", command=self._quarantine_selected,
        ).pack(anchor="w")

    def _browse(self):
        d = filedialog.askdirectory()
        if d:
            self.scan_path.set(d)
            self.scan_mode.set("custom")

    def _start_scan(self):
        path = self.scan_path.get()
        if not os.path.exists(path):
            messagebox.showerror("Scan", "Path does not exist.")
            return
        self.cancel.clear()
        self.scan_tv.delete(*self.scan_tv.get_children())
        self.results.clear()
        self.scan_status.set("Scanning…")
        self.progress.start(12)
        self._set_pill("Scanning", C["orange"])
        self.btn_scan.configure(state="disabled")

        def work():
            n = hits = 0
            for res in self.scanner.scan_tree(path, self.cancel):
                n += 1
                if res.verdict not in (CLEAN,):
                    hits += 1
                    self.msgs.put(("scan_hit", res))
                if n % 15 == 0:
                    self.msgs.put(("scan_progress", n))
            self.msgs.put(("scan_done", (n, hits, self.cancel.is_set())))
        threading.Thread(target=work, daemon=True).start()

    def _quarantine_selected(self):
        for iid in self.scan_tv.selection():
            res = self.results.get(iid)
            if not res or res.verdict == ERROR:
                continue
            try:
                quarantine.quarantine_file(res.path, "; ".join(res.reasons), res.sha256)
                self.scan_tv.delete(iid)
                self.threat_count = max(0, self.threat_count - 1)
            except Exception as e:
                messagebox.showerror("Quarantine", f"{res.path}\n{e}")
        self._refresh_q()
        self._refresh_home_stats()

    # ═════════════════════════════════════════════════════════════════════
    # REAL-TIME
    # ═════════════════════════════════════════════════════════════════════
    def _build_realtime(self):
        page = tk.Frame(self.content, bg=C["bg"])
        self.pages["realtime"] = page

        # status card
        top = tk.Frame(page, bg=C["card"], highlightbackground=C["border"],
                       highlightthickness=1)
        top.pack(fill="x", pady=(0, 14))
        inner = tk.Frame(top, bg=C["card"])
        inner.pack(fill="x", padx=18, pady=16)
        self.rt_status_lbl = tk.Label(
            inner, text="Real-time protection is OFF",
            bg=C["card"], fg=C["orange"], font=("Segoe UI", 14, "bold"),
        )
        self.rt_status_lbl.pack(anchor="w")
        tk.Label(
            inner,
            text="Watches folders for new/changed files, ransomware canaries, "
                 "and suspicious process chains (e.g. Office → PowerShell).",
            bg=C["card"], fg=C["muted"], font=("Segoe UI", 10), wraplength=700,
            justify="left",
        ).pack(anchor="w", pady=(4, 0))

        # options
        opts = tk.Frame(page, bg=C["bg"])
        opts.pack(fill="x", pady=(0, 10))
        tk.Label(opts, text="Folders to watch  (separate with  ;  or  : )",
                 bg=C["bg"], fg=C["muted"], font=("Segoe UI", 10)).pack(anchor="w")
        self.rt_paths = tk.StringVar(value=str(Path.home() / "Downloads"))
        ttk.Entry(opts, textvariable=self.rt_paths).pack(fill="x", pady=(4, 8), ipady=4)

        self.auto_q = tk.BooleanVar(value=False)
        self.canary = tk.BooleanVar(value=True)
        tk.Checkbutton(
            opts, text="Auto-quarantine malicious files",
            variable=self.auto_q, bg=C["bg"], fg=C["text"],
            activebackground=C["bg"], activeforeground=C["text"],
            selectcolor=C["card"], font=("Segoe UI", 10),
        ).pack(anchor="w")
        tk.Checkbutton(
            opts, text="Ransomware canary files (hidden decoys in watched folders)",
            variable=self.canary, bg=C["bg"], fg=C["text"],
            activebackground=C["bg"], activeforeground=C["text"],
            selectcolor=C["card"], font=("Segoe UI", 10),
        ).pack(anchor="w")

        self.rt_btn = tk.Button(
            opts, text="Start Protection", bg=C["green"], fg="#06220f",
            activebackground="#16A34A", relief="flat", padx=20, pady=10,
            font=("Segoe UI", 11, "bold"), cursor="hand2",
            command=self._toggle_rt,
        )
        self.rt_btn.pack(anchor="w", pady=(12, 8))

        tk.Label(page, text="Live Activity", bg=C["bg"], fg=C["muted"],
                 font=("Segoe UI", 10, "bold")).pack(anchor="w")
        fr, self.rt_log = self._log_box(page, height=12)
        fr.pack(fill="both", expand=True, pady=(4, 0))
        self._append(self.rt_log, "Protection is stopped. Click Start Protection to begin.")

    def _toggle_rt(self):
        if self.monitor:
            self.monitor.stop()
            self.procwatch.stop()
            self.monitor = self.procwatch = None
            self.rt_active = False
            self.rt_btn.configure(text="Start Protection", bg=C["green"],
                                  fg="#06220f", activebackground="#16A34A")
            self.rt_status_lbl.configure(text="Real-time protection is OFF", fg=C["orange"])
            self.side_status.configure(text="Real-time: OFF", fg=C["faint"])
            self._append(self.rt_log, "Protection stopped.")
            self._refresh_home_stats()
            return

        # pathsep on Windows is ';', on Unix ':'
        raw = self.rt_paths.get().replace(";", os.pathsep)
        paths = [p.strip() for p in raw.split(os.pathsep) if p.strip() and os.path.isdir(p.strip())]
        if not paths:
            messagebox.showerror("Real-time", "No valid folders to watch.")
            return
        emit = lambda a: self.msgs.put(("alert", a))
        try:
            self.monitor = RealtimeMonitor(
                self.scanner, paths, emit, self.auto_q.get(), self.canary.get())
            self.monitor.start()
            self.procwatch = ProcessWatcher(emit)
            self.procwatch.start()
        except RuntimeError as e:
            self.monitor = self.procwatch = None
            messagebox.showerror("Real-time", str(e))
            return
        self.rt_active = True
        self.rt_btn.configure(text="Stop Protection", bg=C["accent"],
                              fg=C["white"], activebackground=C["accent_dim"])
        self.rt_status_lbl.configure(text="Real-time protection is ON", fg=C["green"])
        self.side_status.configure(text="Real-time: ON", fg=C["green"])
        self._append(self.rt_log, f"Watching: {', '.join(paths)}")
        self._refresh_home_stats()

    # ═════════════════════════════════════════════════════════════════════
    # QUARANTINE
    # ═════════════════════════════════════════════════════════════════════
    def _build_quarantine(self):
        page = tk.Frame(self.content, bg=C["bg"])
        self.pages["quarantine"] = page

        info = tk.Frame(page, bg=C["card"], highlightbackground=C["border"],
                        highlightthickness=1)
        info.pack(fill="x", pady=(0, 12))
        tk.Label(
            info,
            text="Quarantined files are moved out of reach and obfuscated so they cannot run. "
                 "You can restore or permanently delete them.",
            bg=C["card"], fg=C["muted"], font=("Segoe UI", 10),
            wraplength=900, justify="left",
        ).pack(anchor="w", padx=16, pady=14)

        row = tk.Frame(page, bg=C["bg"])
        row.pack(fill="x", pady=(0, 8))
        for text, cmd, color in (
            ("Refresh", self._refresh_q, C["card_alt"]),
            ("Restore selected", self._restore_q, C["green"]),
            ("Delete permanently", self._delete_q, C["accent"]),
        ):
            tk.Button(
                row, text=text, bg=color,
                fg=("#06220f" if color == C["green"] else C["white"] if color == C["accent"] else C["text"]),
                activebackground=C["border"], relief="flat", padx=14, pady=7,
                font=("Segoe UI", 10, "bold" if color != C["card_alt"] else "normal"),
                cursor="hand2", command=cmd,
            ).pack(side="left", padx=(0, 8))

        fr, self.q_tv = self._tree(
            page, ("Original Path", "Reason", "SHA-256"),
            (400, 280, 260), height=14,
        )
        fr.pack(fill="both", expand=True)

    def _refresh_q(self):
        if not hasattr(self, "q_tv"):
            return
        self.q_tv.delete(*self.q_tv.get_children())
        for it in quarantine.list_items():
            self.q_tv.insert("", "end", iid=it["id"],
                             values=(it["original_path"], it["reason"], it["sha256"][:16] + "…"))
        self.metric_vars["quarantine"].set(str(len(quarantine.list_items())))

    def _restore_q(self):
        sel = self.q_tv.selection()
        if not sel:
            messagebox.showinfo("Restore", "Select one or more items first.")
            return
        if messagebox.askyesno("Restore",
                               "Restore the selected file(s)?\nThey may still be malicious."):
            for qid in sel:
                try:
                    quarantine.restore(qid)
                except Exception as e:
                    messagebox.showerror("Restore", str(e))
            self._refresh_q()

    def _delete_q(self):
        sel = self.q_tv.selection()
        if not sel:
            messagebox.showinfo("Delete", "Select one or more items first.")
            return
        if messagebox.askyesno("Delete", "Permanently delete the selected file(s)?"):
            for qid in sel:
                try:
                    quarantine.delete(qid)
                except Exception as e:
                    messagebox.showerror("Delete", str(e))
            self._refresh_q()

    # ═════════════════════════════════════════════════════════════════════
    # WEB GUARD
    # ═════════════════════════════════════════════════════════════════════
    def _build_web(self):
        page = tk.Frame(self.content, bg=C["bg"])
        self.pages["web"] = page

        info = tk.Frame(page, bg=C["card"], highlightbackground=C["border"],
                        highlightthickness=1)
        info.pack(fill="x", pady=(0, 14))
        tk.Label(
            info,
            text="Check any URL for phishing tricks, lookalike domains, risky TLDs, "
                 "punycode, and other web threats. The browser extension uses the same logic.",
            bg=C["card"], fg=C["muted"], font=("Segoe UI", 10),
            wraplength=900, justify="left",
        ).pack(anchor="w", padx=16, pady=14)

        row = tk.Frame(page, bg=C["bg"])
        row.pack(fill="x", pady=(0, 12))
        self.url_var = tk.StringVar()
        e = ttk.Entry(row, textvariable=self.url_var)
        e.pack(side="left", fill="x", expand=True, ipady=5)
        e.bind("<Return>", lambda _e: self._check_url())
        tk.Button(
            row, text="Check URL", bg=C["accent"], fg=C["white"],
            activebackground=C["accent_dim"], relief="flat", padx=18, pady=7,
            font=("Segoe UI", 10, "bold"), cursor="hand2",
            command=self._check_url,
        ).pack(side="left", padx=(8, 0))

        result = tk.Frame(page, bg=C["card"], highlightbackground=C["border"],
                          highlightthickness=1)
        result.pack(fill="both", expand=True)
        self.url_verdict = tk.Label(
            result, text="Enter a URL above to analyse it",
            bg=C["card"], fg=C["muted"], font=("Segoe UI", 14, "bold"),
        )
        self.url_verdict.pack(anchor="w", padx=18, pady=(18, 6))
        self.url_detail = tk.Label(
            result, text="", bg=C["card"], fg=C["text"],
            font=("Segoe UI", 11), justify="left", wraplength=880,
        )
        self.url_detail.pack(anchor="w", padx=18, pady=(0, 18))

    def _check_url(self):
        url = self.url_var.get().strip()
        if not url:
            messagebox.showinfo("Web Guard", "Enter a URL first.")
            return
        v = webguard.analyze_url(url)
        colors = {"clean": C["green"], "suspicious": C["orange"], "malicious": C["accent"]}
        color = colors.get(v.verdict, C["text"])
        self.url_verdict.configure(
            text=f"{v.verdict.upper()}   ·   risk {v.score}/100", fg=color)
        why = "\n".join(f"•  {r}" for r in v.reasons) or "•  No risk signals found"
        self.url_detail.configure(text=why)

    # ═════════════════════════════════════════════════════════════════════
    # SYSTEM AUDIT
    # ═════════════════════════════════════════════════════════════════════
    def _build_audit(self):
        page = tk.Frame(self.content, bg=C["bg"])
        self.pages["audit"] = page

        top = tk.Frame(page, bg=C["card"], highlightbackground=C["border"],
                       highlightthickness=1)
        top.pack(fill="x", pady=(0, 12))
        inner = tk.Frame(top, bg=C["card"])
        inner.pack(fill="x", padx=18, pady=16)

        left = tk.Frame(inner, bg=C["card"])
        left.pack(side="left", fill="x", expand=True)
        tk.Label(left, text="Security Score", bg=C["card"], fg=C["muted"],
                 font=("Segoe UI", 10)).pack(anchor="w")
        self.score_var = tk.StringVar(value="--")
        tk.Label(left, textvariable=self.score_var, bg=C["card"], fg=C["cyan"],
                 font=("Segoe UI", 36, "bold")).pack(anchor="w")
        self.audit_status = tk.StringVar(value="Click Run Audit to check your PC")
        tk.Label(left, textvariable=self.audit_status, bg=C["card"], fg=C["muted"],
                 font=("Segoe UI", 10)).pack(anchor="w", pady=(4, 0))

        tk.Button(
            inner, text="Run Audit", bg=C["accent"], fg=C["white"],
            activebackground=C["accent_dim"], relief="flat", padx=20, pady=10,
            font=("Segoe UI", 11, "bold"), cursor="hand2",
            command=self._run_audit,
        ).pack(side="right", anchor="center")

        tk.Label(page, text="Findings", bg=C["bg"], fg=C["muted"],
                 font=("Segoe UI", 10, "bold")).pack(anchor="w")
        fr, self.audit_tv = self._tree(
            page, ("Severity", "Category", "Issue", "Fix"),
            (90, 110, 380, 320), height=13,
        )
        fr.pack(fill="both", expand=True, pady=(4, 0))

    def _run_audit(self):
        self.audit_status.set("Running audit…")
        self.score_var.set("…")
        self._set_pill("Auditing", C["orange"])
        threading.Thread(
            target=lambda: self.msgs.put(("audit", sysaudit.run_audit())),
            daemon=True,
        ).start()

    # ═════════════════════════════════════════════════════════════════════
    # MESSAGE QUEUE (UI thread)
    # ═════════════════════════════════════════════════════════════════════
    def _drain(self):
        try:
            while True:
                kind, data = self.msgs.get_nowait()
                if kind == "scan_hit":
                    iid = self.scan_tv.insert(
                        "", "end",
                        values=(data.verdict.upper(), data.score, data.path,
                                "; ".join(data.reasons)),
                    )
                    self.results[iid] = data
                    self.threat_count += 1
                elif kind == "scan_progress":
                    self.scan_status.set(f"Scanned {data} files…")
                elif kind == "scan_done":
                    n, hits, cancelled = data
                    self.scan_count = n
                    self.progress.stop()
                    self.btn_scan.configure(state="normal")
                    msg = ("Cancelled" if cancelled else "Done")
                    self.scan_status.set(
                        f"{msg}: {n} files scanned · {hits} threat(s) found")
                    self._set_pill("Ready", C["green"] if hits == 0 else C["orange"])
                    self.metric_vars["threats"].set(str(self.threat_count))
                    if hits:
                        self._append(
                            self.alert_log,
                            f"[SCAN] {hits} threat(s) found in last scan ({n} files).")
                elif kind == "alert":
                    line = str(data) + (f" | {data.detail}" if getattr(data, "detail", "") else "")
                    self._append(self.alert_log, line)
                    if hasattr(self, "rt_log"):
                        self._append(self.rt_log, line)
                    if getattr(data, "severity", "") in ("high", "critical"):
                        self.bell()
                        self._set_pill("Threat detected", C["accent"])
                elif kind == "audit":
                    self.last_score = data.score
                    self.score_var.set(f"{data.score}")
                    self.metric_vars["score"].set(f"{data.score}/100")
                    self.audit_status.set(f"{len(data.findings)} finding(s)")
                    self.audit_tv.delete(*self.audit_tv.get_children())
                    for fd in data.findings:
                        self.audit_tv.insert(
                            "", "end",
                            values=(fd.severity.upper(), fd.category, fd.title, fd.fix),
                        )
                    self._set_pill("Ready", C["green"] if data.score >= 80 else C["orange"])
        except queue.Empty:
            pass
        self.after(120, self._drain)

    def _close(self):
        if self.monitor:
            try:
                self.monitor.stop()
            except Exception:
                pass
        if self.procwatch:
            try:
                self.procwatch.stop()
            except Exception:
                pass
        self.destroy()


def run():
    app = App()
    app.mainloop()
