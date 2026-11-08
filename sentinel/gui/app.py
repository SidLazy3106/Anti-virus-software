"""X-Secure desktop app window: shell, navigation and the UI-thread message queue."""
from __future__ import annotations

import queue
import threading
import time
import tkinter as tk
from tkinter import ttk

from .. import config, fatal, hardware, logger, optimizer, single_instance, ui_kit as ui, webguard
from ..scanner import Scanner
from ..ui_kit import T, dp
from .text import SEVERITY_LABEL, VERDICT_LABEL
from .analytics import AnalyticsPage
from .audit import AuditPage
from .home import HomePage
from .modes import ModeSwitcher
from .optimizer import OptimizerPage
from .quarantine import QuarantinePage
from .realtime import RealtimePage
from .recommendations import RecommendationsPanel
from .scan import ScanPage
from .web import WebPage


class App(HomePage, ScanPage, RealtimePage, QuarantinePage, WebPage, AuditPage, OptimizerPage, ModeSwitcher, RecommendationsPanel, AnalyticsPage, tk.Tk):
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
        self.title(config.WINDOW_TITLE)
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


    # MESSAGE QUEUE (UI thread)
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
                except Exception as e:      # shutting down: report, but never block closing the window
                    logger.get().info("could not stop %s cleanly: %s", type(part).__name__, e)
        self.destroy()


def run() -> int:
    """Open the app window. A second launch just brings the first window forward. Returns the exit code."""
    if not single_instance.acquire():
        single_instance.focus_existing()
        return 0
    try:
        try:
            app = App()
        except Exception as e:           # no display, broken Tk install...: say so instead of vanishing
            logger.get().exception("could not open the window")
            fatal.report(f"X-Secure could not open its window.\n\n{type(e).__name__}: {e}")
            return 1
        app.mainloop()
        return 0
    finally:
        single_instance.release()
