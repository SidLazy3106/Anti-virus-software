"""Home page: protection level, next step, tips."""
from __future__ import annotations

import time
import tkinter as tk

from .. import quarantine, ui_kit as ui
from ..ui_kit import T, dp
from .text import TIPS, ago


class HomePage:
    """Home page: protection level, next step, tips."""

    # state owned by the App window and shared by every page mixin
    rt_active: bool
    last_scan: dict | None
    last_score: int | None
    threat_count: int

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
            hnt.configure(text=f"Last scan {ago(self.last_scan['time'])} · {qn} in quarantine")
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
