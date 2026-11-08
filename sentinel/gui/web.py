"""Web guard page: URL checker."""
from __future__ import annotations

import tkinter as tk

from .. import ui_kit as ui, webguard
from ..ui_kit import T, dp


class WebPage:
    """Web guard page: URL checker."""

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
