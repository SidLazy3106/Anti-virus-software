"""Health check page (system audit)."""
from __future__ import annotations

import threading
import tkinter as tk

from .. import sysaudit, ui_kit as ui
from ..ui_kit import T, dp


class AuditPage:
    """Health check page (system audit)."""

    # HEALTH CHECK (system audit)
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
