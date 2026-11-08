"""Quarantine page."""
from __future__ import annotations

import tkinter as tk
from tkinter import messagebox

from .. import quarantine, ui_kit as ui
from ..ui_kit import T, dp
from .text import ago


class QuarantinePage:
    """Quarantine page."""

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
                             values=(it["original_path"], it["reason"], ago(it["time"])))
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
