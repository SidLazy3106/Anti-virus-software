"""PC optimizer scan, recommendation cards, apply/undo."""
from __future__ import annotations

import threading
import time
import tkinter as tk
from tkinter import messagebox

from .. import optimizer, ui_kit as ui
from ..ui_kit import T, dp


class RecommendationsPanel:
    """PC optimizer scan, recommendation cards, apply/undo."""

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
