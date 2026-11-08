"""PC optimizer power/performance profile switcher and its animation."""
from __future__ import annotations

import threading
import time
import tkinter as tk
from tkinter import messagebox

from .. import aa, analytics, hardware, logger, mode_art, optimizer, ui_kit as ui
from ..ui_kit import T, dp


class ModeSwitcher:
    """PC optimizer power/performance profile switcher and its animation."""

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
