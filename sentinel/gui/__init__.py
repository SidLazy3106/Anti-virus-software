"""X-Secure desktop app.

A calm "Am I safe?" dashboard: one big protection level, one obvious next step, plain-English wording, and
rounded modern cards. Worker threads push messages onto a queue and the UI thread drains it, so the window
stays responsive during scans and audits. Widgets live in ui_kit (sharp HiDPI rendering, cards, buttons...).

Layout: app.py is the window shell; every page is a mixin in its own module (home, scan, realtime, ...).
"""
from .app import App, run

__all__ = ["App", "run"]
