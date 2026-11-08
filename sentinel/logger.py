"""Rotating log file (~/.x-secure/x-secure.log). Logging must never break protection."""
from __future__ import annotations

import logging
import logging.handlers

from . import config

_log = None


def get() -> logging.Logger:
    global _log
    if _log is None:
        _log = logging.getLogger("x-secure")
        _log.setLevel(logging.INFO)
        _log.propagate = False
        try:
            config.ensure_dirs()
            h = logging.handlers.RotatingFileHandler(
                config.LOG_FILE, maxBytes=config.LOG_MAX_BYTES, backupCount=config.LOG_BACKUP_COUNT, encoding="utf-8")
            h.setFormatter(logging.Formatter("%(asctime)s %(levelname)s %(message)s"))
            _log.addHandler(h)
        except OSError:
            _log.addHandler(logging.NullHandler())
    return _log


def close():
    """Release the log file (e.g. before deleting the data folder; Windows can't delete an open file)."""
    global _log
    if _log is not None:
        for h in list(_log.handlers):
            h.close()
            _log.removeHandler(h)
        _log = None
