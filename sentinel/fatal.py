"""Tell the user about an error that stops the program, in a way that works without a console."""
from __future__ import annotations

import ctypes
import sys

from . import config
from .platform_utils import IS_WIN
from .winconst import MB_ICONERROR


def report(message: str) -> None:
    """Message box for the windowed build, stderr otherwise. The log file always has the full details."""
    text = f"{message}\n\nDetails were saved to:\n{config.LOG_FILE}"
    if IS_WIN and getattr(sys, "frozen", False) and sys.stderr is None:
        ctypes.windll.user32.MessageBoxW(None, text, config.APP_NAME, MB_ICONERROR)
    else:
        print(text, file=sys.stderr)
