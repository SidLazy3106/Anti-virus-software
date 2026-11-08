"""Allow only one X-Secure window per Windows sign-in session.

A named mutex is held for as long as the app runs. A second launch finds the mutex taken, brings the existing
window to the front and exits instead of opening a duplicate.
"""
from __future__ import annotations

import ctypes

from . import config
from .platform_utils import IS_WIN
from .winconst import ERROR_ALREADY_EXISTS, SW_RESTORE

MUTEX_NAME = r"Local\X-Secure-Desktop-App"
_handle = None


def acquire(name: str = MUTEX_NAME) -> bool:
    """True if this process is the only instance (or if that cannot be determined: never lock the user out)."""
    global _handle
    if not IS_WIN:
        return True
    k32 = ctypes.windll.kernel32
    handle = k32.CreateMutexW(None, False, name)
    if not handle:
        return True
    if k32.GetLastError() == ERROR_ALREADY_EXISTS:
        k32.CloseHandle(handle)
        return False
    _handle = handle
    return True


def release() -> None:
    global _handle
    if _handle is not None:
        ctypes.windll.kernel32.CloseHandle(_handle)
        _handle = None


def focus_existing(title: str = config.WINDOW_TITLE) -> bool:
    """Bring the running X-Secure window to the front. Returns whether a window was found."""
    if not IS_WIN:
        return False
    user32 = ctypes.windll.user32
    hwnd = user32.FindWindowW(None, title)
    if not hwnd:
        return False
    user32.ShowWindow(hwnd, SW_RESTORE)
    user32.SetForegroundWindow(hwnd)
    return True
