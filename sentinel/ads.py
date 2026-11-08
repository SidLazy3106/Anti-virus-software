"""NTFS alternate data streams (ADS).

A file can carry hidden extra streams ("notes.txt:payload.exe") that Explorer never shows; malware uses them to
hide programs and scripts. list_streams() enumerates them with FindFirstStreamW. Streams Windows and common apps
write for normal reasons (the "downloaded from the internet" mark and similar) are ignored.
"""
from __future__ import annotations

import ctypes
import sys
from ctypes import wintypes

IS_WIN = sys.platform == "win32"
BENIGN = {"zone.identifier", "smartscreen", "com.dropbox.attrs", "com.dropbox.attributes", "encryptable",
          "afp_afpinfo", "afp_resource", "ms-properties", "{4c8cc155-6c1e-11d1-8e41-00c04fb9386d}"}
_INVALID = ctypes.c_void_p(-1).value


class _STREAM_DATA(ctypes.Structure):
    _fields_ = [("StreamSize", ctypes.c_longlong), ("cStreamName", ctypes.c_wchar * 296)]


_k32 = None


def _api():
    global _k32
    if _k32 is None:
        k = ctypes.WinDLL("kernel32", use_last_error=True)
        k.FindFirstStreamW.argtypes = [wintypes.LPCWSTR, ctypes.c_int, ctypes.c_void_p, wintypes.DWORD]
        k.FindFirstStreamW.restype = ctypes.c_void_p
        k.FindNextStreamW.argtypes = [ctypes.c_void_p, ctypes.c_void_p]
        k.FindNextStreamW.restype = wintypes.BOOL
        k.FindClose.argtypes = [ctypes.c_void_p]
        _k32 = k
    return _k32


def list_streams(path) -> list:
    """[(name, size)] of the file's named streams, excluding the main stream. [] when there are none or on error."""
    if not IS_WIN:
        return []
    k = _api()
    data = _STREAM_DATA()
    h = k.FindFirstStreamW(str(path), 0, ctypes.byref(data), 0)
    if h is None or h == _INVALID:
        return []
    out = []
    try:
        while True:
            raw = data.cStreamName                      # ":name:$DATA"; the main stream is "::$DATA"
            if raw and raw != "::$DATA":
                name = raw[1:].rsplit(":", 1)[0]
                if name:
                    out.append((name, int(data.StreamSize)))
            if not k.FindNextStreamW(h, ctypes.byref(data)):
                break
    finally:
        k.FindClose(h)
    return out


def suspicious_streams(path) -> list:
    """Named, non-empty streams that are not on the benign list."""
    return [(n, s) for n, s in list_streams(path) if s > 0 and n.lower() not in BENIGN]
