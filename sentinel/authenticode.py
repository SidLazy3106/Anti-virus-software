"""Authenticode (digital signature) verification through Windows' own WinVerifyTrust.

Used only to *lower* heuristic suspicion for programs whose embedded signature Windows verifies as valid.
It runs fully offline: revocation checks are disabled and no certificate URLs are fetched, so a scan never waits
on the network. Files that are signed only through a Windows catalog (many system files) report "no signature",
which simply means no reduction; it is never treated as a sign of malware.
"""
from __future__ import annotations

import ctypes
import uuid
from ctypes import wintypes

from .platform_utils import IS_WIN
from .winconst import WTD_CACHE_ONLY_URL_RETRIEVAL, WTD_REVOCATION_CHECK_NONE

# {00AAC56B-CD44-11d0-8CC2-00C04FC295EE}
_ACTION_GENERIC_VERIFY_V2 = uuid.UUID("00AAC56B-CD44-11d0-8CC2-00C04FC295EE")
WTD_UI_NONE, WTD_REVOKE_NONE, WTD_CHOICE_FILE = 2, 0, 1
WTD_STATEACTION_VERIFY, WTD_STATEACTION_CLOSE = 1, 2


class _GUID(ctypes.Structure):
    _fields_ = [("Data1", wintypes.DWORD), ("Data2", wintypes.WORD), ("Data3", wintypes.WORD),
                ("Data4", ctypes.c_ubyte * 8)]

    @classmethod
    def of(cls, u: uuid.UUID):
        f = u.fields
        d4 = (ctypes.c_ubyte * 8)(*u.bytes[8:])
        return cls(f[0], f[1], f[2], d4)


class _FILE_INFO(ctypes.Structure):
    _fields_ = [("cbStruct", wintypes.DWORD), ("pcwszFilePath", wintypes.LPCWSTR), ("hFile", wintypes.HANDLE),
                ("pgKnownSubject", ctypes.c_void_p)]


class _TRUST_DATA(ctypes.Structure):
    _fields_ = [("cbStruct", wintypes.DWORD), ("pPolicyCallbackData", ctypes.c_void_p),
                ("pSIPClientData", ctypes.c_void_p), ("dwUIChoice", wintypes.DWORD),
                ("fdwRevocationChecks", wintypes.DWORD), ("dwUnionChoice", wintypes.DWORD),
                ("pFile", ctypes.POINTER(_FILE_INFO)), ("dwStateAction", wintypes.DWORD),
                ("hWVTStateData", wintypes.HANDLE), ("pwszURLReference", wintypes.LPCWSTR),
                ("dwProvFlags", wintypes.DWORD), ("dwUIContext", wintypes.DWORD),
                ("pSignatureSettings", ctypes.c_void_p)]


def has_valid_signature(path: str) -> bool:
    """True only if Windows verifies an embedded Authenticode signature on the file as valid and trusted."""
    if not IS_WIN:
        return False
    try:
        wvt = ctypes.windll.wintrust.WinVerifyTrust
        wvt.argtypes = [wintypes.HWND, ctypes.POINTER(_GUID), ctypes.c_void_p]
        wvt.restype = ctypes.c_long
        finfo = _FILE_INFO(ctypes.sizeof(_FILE_INFO), str(path), None, None)
        data = _TRUST_DATA()
        data.cbStruct = ctypes.sizeof(_TRUST_DATA)
        data.dwUIChoice = WTD_UI_NONE
        data.fdwRevocationChecks = WTD_REVOKE_NONE
        data.dwUnionChoice = WTD_CHOICE_FILE
        data.pFile = ctypes.pointer(finfo)
        data.dwStateAction = WTD_STATEACTION_VERIFY
        data.dwProvFlags = WTD_REVOCATION_CHECK_NONE | WTD_CACHE_ONLY_URL_RETRIEVAL
        guid = _GUID.of(_ACTION_GENERIC_VERIFY_V2)
        status = wvt(None, ctypes.byref(guid), ctypes.byref(data))
        data.dwStateAction = WTD_STATEACTION_CLOSE              # always release the verification state
        wvt(None, ctypes.byref(guid), ctypes.byref(data))
        return status == 0
    except (OSError, AttributeError, ValueError):
        return False
