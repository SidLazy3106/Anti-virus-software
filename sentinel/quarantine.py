"""Quarantine store.

Files are moved into ~/.x-secure/quarantine as <id>.qz and ENCRYPTED with Windows DPAPI (CryptProtectData:
AES-256 with an integrity check, keyed to your Windows account). No key is stored in the quarantine folder, so a
copied quarantine folder (or another Windows user) cannot open the files, and a modified file fails to decrypt
instead of being restored corrupted. Each file is bound to its quarantine id, so blobs can't be swapped.

Limits: anything running as *you* can still ask Windows to decrypt (that needs a SYSTEM service to fix).
Older items stored with the previous XOR format (key in index.json) are still restored correctly.
On non-Windows systems the XOR format is used as a fallback.
"""
from __future__ import annotations

import ctypes
import json
import os
import struct
import sys
import time
import uuid
from pathlib import Path

from . import config

IS_WIN = sys.platform == "win32"
KEY_LEN = 32
CHUNK = 1 << 20          # multiple of KEY_LEN so the legacy XOR key stream stays aligned
ENC_CHUNK = 4 << 20      # plaintext bytes per DPAPI blob
MAGIC = b"XSQ2"          # file header of the encrypted format
FORMAT = "dpapi-v1"


# ── DPAPI ────────────────────────────────────────────────────────────────
class _BLOB(ctypes.Structure):
    _fields_ = [("cbData", ctypes.c_uint32), ("pbData", ctypes.POINTER(ctypes.c_char))]


def _blob(data: bytes):
    buf = ctypes.create_string_buffer(data, len(data))
    return _BLOB(len(data), ctypes.cast(buf, ctypes.POINTER(ctypes.c_char))), buf


def _dpapi(data: bytes, entropy: bytes, protect: bool) -> bytes:
    crypt32, kernel32 = ctypes.windll.crypt32, ctypes.windll.kernel32
    src, _k1 = _blob(data)
    ent, _k2 = _blob(entropy)
    out = _BLOB()
    flags = 0x1  # CRYPTPROTECT_UI_FORBIDDEN
    fn = crypt32.CryptProtectData if protect else crypt32.CryptUnprotectData
    ok = fn(ctypes.byref(src), None, ctypes.byref(ent), None, None, flags, ctypes.byref(out))
    if not ok:
        raise OSError(ctypes.GetLastError(), "Windows could not " + ("encrypt" if protect else
                                                                     "decrypt (file changed or wrong user)"))
    try:
        return ctypes.string_at(out.pbData, out.cbData)
    finally:
        kernel32.LocalFree(out.pbData)


def available() -> bool:
    return IS_WIN


def _encrypt_file(src, dst, entropy: bytes):
    with open(src, "rb") as fi, open(dst, "wb") as fo:
        fo.write(MAGIC)
        while True:
            chunk = fi.read(ENC_CHUNK)
            if not chunk:
                break
            blob = _dpapi(chunk, entropy, True)
            fo.write(struct.pack("<I", len(blob)) + blob)


def _decrypt_file(src, dst, entropy: bytes):
    tmp = Path(str(dst) + ".partial")
    try:
        with open(src, "rb") as fi, open(tmp, "wb") as fo:
            if fi.read(4) != MAGIC:
                raise ValueError("not an encrypted quarantine file")
            while True:
                head = fi.read(4)
                if not head:
                    break
                (n,) = struct.unpack("<I", head)
                blob = fi.read(n)
                if len(blob) != n:
                    raise ValueError("quarantine file is truncated")
                fo.write(_dpapi(blob, entropy, False))
        os.replace(tmp, dst)                # only a fully verified file ever appears at the target
    finally:
        tmp.unlink(missing_ok=True)


def _xor_stream(src, dst, key: bytes):
    """Legacy format (obfuscation only); kept to restore old items and for non-Windows."""
    stream = key * (CHUNK // KEY_LEN)
    with open(src, "rb") as fi, open(dst, "wb") as fo:
        while True:
            chunk = fi.read(CHUNK)
            if not chunk:
                break
            n = len(chunk)
            x = int.from_bytes(chunk, "big") ^ int.from_bytes(stream[:n], "big")
            fo.write(x.to_bytes(n, "big"))


# ── index ────────────────────────────────────────────────────────────────
def _index_file() -> Path:
    return config.QUARANTINE_DIR / "index.json"


def _load() -> dict:
    try:
        return json.loads(_index_file().read_text())
    except (OSError, ValueError):
        return {}


def _save(idx: dict):
    config.ensure_dirs()
    tmp = _index_file().with_suffix(".tmp")
    tmp.write_text(json.dumps(idx, indent=2))
    os.replace(tmp, _index_file())


# ── public API ───────────────────────────────────────────────────────────
def quarantine_file(path, reason: str = "", sha256: str = "") -> str:
    config.ensure_dirs()
    src = Path(path).resolve()
    qid = uuid.uuid4().hex
    dst = config.QUARANTINE_DIR / f"{qid}.qz"
    entry = {"original_path": str(src), "sha256": sha256, "reason": reason, "time": time.time()}
    try:
        if available():
            _encrypt_file(src, dst, qid.encode())
            entry["format"] = FORMAT
        else:
            key = os.urandom(KEY_LEN)
            _xor_stream(src, dst, key)
            entry.update(format="xor", key=key.hex())
        os.remove(src)
    except Exception:
        dst.unlink(missing_ok=True)  # encryption failed or file in use: leave the original untouched
        raise
    entry["size"] = dst.stat().st_size
    idx = _load()
    idx[qid] = entry
    _save(idx)
    return qid


def list_items() -> list[dict]:
    return [dict(v, id=k) for k, v in sorted(_load().items(), key=lambda kv: kv[1]["time"], reverse=True)]


def restore(qid: str, dest=None) -> Path:
    idx = _load()
    item = idx[qid]
    target = Path(dest or item["original_path"])
    if target.exists():
        target = target.with_name(target.name + ".restored")
    target.parent.mkdir(parents=True, exist_ok=True)
    src = config.QUARANTINE_DIR / f"{qid}.qz"
    if item.get("format") == FORMAT:
        _decrypt_file(src, target, qid.encode())
    else:                                    # legacy XOR items (key stored in the index)
        _xor_stream(src, target, bytes.fromhex(item["key"]))
    delete(qid)
    return target


def delete(qid: str):
    idx = _load()
    (config.QUARANTINE_DIR / f"{qid}.qz").unlink(missing_ok=True)
    idx.pop(qid, None)
    _save(idx)
