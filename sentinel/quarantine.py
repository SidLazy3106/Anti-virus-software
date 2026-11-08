"""Quarantine store.

Files are moved into ~/.x-secure/quarantine as <id>.qz and ENCRYPTED with Windows DPAPI (CryptProtectData:
AES-256 with an integrity check, keyed to your Windows account). No key is stored in the quarantine folder, so a
copied quarantine folder (or another Windows user) cannot open the files, and a modified file fails to decrypt
instead of being restored corrupted. Each file is bound to its quarantine id, so blobs can't be swapped.

Limits: anything running as *you* can still ask Windows to decrypt (that needs a SYSTEM service to fix).
Older items stored with the previous XOR format (key in index.json) are still restored correctly, but nothing new
is ever written in that format: without Windows DPAPI there is no trustworthy encryption available here, so
quarantining is refused (the file is left where it is) rather than hidden behind obfuscation.

The index is shared state, so every read-modify-write holds a cross-process file lock, and an unreadable index is
set aside (index.corrupt-<time>.json) instead of being silently replaced by an empty one.
"""
from __future__ import annotations

import contextlib
import ctypes
import json
import os
import struct
import time
import uuid
from pathlib import Path

from . import config, logger
from .platform_utils import IS_WIN
from .winconst import CRYPTPROTECT_UI_FORBIDDEN

KEY_LEN = 32
CHUNK = 1 << 20          # multiple of KEY_LEN so the legacy XOR key stream stays aligned
ENC_CHUNK = 4 << 20      # plaintext bytes per DPAPI blob
MAGIC = b"XSQ2"          # file header of the encrypted format
FORMAT = "dpapi-v1"
LOCK_POLL_SECONDS = 0.05


class QuarantineError(OSError):
    """Quarantine could not do what was asked. An OSError, so existing `except OSError` handlers still apply."""


class ItemNotFoundError(QuarantineError):
    """No quarantined item has that id."""


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
    flags = CRYPTPROTECT_UI_FORBIDDEN
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
    """Legacy format (obfuscation only); kept only to restore old items."""
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
    except FileNotFoundError:
        return {}
    except OSError:
        return {}
    except ValueError:                       # damaged JSON: keep it for inspection instead of overwriting it later
        damaged = _index_file().with_name(f"index.corrupt-{int(time.time())}.json")
        try:
            os.replace(_index_file(), damaged)
            logger.get().warning("quarantine index was unreadable; moved to %s", damaged.name)
        except OSError:
            pass
        return {}


@contextlib.contextmanager
def _locked(timeout: float = config.QUARANTINE_LOCK_TIMEOUT_SECONDS):
    """Cross-process lock for index read-modify-write cycles (the GUI, the CLI and the monitor can all quarantine)."""
    config.ensure_dirs()
    with open(config.QUARANTINE_DIR / "index.lock", "a+b") as fh:
        if fh.tell() == 0 and os.path.getsize(fh.name) == 0:
            fh.write(b"0")
            fh.flush()
        deadline = time.monotonic() + timeout
        while True:
            try:
                _lock_file(fh)
                break
            except OSError as e:
                if time.monotonic() >= deadline:
                    raise QuarantineError("the quarantine index is busy (another X-Secure task is using it)") from e
                time.sleep(LOCK_POLL_SECONDS)
        try:
            yield
        finally:
            _unlock_file(fh)


if IS_WIN:
    import msvcrt

    def _lock_file(fh):
        fh.seek(0)
        msvcrt.locking(fh.fileno(), msvcrt.LK_NBLCK, 1)

    def _unlock_file(fh):
        fh.seek(0)
        msvcrt.locking(fh.fileno(), msvcrt.LK_UNLCK, 1)
else:  # pragma: no cover - exercised only off Windows
    import fcntl

    def _lock_file(fh):
        fcntl.flock(fh.fileno(), fcntl.LOCK_EX | fcntl.LOCK_NB)

    def _unlock_file(fh):
        fcntl.flock(fh.fileno(), fcntl.LOCK_UN)


def _save(idx: dict):
    config.ensure_dirs()
    tmp = _index_file().with_suffix(".tmp")
    tmp.write_text(json.dumps(idx, indent=2))
    os.replace(tmp, _index_file())


# ── public API ───────────────────────────────────────────────────────────
def quarantine_file(path, reason: str = "", sha256: str = "") -> str:
    """Encrypt `path` into the quarantine store and remove the original. Returns the quarantine id."""
    if not available():
        raise QuarantineError("Quarantine needs Windows data protection (DPAPI); the file was left untouched.")
    config.ensure_dirs()
    src = Path(path).resolve()
    qid = uuid.uuid4().hex
    dst = config.QUARANTINE_DIR / f"{qid}.qz"
    entry = {"original_path": str(src), "sha256": sha256, "reason": reason, "time": time.time(), "format": FORMAT}
    try:
        _encrypt_file(src, dst, qid.encode())
        os.remove(src)
    except Exception:
        dst.unlink(missing_ok=True)  # encryption failed or file in use: leave the original untouched
        raise
    entry["size"] = dst.stat().st_size
    with _locked():
        idx = _load()
        idx[qid] = entry
        _save(idx)
    return qid


def list_items() -> list[dict]:
    return [dict(v, id=k) for k, v in sorted(_load().items(), key=lambda kv: kv[1]["time"], reverse=True)]


def restore(qid: str, dest=None) -> Path:
    """Decrypt an item back to `dest` (default: where it came from; `.restored` is added if that name is taken)."""
    with _locked():
        item = _load().get(qid)
        if item is None:
            raise ItemNotFoundError(f"There is no quarantined item with id {qid}.")
        target = Path(dest or item["original_path"])
        if target.exists():
            target = target.with_name(target.name + ".restored")
        target.parent.mkdir(parents=True, exist_ok=True)
        src = config.QUARANTINE_DIR / f"{qid}.qz"
        if item.get("format") == FORMAT:
            _decrypt_file(src, target, qid.encode())
        else:                                    # legacy XOR items (key stored in the index)
            _xor_stream(src, target, bytes.fromhex(item["key"]))
        _delete_unlocked(qid)
    return target


def _delete_unlocked(qid: str):
    idx = _load()
    (config.QUARANTINE_DIR / f"{qid}.qz").unlink(missing_ok=True)
    idx.pop(qid, None)
    _save(idx)


def delete(qid: str):
    with _locked():
        _delete_unlocked(qid)
