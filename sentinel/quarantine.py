"""Quarantine store.

Files are moved into ~/.sentinel/quarantine as <id>.qz, XOR-obfuscated with a random
per-file key so they cannot be executed or opened by accident. The key is stored in
index.json next to the data, so this is OBFUSCATION, not encryption. Anything that can
read the folder can recover the file. That is fine for safe handling; for real secrecy
use `cryptography` (Fernet/AES-GCM) with a key held elsewhere.
"""
from __future__ import annotations

import json
import os
import time
import uuid
from pathlib import Path

from . import config

KEY_LEN = 32
CHUNK = 1 << 20  # multiple of KEY_LEN so the key stream stays aligned


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


def _xor_stream(src, dst, key: bytes):
    stream = key * (CHUNK // KEY_LEN)
    with open(src, "rb") as fi, open(dst, "wb") as fo:
        while True:
            chunk = fi.read(CHUNK)
            if not chunk:
                break
            n = len(chunk)
            x = int.from_bytes(chunk, "big") ^ int.from_bytes(stream[:n], "big")
            fo.write(x.to_bytes(n, "big"))


def quarantine_file(path, reason: str = "", sha256: str = "") -> str:
    config.ensure_dirs()
    src = Path(path).resolve()
    qid = uuid.uuid4().hex
    key = os.urandom(KEY_LEN)
    dst = config.QUARANTINE_DIR / f"{qid}.qz"
    _xor_stream(src, dst, key)
    try:
        os.remove(src)
    except OSError:
        dst.unlink(missing_ok=True)  # file in use: leave original untouched
        raise
    idx = _load()
    idx[qid] = {"original_path": str(src), "sha256": sha256, "reason": reason,
                "time": time.time(), "size": dst.stat().st_size, "key": key.hex()}
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
    _xor_stream(config.QUARANTINE_DIR / f"{qid}.qz", target, bytes.fromhex(item["key"]))
    delete(qid)
    return target


def delete(qid: str):
    idx = _load()
    (config.QUARANTINE_DIR / f"{qid}.qz").unlink(missing_ok=True)
    idx.pop(qid, None)
    _save(idx)
