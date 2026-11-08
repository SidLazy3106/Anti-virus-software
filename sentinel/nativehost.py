"""Native Messaging bridge: lets the browser extension hand finished downloads to the desktop scanner.

Protocol (Chrome/Edge native messaging): every message is a 4-byte little-endian length followed by UTF-8 JSON,
over stdin/stdout. The browser starts this host on demand and only for extension ids listed in the host manifest.

Requests:  {"type": "ping"}                       -> {"ok": true, "app": "X-Secure", "version": ...}
           {"type": "scan", "path": "C:\\...\\f"}  -> {"ok": true, "verdict", "score", "reasons", "sha256", "name"}
The host only READS files (scan), never opens, runs, moves or deletes anything, and rejects anything that is not
an existing regular file given by absolute path.

Install for your browser (needs the extension id from chrome://extensions or edge://extensions):
    python main.py nativehost install --extension-id <id>
"""
from __future__ import annotations

import json
import os
import struct
import sys
from pathlib import Path
from typing import Optional

from . import config
from .platform_utils import IS_WIN

HOST_NAME = config.NATIVE_HOST_NAME
MAX_MESSAGE = config.NATIVE_MAX_MESSAGE_BYTES
REG_KEYS = {
    "chrome": r"Software\Google\Chrome\NativeMessagingHosts",
    "edge": r"Software\Microsoft\Edge\NativeMessagingHosts",
}


# ── protocol ─────────────────────────────────────────────────────────────
def read_message(stream):
    head = stream.read(4)
    if len(head) < 4:
        return None                    # browser closed the pipe
    (n,) = struct.unpack("<I", head)
    if n > MAX_MESSAGE:
        raise ValueError("message too large")
    body = stream.read(n)
    if len(body) != n:
        return None
    return json.loads(body.decode("utf-8"))


def write_message(stream, obj):
    data = json.dumps(obj).encode("utf-8")
    stream.write(struct.pack("<I", len(data)) + data)
    stream.flush()


_scanner = None


def handle(msg) -> dict:
    global _scanner
    if not isinstance(msg, dict):
        return {"ok": False, "error": "bad request"}
    kind = msg.get("type")
    if kind == "ping":
        return {"ok": True, "app": config.APP_NAME, "version": config.VERSION}
    if kind == "scan":
        raw = msg.get("path")
        if not isinstance(raw, str) or not raw:
            return {"ok": False, "error": "no path given"}
        p = Path(raw)
        if not p.is_absolute():
            return {"ok": False, "error": "path must be absolute"}
        try:
            if not p.is_file() or p.is_symlink():
                return {"ok": False, "error": "not a regular file"}
        except OSError as e:
            return {"ok": False, "error": str(e)}
        from .scanner import Scanner
        _scanner = _scanner or Scanner()
        r = _scanner.scan_file(p)
        return {"ok": True, "name": p.name, "verdict": r.verdict, "score": r.score, "reasons": r.reasons,
                "sha256": r.sha256}
    return {"ok": False, "error": f"unknown request type: {kind!r}"}


def serve(stdin=None, stdout=None) -> int:
    """Answer requests until the browser closes the pipe."""
    if IS_WIN and stdin is None:
        import msvcrt
        msvcrt.setmode(sys.stdin.fileno(), os.O_BINARY)
        msvcrt.setmode(sys.stdout.fileno(), os.O_BINARY)
    stdin = stdin or sys.stdin.buffer
    stdout = stdout or sys.stdout.buffer
    while True:
        try:
            msg = read_message(stdin)
        except (ValueError, json.JSONDecodeError) as e:
            write_message(stdout, {"ok": False, "error": f"bad message: {e}"})
            return 1
        if msg is None:
            return 0
        try:
            reply = handle(msg)
        except Exception as e:  # never crash the pipe on one bad file
            reply = {"ok": False, "error": f"{type(e).__name__}: {e}"}
        write_message(stdout, reply)


# ── installation ─────────────────────────────────────────────────────────
def host_dir() -> Path:
    return config.DATA_DIR / "native"


def launcher_text() -> str:
    """A .bat the browser can start (it must be an executable path; arguments come from the browser)."""
    if getattr(sys, "frozen", False):          # packaged: use the console build, which has real stdin/stdout
        cli = Path(sys.executable).with_name("x-secure-cli.exe")
        return f'@echo off\r\n"{cli if cli.exists() else sys.executable}" nativehost serve\r\n'
    main = Path(__file__).resolve().parent.parent / "main.py"
    return f'@echo off\r\n"{sys.executable}" -u "{main}" nativehost serve\r\n'


def manifest(launcher: Path, extension_ids: list[str]) -> dict:
    return {"name": HOST_NAME, "description": "X-Secure desktop scanner for downloads",
            "path": str(launcher), "type": "stdio",
            "allowed_origins": [f"chrome-extension://{i}/" for i in extension_ids]}


def valid_extension_id(ext_id: str) -> bool:
    return len(ext_id) == 32 and all("a" <= c <= "p" for c in ext_id)   # Chrome ids use the letters a-p


def install(extension_ids: list[str], browsers=("chrome", "edge"), reg_base: str | None = None) -> list[tuple[str, str]]:
    """Write the launcher + manifest and register them (HKCU only, no admin). Returns [(browser, key path)].
    reg_base overrides the registry location (used by the tests)."""
    ids = [i.strip().lower() for i in extension_ids]
    bad = [i for i in ids if not valid_extension_id(i)]
    if not ids or bad:
        raise ValueError(f"not a valid extension id: {', '.join(bad) or '(none)'} (32 letters a-p)")
    import winreg
    d = host_dir()
    d.mkdir(parents=True, exist_ok=True)
    launcher = d / "xsecure_host.bat"
    launcher.write_text(launcher_text(), encoding="utf-8", newline="")
    man = d / f"{HOST_NAME}.json"
    man.write_text(json.dumps(manifest(launcher, ids), indent=2), encoding="utf-8")
    done = []
    for b in browsers:
        key = (reg_base or REG_KEYS[b]) + "\\" + HOST_NAME
        with winreg.CreateKey(winreg.HKEY_CURRENT_USER, key) as k:
            winreg.SetValueEx(k, "", 0, winreg.REG_SZ, str(man))
        done.append((b, key))
    return done


def uninstall(browsers=("chrome", "edge"), reg_base: str | None = None) -> list[str]:
    import winreg
    removed = []
    for b in browsers:
        key = (reg_base or REG_KEYS[b]) + "\\" + HOST_NAME
        try:
            winreg.DeleteKey(winreg.HKEY_CURRENT_USER, key)
            removed.append(b)
        except OSError:
            pass
    for f in (host_dir() / f"{HOST_NAME}.json", host_dir() / "xsecure_host.bat"):
        f.unlink(missing_ok=True)
    return removed


def status(browsers=("chrome", "edge"), reg_base: str | None = None) -> dict[str, Optional[str]]:
    import winreg
    out = {}
    for b in browsers:
        try:
            with winreg.OpenKey(winreg.HKEY_CURRENT_USER, (reg_base or REG_KEYS[b]) + "\\" + HOST_NAME) as k:
                out[b] = winreg.QueryValueEx(k, "")[0]
        except OSError:
            out[b] = None
    return out
