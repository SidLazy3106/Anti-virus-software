"""Build the distributable Windows release of X-Secure.

    python tools/build_release.py                 build, smoke-test and package
    python tools/build_release.py --skip-tests    skip the unit-test run (faster; not for real releases)
    python tools/build_release.py --no-build      only repackage an existing dist/X-Secure

Steps: (1) run the tests, (2) make the icon and Windows version resource, (3) PyInstaller, (4) smoke-test the built
executables, (5) zip the portable app, (6) write release/release.json (version, file, size, SHA-256) and copy both to
docs/downloads/ so the website's download button points at the real file, (7) compile the installer if Inno Setup
is installed.
"""
from __future__ import annotations

import argparse
import hashlib
import json
import shutil
import subprocess
import sys
import tempfile
import time
import zipfile
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

from sentinel import config  # noqa: E402

DIST = ROOT / "dist" / "X-Secure"
RELEASE = ROOT / "release"
SITE_DOWNLOADS = ROOT / "docs" / "downloads"
ICON_PNG = ROOT / "browser_extension" / "icons" / "icon128.png"
ICON_ICO = ROOT / "assets" / "xsecure.ico"
VERSION_FILE = ROOT / "build" / "version_info.txt"
ISS = ROOT / "installer" / "xsecure.iss"
INNO_CANDIDATES = [Path(p) for p in (r"C:\Program Files (x86)\Inno Setup 6\ISCC.exe", r"C:\Program Files\Inno Setup 6\ISCC.exe")]


def say(msg: str) -> None:
    print(f"[build] {msg}", flush=True)


def run(cmd, **kw) -> subprocess.CompletedProcess:
    return subprocess.run([str(c) for c in cmd], cwd=ROOT, check=True, **kw)


def make_icon() -> Path:
    """Multi-size .ico from the 128 px PNG, so Explorer, the taskbar and the installer all get a sharp icon."""
    from PIL import Image
    ICON_ICO.parent.mkdir(exist_ok=True)
    Image.open(ICON_PNG).convert("RGBA").save(ICON_ICO, sizes=[(16, 16), (24, 24), (32, 32), (48, 48), (64, 64), (128, 128)])
    return ICON_ICO


def version_tuple(v: str) -> tuple:
    parts = [int(p) for p in v.split(".")[:4]]
    return tuple(parts + [0] * (4 - len(parts)))


def make_version_resource() -> Path:
    """The Windows 'Details' tab: product name, publisher, version (read by Explorer and SmartScreen)."""
    v = version_tuple(config.VERSION)
    text = f"""VSVersionInfo(
  ffi=FixedFileInfo(filevers={v}, prodvers={v}, mask=0x3f, flags=0x0, OS=0x40004, fileType=0x1, subtype=0x0, date=(0, 0)),
  kids=[
    StringFileInfo([StringTable('040904B0', [
      StringStruct('CompanyName', '{config.PUBLISHER}'),
      StringStruct('FileDescription', '{config.APP_NAME} antivirus and PC optimizer'),
      StringStruct('FileVersion', '{config.VERSION}'),
      StringStruct('InternalName', 'X-Secure'),
      StringStruct('LegalCopyright', 'MIT License'),
      StringStruct('OriginalFilename', 'X-Secure.exe'),
      StringStruct('ProductName', '{config.APP_NAME}'),
      StringStruct('ProductVersion', '{config.VERSION}')])]),
    VarFileInfo([VarStruct('Translation', [1033, 1200])])
  ])
"""
    VERSION_FILE.parent.mkdir(exist_ok=True)
    VERSION_FILE.write_text(text, encoding="utf-8")
    return VERSION_FILE


def smoke_test() -> None:
    """Run the BUILT executables, not the source: they must work without Python or the repository."""
    cli = DIST / "x-secure-cli.exe"
    gui = DIST / "X-Secure.exe"
    for exe in (cli, gui):
        if not exe.exists():
            raise SystemExit(f"missing build output: {exe}")
    home = Path(tempfile.mkdtemp(prefix="xsecure_smoke_"))
    env = {**__import__("os").environ, "XSECURE_HOME": str(home)}
    try:
        r = subprocess.run([str(cli), "url", "http://paypa1-secure-login.xyz/verify"], capture_output=True, text=True,
                           env=env, timeout=120, cwd=tempfile.gettempdir())
        if r.returncode != 1 or "MALICIOUS" not in r.stdout:
            raise SystemExit(f"cli url check failed: rc={r.returncode} out={r.stdout!r} err={r.stderr!r}")
        say("cli: URL check OK (flags the phishing sample)")
        sample = Path(tempfile.mkdtemp(prefix="xsecure_sample_"))      # outside the data folder, which scans exclude
        (sample / "fine.txt").write_text("hello")
        (sample / "bad.ps1").write_text("vssadmin delete shadows /all\nSet-MpPreference -DisableRealtimeMonitoring $true\n")
        r = subprocess.run([str(cli), "scan", str(sample), "--workers", "2", "--no-cache"], capture_output=True, text=True,
                           env=env, timeout=300, cwd=tempfile.gettempdir())
        if r.returncode != 1 or "MALICIOUS" not in r.stdout:
            raise SystemExit(f"cli scan failed: rc={r.returncode} out={r.stdout!r} err={r.stderr!r}")
        say("cli: parallel scan OK (worker processes start inside the packaged build)")
        proc = subprocess.Popen([str(gui)], env=env, cwd=tempfile.gettempdir())
        time.sleep(6)
        alive = proc.poll() is None
        second = subprocess.run([str(gui)], env=env, timeout=60, cwd=tempfile.gettempdir())
        proc.terminate()
        try:
            proc.wait(timeout=15)
        except subprocess.TimeoutExpired:
            proc.kill()
        if not alive:
            raise SystemExit("the GUI exited by itself during start-up (see the log in the data folder)")
        if second.returncode != 0:
            raise SystemExit(f"a second launch should exit quietly (single instance), got {second.returncode}")
        say("gui: window stays up, a second launch exits quietly (single instance)")
    finally:
        shutil.rmtree(sample, ignore_errors=True) if "sample" in locals() else None
        for log in home.glob("*.log"):
            text = log.read_text(encoding="utf-8", errors="replace")
            if "Traceback" in text or " ERROR " in text:
                raise SystemExit(f"errors in the application log {log}:\n{text[-1500:]}")
        shutil.rmtree(home, ignore_errors=True)


def package() -> dict:
    RELEASE.mkdir(exist_ok=True)
    name = f"X-Secure-{config.VERSION}-win64-portable.zip"
    out = RELEASE / name
    out.unlink(missing_ok=True)
    with zipfile.ZipFile(out, "w", zipfile.ZIP_DEFLATED, compresslevel=9) as z:
        for f in sorted(DIST.rglob("*")):
            if f.is_file():
                z.write(f, Path("X-Secure") / f.relative_to(DIST))
        z.write(ROOT / "LICENSE", "X-Secure/LICENSE.txt")
        if (ROOT / "BUILD.md").exists():
            z.write(ROOT / "BUILD.md", "X-Secure/README-BUILD.md")
    digest = hashlib.sha256(out.read_bytes()).hexdigest()
    info = {"version": config.VERSION, "file": name, "size": out.stat().st_size, "sha256": digest,
            "built": time.strftime("%Y-%m-%d"), "requires": "Windows 10 or Windows 11 (64-bit)"}
    return info


def build_installer(info: dict) -> None:
    iscc = next((p for p in INNO_CANDIDATES if p.exists()), None) or (Path(shutil.which("ISCC") or "") if shutil.which("ISCC") else None)
    if iscc is None:
        say("Inno Setup not found: installer NOT built (portable zip only). Install it from https://jrsoftware.org/isinfo.php "
            "and run this script again, or compile installer/xsecure.iss by hand.")
        return
    run([iscc, f"/DAppVersion={config.VERSION}", f"/DSourceDir={DIST}", f"/DOutputDir={RELEASE}", ISS])
    setup = RELEASE / f"X-Secure-{config.VERSION}-setup.exe"
    if setup.exists():
        info["installer"] = {"file": setup.name, "size": setup.stat().st_size,
                             "sha256": hashlib.sha256(setup.read_bytes()).hexdigest()}
        say(f"installer built: {setup}")


def main(argv=None) -> int:
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--skip-tests", action="store_true")
    ap.add_argument("--no-build", action="store_true")
    a = ap.parse_args(argv)
    if not a.skip_tests and not a.no_build:
        say("running the unit tests")
        run([sys.executable, "-m", "pytest"])
    if not a.no_build:
        say(f"icon -> {make_icon()}")
        say(f"version resource -> {make_version_resource()}")
        say("PyInstaller (a few minutes)")
        run([sys.executable, "-m", "PyInstaller", "--noconfirm", "--clean", ROOT / "xsecure.spec"])
    smoke_test()
    info = package()
    build_installer(info)
    (RELEASE / "release.json").write_text(json.dumps(info, indent=2) + "\n", encoding="utf-8")
    SITE_DOWNLOADS.mkdir(parents=True, exist_ok=True)
    shutil.copy2(RELEASE / info["file"], SITE_DOWNLOADS / info["file"])
    if "installer" in info:
        shutil.copy2(RELEASE / info["installer"]["file"], SITE_DOWNLOADS / info["installer"]["file"])
    (ROOT / "docs" / "release.json").write_text(json.dumps(info, indent=2) + "\n", encoding="utf-8")
    say(f"release ready: {RELEASE / info['file']}  ({info['size'] / 1048576:.1f} MB, sha256 {info['sha256'][:16]}...)")
    return 0


if __name__ == "__main__":
    sys.exit(main())
