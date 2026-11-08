# PyInstaller build for X-Secure.   Normal way to build:  python tools/build_release.py     (see BUILD.md)
# Direct:  python -m PyInstaller --noconfirm --clean xsecure.spec
# Output: dist\X-Secure\X-Secure.exe       windowed app (no console)  - also what scheduled scans run
#         dist\X-Secure\x-secure-cli.exe   command line               - also the browser native-messaging host
# The whole dist\X-Secure folder is the app; copy or zip it as one unit.
import os

ROOT = os.path.abspath(SPECPATH)
ICO = os.path.join(ROOT, "assets", "xsecure.ico")                  # made by tools/build_release.py
VERSION_FILE = os.path.join(ROOT, "build", "version_info.txt")     # made by tools/build_release.py
icon = ICO if os.path.exists(ICO) else os.path.join(ROOT, "browser_extension", "icons", "icon128.png")
version = VERSION_FILE if os.path.exists(VERSION_FILE) else None

a = Analysis(
    ["main.py"],
    pathex=["."],
    datas=[("sentinel/signatures", "sentinel/signatures"), ("sentinel/rules", "sentinel/rules"),
           ("sentinel/data", "sentinel/data")],
    hiddenimports=["PIL._tkinter_finder", "sentinel.gui", "sentinel.nativehost", "sentinel.benchmark",
                   "sentinel.schedule", "sentinel.updater", "sentinel.cli"],
    excludes=["pytest", "IPython", "matplotlib", "numpy", "coverage", "mypy"],
    noarchive=False,
)
pyz = PYZ(a.pure)

gui = EXE(pyz, a.scripts, [], exclude_binaries=True, name="X-Secure", console=False, icon=icon,
          version=version, upx=False)
cli = EXE(pyz, a.scripts, [], exclude_binaries=True, name="x-secure-cli", console=True, icon=icon,
          version=version, upx=False)

coll = COLLECT(gui, cli, a.binaries, a.datas, name="X-Secure", upx=False)
