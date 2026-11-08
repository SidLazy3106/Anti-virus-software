# PyInstaller build for X-Secure.   Build:  py -m PyInstaller --noconfirm --clean xsecure.spec
# Output: dist\X-Secure\X-Secure.exe       windowed app (no console)  - also what scheduled scans run
#         dist\X-Secure\x-secure-cli.exe   command line               - also the browser native-messaging host
# The whole dist\X-Secure folder is the app; copy or zip it as one unit.

a = Analysis(
    ["main.py"],
    pathex=["."],
    datas=[("sentinel/signatures", "sentinel/signatures"), ("sentinel/rules", "sentinel/rules")],
    hiddenimports=["PIL._tkinter_finder", "sentinel.gui", "sentinel.nativehost", "sentinel.benchmark",
                   "sentinel.schedule", "sentinel.updater"],
    excludes=["pytest", "IPython", "matplotlib", "numpy"],
    noarchive=False,
)
pyz = PYZ(a.pure)
icon = "browser_extension/icons/icon128.png"

gui = EXE(pyz, a.scripts, [], exclude_binaries=True, name="X-Secure", console=False, icon=icon,
          version=None, upx=False)
cli = EXE(pyz, a.scripts, [], exclude_binaries=True, name="x-secure-cli", console=True, icon=icon, upx=False)

coll = COLLECT(gui, cli, a.binaries, a.datas, name="X-Secure", upx=False)
