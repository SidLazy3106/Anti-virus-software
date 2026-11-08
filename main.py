"""X-Secure entry point.  python main.py [gui|scan|quickscan|fullscan|audit|url|monitor|update|allow|schedule|nativehost|benchmark]

All the work lives in sentinel/cli.py; this file only starts it (and enables parallel scanning in a PyInstaller .exe).
"""
import multiprocessing
import sys

from sentinel.cli import safe_main

if __name__ == "__main__":
    multiprocessing.freeze_support()  # required for parallel scanning in a PyInstaller .exe
    sys.exit(safe_main())
