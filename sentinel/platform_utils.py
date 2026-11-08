"""Small helpers shared by every module: platform detection, optional psutil, and path normalisation.

Keeping these in one place avoids re-declaring ``IS_WIN`` / ``_norm`` / the optional-import dance in each module.
"""
from __future__ import annotations

import os
import sys

try:
    import psutil
except ImportError:  # pragma: no cover - optional: features that need it degrade gracefully
    psutil = None

IS_WIN = sys.platform == "win32"


def norm_path(path) -> str:
    """Absolute, case-normalised form of a path, suitable as a dictionary key or for prefix comparisons."""
    return os.path.normcase(os.path.abspath(str(path)))
