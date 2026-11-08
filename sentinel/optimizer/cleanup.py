"""Old temporary files: estimate and delete (the one change that cannot be undone)."""
from __future__ import annotations

import os
import tempfile
import time
from pathlib import Path

from .. import config
from .. import logger
from .models import human


TEMP_MAX_AGE_DAYS = config.TEMP_MAX_AGE_DAYS


# ── temp files ───────────────────────────────────────────────────────────
def temp_roots() -> list[Path]:
    roots = {os.path.normcase(os.path.realpath(tempfile.gettempdir())): tempfile.gettempdir()}
    lad = os.environ.get("LOCALAPPDATA")
    if lad:
        p = os.path.join(lad, "Temp")
        roots.setdefault(os.path.normcase(os.path.realpath(p)), p)
    return [Path(p) for p in roots.values() if os.path.isdir(p)]


def _eligible_temp_files(roots, max_age_days=TEMP_MAX_AGE_DAYS, limit=config.TEMP_SCAN_LIMIT):
    cutoff = time.time() - max_age_days * 86400
    keep_out = os.path.normcase(os.path.realpath(str(config.DATA_DIR)))
    n = 0
    for root in roots:
        real_root = os.path.normcase(os.path.realpath(str(root)))
        stack = [str(root)]
        while stack:
            d = stack.pop()
            try:
                it = os.scandir(d)
            except OSError:
                continue
            with it:
                for e in it:
                    n += 1
                    if n > limit:
                        return
                    try:
                        if e.is_symlink():
                            continue
                        real = os.path.normcase(os.path.realpath(e.path))
                        if not real.startswith(real_root + os.sep) or real.startswith(keep_out):
                            continue
                        if e.is_dir(follow_symlinks=False):
                            stack.append(e.path)
                        elif e.is_file(follow_symlinks=False):
                            st = e.stat(follow_symlinks=False)
                            if st.st_mtime < cutoff:  # age by last modification only
                                yield e.path, st.st_size
                    except OSError:
                        continue


def estimate_temp(roots=None, max_age_days=TEMP_MAX_AGE_DAYS) -> tuple[int, int]:
    files = size = 0
    for _p, sz in _eligible_temp_files(roots or temp_roots(), max_age_days):
        files += 1
        size += sz
    return files, size


def clean_temp(roots=None, max_age_days=TEMP_MAX_AGE_DAYS, cancel=None) -> tuple[int, int, int]:
    """Delete eligible old temp files. Returns (deleted, bytes_freed, skipped). Cannot be undone."""
    deleted = freed = skipped = 0
    for path, sz in list(_eligible_temp_files(roots or temp_roots(), max_age_days)):
        if cancel is not None and cancel.is_set():
            break
        try:
            os.remove(path)
            deleted += 1
            freed += sz
        except OSError:  # in use or protected: leave it
            skipped += 1
    logger.get().info("optimizer: cleaned %d temp files, freed %s, skipped %d", deleted, human(freed), skipped)
    return deleted, freed, skipped
