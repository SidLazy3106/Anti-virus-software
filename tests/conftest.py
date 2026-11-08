"""Test environment: all X-Secure data and every temp file live in throw-away folders.

This file is imported by pytest before any test module, so XSECURE_HOME is set before `sentinel` is first imported.
"""
import os
import shutil
import tempfile

import pytest

_HOME = tempfile.mkdtemp(prefix="sentinel_test_home_")
os.environ["XSECURE_HOME"] = _HOME
# Every temp file/folder the tests create goes under _TMP, which is deleted when the session finishes, so test
# samples (fake malware scripts, double-extension files) are never left behind in the real Temp folder
# (a sibling of _HOME, not inside it: the temp cleaner deliberately never touches X-Secure's own data folder).
_TMP = tempfile.mkdtemp(prefix="sentinel_test_tmp_")
tempfile.tempdir = _TMP


@pytest.fixture(scope="session", autouse=True)
def _cleanup_test_folders():
    yield
    from tests import gui_support, tk_support
    gui_support.close_shared_app()
    tk_support.close_shared_root()
    tempfile.tempdir = None
    from sentinel import logger
    logger.close()
    shutil.rmtree(_TMP, ignore_errors=True)
    shutil.rmtree(_HOME, ignore_errors=True)
