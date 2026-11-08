"""Central configuration and paths for X-Secure."""
import os
from pathlib import Path

APP_NAME = "X-Secure"
VERSION = "1.0.0"

# User data lives under ~/.x-secure (or XSECURE_HOME)
DATA_DIR = Path(os.environ.get("XSECURE_HOME")
                or os.environ.get("SENTINEL_HOME")
                or Path.home() / ".x-secure")
QUARANTINE_DIR = DATA_DIR / "quarantine"
UPDATED_SIGS_DIR = DATA_DIR / "signatures"
LOG_FILE = DATA_DIR / "x-secure.log"
ALLOWLIST_FILE = DATA_DIR / "allowlist.txt"   # SHA-256 hashes of files you trust

PKG_DIR = Path(__file__).resolve().parent
SIGNATURES_DIR = PKG_DIR / "signatures"
RULES_DIR = PKG_DIR / "rules"

MAX_HEURISTIC_SIZE = 100 * 1024 * 1024   # hash only above this size
ENTROPY_SAMPLE = 1024 * 1024             # bytes used for entropy
SUSPICIOUS_THRESHOLD = 35
MALICIOUS_THRESHOLD = 70


def ensure_dirs():
    for d in (DATA_DIR, QUARANTINE_DIR, UPDATED_SIGS_DIR):
        d.mkdir(parents=True, exist_ok=True)
