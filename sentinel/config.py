"""Central configuration and paths for X-Secure.

Everything a maintainer might want to tune lives here (paths, thresholds, limits, timings, feed addresses), so the
rest of the code holds logic only. Windows API flag values are named in ``winconst.py``.

Naming note: the project was first called "Sentinel", which is why the Python package is still ``sentinel`` and why
the old ``SENTINEL_*`` environment variables are still understood (see ``ENV_*`` below). They are kept so existing
installs keep working after the rename to X-Secure.
"""
import os
from pathlib import Path

APP_NAME = "X-Secure"
VERSION = "1.0.0"
WINDOW_TITLE = f"{APP_NAME}  -  Antivirus & Security"
PUBLISHER = "X-Secure"

# ── environment variables (first name wins; the SENTINEL_* names are kept for installs that predate the rename) ──
ENV_HOME = ("XSECURE_HOME", "SENTINEL_HOME")
ENV_FEED_KEY = ("XSECURE_FEED_KEY", "SENTINEL_FEED_KEY")


def env_first(names, default=None):
    """The first of these environment variables that is set and non-empty."""
    for name in names:
        value = os.environ.get(name)
        if value:
            return value
    return default


# ── paths ────────────────────────────────────────────────────────────────
# User data lives under ~/.x-secure (or $XSECURE_HOME)
DATA_DIR = Path(env_first(ENV_HOME) or Path.home() / ".x-secure")
QUARANTINE_DIR = DATA_DIR / "quarantine"
UPDATED_SIGS_DIR = DATA_DIR / "signatures"
LOG_FILE = DATA_DIR / "x-secure.log"
ALLOWLIST_FILE = DATA_DIR / "allowlist.txt"   # SHA-256 hashes of files you trust

PKG_DIR = Path(__file__).resolve().parent
SIGNATURES_DIR = PKG_DIR / "signatures"
RULES_DIR = PKG_DIR / "rules"
URL_RULES_FILE = PKG_DIR / "data" / "url_rules.json"   # shared with the browser extension (see tools/)

# ── verdict thresholds (0-100 risk score) ────────────────────────────────
SUSPICIOUS_THRESHOLD = 35
MALICIOUS_THRESHOLD = 70

# ── file scanner limits ──────────────────────────────────────────────────
MAX_HEURISTIC_SIZE = 100 * 1024 * 1024   # hash only above this size
ENTROPY_SAMPLE = 1024 * 1024             # bytes used for entropy
SCRIPT_READ_LIMIT = 4 * 1024 * 1024      # scripts of any size are checked; only the first 4 MB is read
MAX_ZIP_ENTRIES = 5000                   # entries inspected per archive
ZIP_BOMB_TOTAL_BYTES = 1 << 30           # unpacked size that is suspicious on its own
ZIP_BOMB_MIN_BYTES = 100 << 20           # unpacked size above which the ratio check applies
ZIP_BOMB_RATIO = 200                     # unpacked / packed
ZIP_MEMBER_READ_CAP = 5 << 20            # largest archive member that is read into memory
EXE_ENTROPY_PACKED = 7.2                 # whole-file entropy (bits/byte) that suggests packing
SECTION_ENTROPY_PACKED = 7.4             # per-section entropy that suggests packing
SECTION_ENTROPY_MIN_BYTES = 4096
SECTION_ENTROPY_MAX_BYTES = 32 << 20     # pure-Python entropy: cap the section size measured
PADDING_TAIL_BYTES = 1 << 20             # tail read when checking for filler padding
PADDING_MAX_ENTROPY = 0.5
EICAR_MAX_SIZE = 256
MAX_STREAMS_SCANNED = 8                  # NTFS alternate data streams examined per file
SIGNATURE_MAX_DISCOUNT = 30              # most a valid Authenticode signature can lower a score

# ── scan engine ──────────────────────────────────────────────────────────
CACHE_MAX_AGE_SECONDS = 7 * 24 * 3600    # re-verify every file at least weekly
CACHE_FLUSH_EVERY = 500                  # buffered results written to SQLite in batches of this size
CACHE_DB_NAME = "scan_cache.sqlite"
MAX_SCAN_WORKERS = 8
IN_FLIGHT_PER_WORKER = 4                 # queued files per worker (keeps memory flat on huge drives)
# Locked or virtual system files: reading them only produces errors.
SKIPPED_FILE_NAMES = frozenset({"pagefile.sys", "hiberfil.sys", "swapfile.sys", "dumpstack.log.tmp"})

# ── real-time protection ─────────────────────────────────────────────────
RANSOM_WINDOW_SECONDS = 5.0              # file-change-rate window
RANSOM_MODIFIED_LIMIT = 60               # modified files inside the window that raises the alarm
RANSOM_ALERT_COOLDOWN_SECONDS = 30       # same alert is not repeated sooner than this
CANARY_NAMES = ("_xsecure_canary.docx", "_xsecure_canary.xlsx")
LEGACY_CANARY_NAMES = ("_sentinel_canary.docx", "_sentinel_canary.xlsx")   # left behind by pre-rename builds
CANARY_TEXT = "X-Secure canary file. Do not edit. If this changes, something is encrypting your files.\n"
IGNORED_DOWNLOAD_SUFFIXES = (".crdownload", ".part", ".partial", ".tmp", ".download")
FILE_STABLE_CHECKS = 20                  # size polls before giving up on a file that keeps growing
FILE_STABLE_INTERVAL_SECONDS = 0.5
PROCESS_POLL_SECONDS = 1.0

# ── threat feeds (updater) ───────────────────────────────────────────────
DOMAIN_FEEDS = {
    "urlhaus": ("URLhaus malware domains", "https://malware-filter.gitlab.io/malware-filter/urlhaus-filter-domains.txt"),
    "phishing_army": ("Phishing Army phishing domains", "https://phishing.army/download/phishing_army_blocklist.txt"),
}
HASH_API_URL = "https://mb-api.abuse.ch/api/v1/"
HASH_API_SIGNUP_URL = "https://auth.abuse.ch"
PSL_URL = "https://publicsuffix.org/list/public_suffix_list.dat"
FEED_TIMEOUT_SECONDS = 30
FEED_MIN_DOMAINS = 10                    # fewer usable lines than this = error page / format change
FEED_MIN_PSL_RULES = 1000

# ── scheduled scans ──────────────────────────────────────────────────────
SCHEDULER_TASK_NAME = r"X-Secure\Scheduled Scan"
SCHEDULER_DEFAULT_TIME = "13:00"
SCHEDULER_MAX_COMMAND_CHARS = 261        # Task Scheduler's limit for the program path + arguments
SCHEDULER_TIMEOUT_SECONDS = 30

# ── browser bridge ───────────────────────────────────────────────────────
NATIVE_HOST_NAME = "com.xsecure.scanner"
NATIVE_MAX_MESSAGE_BYTES = 1 << 20       # browser->host messages are tiny; refuse anything huge

# ── logging ──────────────────────────────────────────────────────────────
LOG_MAX_BYTES = 1_000_000
LOG_BACKUP_COUNT = 3

# ── benchmark ────────────────────────────────────────────────────────────
BENCHMARK_DEFAULT_LIMIT = 20000          # clean files scanned when measuring the false-positive rate

# ── quarantine ───────────────────────────────────────────────────────────
QUARANTINE_LOCK_TIMEOUT_SECONDS = 10     # how long to wait for another X-Secure process to release the index

# ── optimizer ────────────────────────────────────────────────────────────
TEMP_MAX_AGE_DAYS = 7                    # only temp files older than this are ever deleted
TEMP_SCAN_LIMIT = 400_000                # directory entries examined per temp scan
TEMP_ESTIMATE_TTL_SECONDS = 600          # a temp-folder estimate stays valid for 10 minutes


def ensure_dirs():
    for d in (DATA_DIR, QUARANTINE_DIR, UPDATED_SIGS_DIR):
        d.mkdir(parents=True, exist_ok=True)
