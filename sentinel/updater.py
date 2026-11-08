"""Threat-feed updater. Downloads public blocklists into ~/.x-secure/signatures/.

Sources (checked working in Nov 2026; abuse.ch retired its old keyless export URLs, which now return 410 Gone):
* URLhaus malware domains, via the malware-filter project's mirror of the URLhaus database (updated ~2x/day)
* Phishing Army community phishing-domain blocklist (CC BY-NC 4.0: fine for this non-commercial project)
* MalwareBazaar recent SHA-256 hashes through the abuse.ch API, which needs a free Auth-Key
  (https://auth.abuse.ch). Set XSECURE_FEED_KEY (or the older SENTINEL_FEED_KEY) to enable it.

Each feed is stored in its own file, so one feed failing never wipes data from another, and a feed that returns
nothing usable (an error page, a format change) never replaces a working list.
"""
from __future__ import annotations

import json
import os
import re
import urllib.parse
import urllib.request

from . import config

DOMAIN_FEEDS = {
    "urlhaus": ("URLhaus malware domains", "https://malware-filter.gitlab.io/malware-filter/urlhaus-filter-domains.txt"),
    "phishing_army": ("Phishing Army phishing domains", "https://phishing.army/download/phishing_army_blocklist.txt"),
}
HASH_API = "https://mb-api.abuse.ch/api/v1/"
PSL_URL = "https://publicsuffix.org/list/public_suffix_list.dat"
PSL_LABEL = "Public Suffix List"
HASH_FILE = "hashes_malwarebazaar.txt"
HASH_LABEL = "MalwareBazaar malware hashes"
HEX64 = re.compile(r"^[0-9a-fA-F]{64}$")
DOMAIN = re.compile(r"^(?=.{4,253}$)([a-z0-9_](?:[a-z0-9_-]{0,61}[a-z0-9])?\.)+[a-z0-9-]{2,63}$")
UA = f"X-Secure/{getattr(config, 'VERSION', '1')} (threat-feed updater)"


def feed_key():
    return os.environ.get("XSECURE_FEED_KEY") or os.environ.get("SENTINEL_FEED_KEY")


def _fetch(url: str, data: dict | None = None, headers: dict | None = None) -> str:
    body = urllib.parse.urlencode(data).encode() if data else None
    req = urllib.request.Request(url, data=body, headers={"User-Agent": UA, **(headers or {})})
    with urllib.request.urlopen(req, timeout=30) as r:
        return r.read().decode("utf-8", errors="ignore")


def parse_domains(text: str) -> list:
    """One domain per line; also accepts hosts-file lines ('0.0.0.0 example.com'). Junk lines are dropped."""
    out = []
    for raw in text.splitlines():
        raw = raw.split("#", 1)[0].strip().lower()
        if not raw:
            continue
        parts = raw.split()
        cand = parts[1] if len(parts) >= 2 and parts[0] in ("0.0.0.0", "127.0.0.1") else parts[0]
        cand = cand.strip(".")
        if DOMAIN.match(cand) and cand not in ("localhost", "localhost.localdomain"):
            out.append(cand)
    return out


def parse_hashes(text: str) -> list:
    """MalwareBazaar API JSON ({"query_status": "ok", "data": [{"sha256_hash": ...}]})."""
    doc = json.loads(text)
    if doc.get("query_status") != "ok":
        raise ValueError(f"API answered '{doc.get('query_status')}'")
    return [d["sha256_hash"].lower() for d in doc.get("data") or [] if HEX64.match(d.get("sha256_hash") or "")]


def _feeds_dir():
    d = config.UPDATED_SIGS_DIR / "feeds"
    d.mkdir(parents=True, exist_ok=True)
    return d


def _rebuild_domain_list() -> int:
    """bad_domains.txt (what the web guard reads) = union of every feed's last good download."""
    merged = set()
    for f in _feeds_dir().glob("domains_*.txt"):
        merged.update(x for x in f.read_text(encoding="utf-8", errors="ignore").split() if x)
    if merged:
        (config.UPDATED_SIGS_DIR / "bad_domains.txt").write_text("\n".join(sorted(merged)) + "\n", encoding="utf-8")
    return len(merged)


def update_feeds() -> dict:
    """Returns {feed label: result text}. Never raises."""
    config.ensure_dirs()
    report = {}
    for slug, (label, url) in DOMAIN_FEEDS.items():
        try:
            doms = sorted(set(parse_domains(_fetch(url))))
            if len(doms) < 10:  # an error page or a format change, not a real list
                raise ValueError("feed returned no usable entries (format change or access denied); kept previous list")
            (_feeds_dir() / f"domains_{slug}.txt").write_text("\n".join(doms) + "\n", encoding="utf-8")
            report[label] = f"{len(doms):,} domains"
        except Exception as e:
            report[label] = f"failed: {e}"
    total = _rebuild_domain_list()
    report["Bad-domain list in use"] = f"{total:,} domains" if total else "empty (no feed has succeeded yet)"

    try:                                   # Public Suffix List: correct "registered domain" for every country TLD
        psl = _fetch(PSL_URL)
        rules = sum(1 for ln in psl.splitlines() if ln.strip() and not ln.startswith("//"))
        if "===BEGIN ICANN DOMAINS===" not in psl or rules < 1000:
            raise ValueError("unexpected content; kept previous list")
        (config.UPDATED_SIGS_DIR / "public_suffix_list.dat").write_text(psl, encoding="utf-8")
        report[PSL_LABEL] = f"{rules:,} rules"
    except Exception as e:
        report[PSL_LABEL] = f"failed: {e}"

    key = feed_key()
    if not key:
        report[HASH_LABEL] = ("skipped: MalwareBazaar needs a free Auth-Key from https://auth.abuse.ch; "
                              "set XSECURE_FEED_KEY to enable it")
    else:
        try:
            hashes = parse_hashes(_fetch(HASH_API, {"query": "get_recent", "selector": "time"}, {"Auth-Key": key}))
            if not hashes:
                raise ValueError("feed returned no entries; kept previous list")
            (config.UPDATED_SIGS_DIR / HASH_FILE).write_text("\n".join(hashes) + "\n")
            report[HASH_LABEL] = f"{len(hashes):,} hashes"
        except Exception as e:
            report[HASH_LABEL] = f"failed: {e}"

    from .webguard import _bad_domains, _psl
    _bad_domains.cache_clear()
    _psl.cache_clear()
    return report
