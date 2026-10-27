"""Threat-feed updater. Downloads public blocklists into ~/.sentinel/signatures/.

Check each feed's current terms and whether it now requires a free API/Auth key (abuse.ch has
been moving some endpoints behind keys). Set SENTINEL_FEED_KEY if a feed needs one.
"""
from __future__ import annotations

import os
import re
import urllib.request

from . import config

FEEDS = {
    "hashes_malwarebazaar.txt": ("https://bazaar.abuse.ch/export/txt/sha256/recent/", "hashes"),
    "bad_domains_urlhaus.txt": ("https://urlhaus.abuse.ch/downloads/hostfile/", "hosts"),
}
HEX64 = re.compile(r"^[0-9a-fA-F]{64}$")


def _fetch(url: str) -> str:
    req = urllib.request.Request(url, headers={"User-Agent": "Sentinel/0.1"})
    key = os.environ.get("SENTINEL_FEED_KEY")
    if key:
        req.add_header("Auth-Key", key)
    with urllib.request.urlopen(req, timeout=30) as r:
        return r.read().decode("utf-8", errors="ignore")


def update_feeds() -> dict:
    config.ensure_dirs()
    report = {}
    for fname, (url, kind) in FEEDS.items():
        try:
            lines = []
            for raw in _fetch(url).splitlines():
                raw = raw.strip()
                if not raw or raw.startswith("#"):
                    continue
                if kind == "hashes" and HEX64.match(raw):
                    lines.append(raw.lower())
                elif kind == "hosts":
                    parts = raw.split()
                    if len(parts) >= 2:
                        lines.append(parts[1].lower())
            # bad domains must live in a file named bad_domains*.txt; hashes in hashes*.txt
            target = config.UPDATED_SIGS_DIR / ("bad_domains.txt" if kind == "hosts" else fname)
            target.write_text("\n".join(lines) + "\n")
            report[fname] = f"{len(lines)} entries"
        except Exception as e:
            report[fname] = f"failed: {e}"
    return report
