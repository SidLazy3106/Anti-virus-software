"""URL risk analysis (mirrors browser_extension/analyzer.js so both give the same verdicts)."""
from __future__ import annotations

import ipaddress
import re
from dataclasses import dataclass, field
from functools import lru_cache
from urllib.parse import urlsplit

from . import config

BRANDS = ["google", "microsoft", "paypal", "amazon", "facebook", "instagram", "netflix", "github",
          "apple", "icloud", "outlook", "whatsapp", "linkedin", "dropbox", "binance", "coinbase",
          "paytm", "phonepe", "flipkart", "hdfcbank", "icicibank", "sbi"]
# Genuine registered domains that legitimately contain brand names (extend or replace with a Tranco top-sites list).
OFFICIAL = {"google.com", "googleapis.com", "gstatic.com", "googlevideo.com", "googleusercontent.com",
            "microsoft.com", "microsoftonline.com", "live.com", "office.com", "windows.net", "paypal.com",
            "amazon.com", "amazon.in", "amazonaws.com", "facebook.com", "fbcdn.net", "instagram.com",
            "netflix.com", "github.com", "githubusercontent.com", "apple.com", "icloud.com", "whatsapp.com",
            "linkedin.com", "dropbox.com", "binance.com", "coinbase.com", "paytm.com", "phonepe.com",
            "flipkart.com", "hdfcbank.com", "icicibank.com", "sbi.co.in"}
RISKY_TLDS = {"zip", "mov", "top", "xyz", "click", "tk", "ml", "ga", "cf", "gq", "work", "country",
              "kim", "loan", "men", "icu", "cyou"}
KEYWORDS = ["login", "signin", "verify", "secure", "account", "update", "wallet", "password",
            "billing", "confirm", "suspend"]
MULTI = {"co.uk", "com.au", "co.in", "org.in", "net.in", "ac.in", "gov.in", "co.jp", "com.br", "co.za"}
LEET = str.maketrans({"0": "o", "1": "l", "3": "e", "5": "s", "@": "a"})


@dataclass
class UrlVerdict:
    url: str
    score: int = 0
    verdict: str = "clean"
    reasons: list = field(default_factory=list)


@lru_cache(maxsize=1)
def _bad_domains() -> frozenset:
    out = set()
    for d in (config.SIGNATURES_DIR, config.UPDATED_SIGS_DIR):
        f = d / "bad_domains.txt"
        if f.is_file():
            for line in f.read_text(errors="ignore").splitlines():
                line = line.strip().lower()
                if line and not line.startswith("#"):
                    out.add(line)
    return frozenset(out)


def registered_domain(host: str) -> str:
    labels = host.split(".")
    if len(labels) >= 3 and ".".join(labels[-2:]) in MULTI:
        return ".".join(labels[-3:])
    return ".".join(labels[-2:]) if len(labels) >= 2 else host


def levenshtein(a: str, b: str) -> int:
    prev = list(range(len(b) + 1))
    for i, ca in enumerate(a, 1):
        cur = [i]
        for j, cb in enumerate(b, 1):
            cur.append(min(prev[j] + 1, cur[j - 1] + 1, prev[j - 1] + (ca != cb)))
        prev = cur
    return prev[-1]


def analyze_url(url: str) -> UrlVerdict:
    v = UrlVerdict(url)

    def add(points, why):
        v.score += points
        v.reasons.append(why)

    u = url.strip()
    if "://" not in u:
        u = "http://" + u
    try:
        parts = urlsplit(u)
        host = (parts.hostname or "").lower().rstrip(".")
    except ValueError:
        v.score, v.verdict, v.reasons = 50, "suspicious", ["Malformed URL"]
        return v
    if not host:
        v.score, v.verdict, v.reasons = 50, "suspicious", ["No hostname"]
        return v

    if any(host == d or host.endswith("." + d) for d in _bad_domains()):
        add(100, "Domain is on the known-malicious list")

    try:
        ipaddress.ip_address(host)
        is_ip = True
        add(30, "Uses a raw IP address instead of a domain name")
    except ValueError:
        is_ip = False
    if "@" in parts.netloc:
        add(40, "Contains '@' in the address (hides the real destination)")
    if "xn--" in host:
        add(25, "Punycode domain (possible look-alike characters)")

    path_l = (parts.path or "").lower()
    reg = host
    if not is_ip:
        labels = host.split(".")
        reg = registered_domain(host)
        reg_label, tld = reg.split(".")[0], labels[-1]
        if tld in RISKY_TLDS:
            add(15, f"Uncommon TLD .{tld} often used in abuse")
        if len(labels) - len(reg.split(".")) >= 3:
            add(15, "Excessive number of subdomains")
        if host.count("-") >= 3:
            add(10, "Many hyphens in the domain")
        if reg not in OFFICIAL:
            norm = reg_label.translate(LEET)
            sub_part = host[: -len(reg)] if host.endswith(reg) else ""
            for b in BRANDS:
                if reg_label == b:
                    if tld in RISKY_TLDS:
                        add(30, f"Brand name '{b}' on an unofficial domain")
                        break
                    continue
                if norm == b:
                    add(50, f"Look-alike of '{b}' using swapped characters")
                    break
                if b in norm:
                    add(30, f"Contains the brand name '{b}' but is not the official domain")
                    break
                if len(b) >= 6 and 0 < levenshtein(reg_label, b) <= 2 and abs(len(reg_label) - len(b)) <= 2:
                    add(45, f"Domain is one or two letters away from '{b}'")
                    break
                if b in sub_part:
                    add(40, f"Brand name '{b}' used as a subdomain of another site")
                    break

    hits = [k for k in KEYWORDS if k in host or k in path_l]
    if hits and reg not in OFFICIAL:
        add(10 if len(hits) == 1 else 15, f"Sensitive keywords: {', '.join(hits[:4])}")
        if parts.scheme == "http":
            add(10, "Sensitive page served over unencrypted HTTP")
    if len(u) > 120:
        add(10, "Very long URL")

    v.score = min(v.score, 100)
    v.verdict = ("malicious" if v.score >= config.MALICIOUS_THRESHOLD
                 else "suspicious" if v.score >= config.SUSPICIOUS_THRESHOLD else "clean")
    return v
