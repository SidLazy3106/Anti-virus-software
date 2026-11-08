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
OFFICIAL = {"google.com", "gstatic.com", "googlevideo.com",
            "microsoft.com", "microsoftonline.com", "live.com", "office.com", "paypal.com",
            "amazon.com", "amazon.in", "facebook.com", "fbcdn.net", "instagram.com",
            "netflix.com", "github.com", "apple.com", "icloud.com", "whatsapp.com",
            "linkedin.com", "dropbox.com", "binance.com", "coinbase.com", "paytm.com", "phonepe.com",
            "flipkart.com", "hdfcbank.com", "icicibank.com", "sbi.co.in"}
RISKY_TLDS = {"zip", "mov", "top", "xyz", "click", "tk", "ml", "ga", "cf", "gq", "work", "country",
              "kim", "loan", "men", "icu", "cyou"}
KEYWORDS = ["login", "signin", "verify", "secure", "account", "update", "wallet", "password",
            "billing", "confirm", "suspend"]
MULTI = {"co.uk", "com.au", "co.in", "org.in", "net.in", "ac.in", "gov.in", "co.jp", "com.br", "co.za"}
LEET = str.maketrans({"0": "o", "1": "l", "3": "e", "5": "s", "@": "a"})
# Shared hosting / user-content platforms: anyone can publish here, so brand + keyword checks still apply.
USER_CONTENT = {"amazonaws.com", "googleapis.com", "googleusercontent.com", "githubusercontent.com", "windows.net",
                "appspot.com", "firebaseapp.com", "web.app", "github.io", "pages.dev", "workers.dev", "r2.dev",
                "netlify.app", "vercel.app", "herokuapp.com", "azurewebsites.net", "blogspot.com",
                "000webhostapp.com", "glitch.me", "wixsite.com", "weebly.com", "ngrok.io", "ngrok-free.app",
                "trycloudflare.com", "ipfs.io", "dweb.link"}
_IPV4_PART = re.compile(r"^(0x[0-9a-f]*|0[0-7]*|[1-9][0-9]*)$")


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


@lru_cache(maxsize=1)
def _psl():
    """ICANN section of the Public Suffix List (downloaded by `main.py update`), or None if not downloaded yet.
    The private section (s3.amazonaws.com, github.io...) is left out on purpose: shared-hosting platforms are
    handled by USER_CONTENT so brand checks keep applying there."""
    f = config.UPDATED_SIGS_DIR / "public_suffix_list.dat"
    try:
        text = f.read_text(encoding="utf-8")
    except OSError:
        return None
    rules, wild, exc = set(), set(), set()
    icann = False
    for line in text.splitlines():
        line = line.strip()
        if "===BEGIN ICANN DOMAINS===" in line:
            icann = True
        elif "===END ICANN DOMAINS===" in line:
            break
        if not icann or not line or line.startswith("//"):
            continue
        rule = line.split()[0].lower()
        try:
            rule = ".".join(p if p in ("*", "!") else p.encode("idna").decode("ascii") for p in rule.split("."))
        except UnicodeError:
            pass
        if rule.startswith("!"):
            exc.add(rule[1:])
        elif rule.startswith("*."):
            wild.add(rule[2:])
        else:
            rules.add(rule)
    return (rules, wild, exc) if len(rules) > 1000 else None


def registered_domain(host: str) -> str:
    """The domain someone actually registered (example.co.uk, not co.uk). Uses the Public Suffix List when it
    has been downloaded, otherwise a small built-in list of multi-part suffixes."""
    labels = host.split(".")
    psl = _psl()
    if psl and len(labels) >= 2:
        rules, wild, exc = psl
        suffix_len = 1
        for i in range(len(labels)):
            cand = ".".join(labels[i:])
            if cand in exc:                                   # exception rule: its parent is the suffix
                suffix_len = len(labels) - i - 1
                break
            if cand in rules or (i + 1 < len(labels) and ".".join(labels[i + 1:]) in wild):
                suffix_len = len(labels) - i
                break
        return ".".join(labels[-(suffix_len + 1):]) if len(labels) > suffix_len else host
    if len(labels) >= 3 and ".".join(labels[-2:]) in MULTI:
        return ".".join(labels[-3:])
    return ".".join(labels[-2:]) if len(labels) >= 2 else host


def parse_ipv4(host: str):
    """Parse IPv4 the way browsers do (3232235777, 0xC0A80001, 0300.0250.0.1 ...). Returns dotted form or None."""
    parts = host.split(".")
    if not 1 <= len(parts) <= 4 or not all(_IPV4_PART.match(x) for x in parts):
        return None
    nums = [int(x[2:] or "0", 16) if x.startswith("0x") else int(x, 8) if len(x) > 1 and x[0] == "0" else int(x)
            for x in parts]
    if any(n > 255 for n in nums[:-1]) or nums[-1] >= 256 ** (5 - len(nums)):
        return None
    value = nums[-1]
    for i, n in enumerate(nums[:-1]):
        value += n << (8 * (3 - i))
    return str(ipaddress.IPv4Address(value))


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
    if not host.isascii():  # browsers convert Unicode domains to punycode (xn--); do the same
        try:
            host = host.encode("idna").decode("ascii")
        except UnicodeError:
            pass

    bad = _bad_domains()
    host_labels = host.split(".")
    if any(".".join(host_labels[i:]) in bad for i in range(len(host_labels))):
        add(100, "Domain is on the known-malicious list")

    ip_text = None
    try:
        ipaddress.ip_address(host)
        is_ip = True
    except ValueError:
        ip_text = parse_ipv4(host)
        is_ip = ip_text is not None
    if is_ip:
        add(30, "Uses a raw IP address instead of a domain name")
        if ip_text and ip_text != host:
            add(25, "IP address written in a disguised form (decimal/hex/octal)")
            host = ip_text
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
        if reg in USER_CONTENT:
            tail = (host[: -len(reg)] if host.endswith(reg) else "") + path_l
            for b in BRANDS:
                if b not in reg and re.search(r"(^|[^a-z])" + b + r"([^a-z]|$)", tail):
                    add(35, f"Brand name '{b}' on a shared hosting site ({reg})")
                    break
        elif reg not in OFFICIAL:
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
