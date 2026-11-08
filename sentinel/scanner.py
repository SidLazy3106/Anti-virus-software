"""Static scan engine: hashes, magic bytes, entropy, PE and script heuristics, optional YARA.

This is a heuristic engine. It will have false positives (installers, game cracks,
.NET apps, legitimate packers) and false negatives (anything novel). Treat verdicts
as signals, not proof.

Design: ``Scanner`` only identifies the file (hash, allowlist, EICAR) and then runs a list of independent ``Check``
objects (see ``sentinel/checks``). The signature verifier, the alternate-stream lister and the check list can all be
injected, so the scanner can be tested and extended without editing it.
"""
from __future__ import annotations

import hashlib
import os
from pathlib import Path
from typing import Callable, Iterator, Optional, Sequence

from . import ads, authenticode, config, logger
from .checks import Check, FileContext, default_checks
from .checks.yara_check import load_rules
from .platform_utils import norm_path
from .result import ScanResult
from .verdict import Verdict

CLEAN, SUSPICIOUS, MALICIOUS, ERROR = Verdict.CLEAN, Verdict.SUSPICIOUS, Verdict.MALICIOUS, Verdict.ERROR

EICAR_MARKER = b"EICAR-STANDARD-ANTIVIRUS-TEST-FILE!"
HASH_CHUNK = 1 << 20

SignatureVerifier = Callable[[str], bool]       # path -> "carries a valid digital signature"


class SignatureDB:
    """Known-bad SHA-256 hashes loaded from bundled and updated feed files."""

    def __init__(self, dirs=None):
        self.hashes: dict[str, str] = {}
        for d in dirs or (config.SIGNATURES_DIR, config.UPDATED_SIGS_DIR):
            d = Path(d)
            if not d.is_dir():
                continue
            for f in d.glob("hashes*.txt"):
                self._load(f)

    def _load(self, f: Path):
        try:
            lines = f.read_text(errors="ignore").splitlines()
        except OSError:
            return
        for line in lines:
            line = line.strip()
            if not line or line.startswith("#"):
                continue
            parts = line.split(None, 1)
            h = parts[0].lower()
            if len(h) == 64 and all(c in "0123456789abcdef" for c in h):
                self.hashes[h] = parts[1] if len(parts) > 1 else "Known malware hash"


def _hash_and_sample(path: Path):
    h = hashlib.sha256()
    sample = b""
    with open(path, "rb") as f:
        while True:
            chunk = f.read(HASH_CHUNK)
            if not chunk:
                break
            if len(sample) < config.ENTROPY_SAMPLE:
                sample += chunk[: config.ENTROPY_SAMPLE - len(sample)]
            h.update(chunk)
    return h.hexdigest(), sample


class Scanner:
    def __init__(self, db: Optional[SignatureDB] = None, log: bool = True,
                 checks: Optional[Sequence[Check]] = None,
                 signature_verifier: SignatureVerifier = authenticode.has_valid_signature,
                 stream_lister: Callable[[Path], list] = ads.suspicious_streams,
                 allowlist: Optional[set] = None):
        self.db = db or SignatureDB()
        self.log = log  # ScanEngine logs centrally, so its worker processes pass log=False
        self.allow = allowlist if allowlist is not None else self._load_allowlist()
        self.verify_signature = signature_verifier
        self.rules = load_rules(log) if checks is None else None
        self.checks: list[Check] = (list(checks) if checks is not None
                                    else default_checks(self.rules, self.scan_file, stream_lister))

    def scan_file(self, path) -> ScanResult:
        p = Path(path)
        res = ScanResult(path=str(p))
        try:
            size = p.stat().st_size
            res.sha256, sample = _hash_and_sample(p)
        except OSError as e:
            res.verdict = ERROR
            res.reasons.append(f"Could not read file: {e}")
            return res

        known_bad = self.db.hashes.get(res.sha256)
        if not known_bad and res.sha256 in self.allow:
            res.finalize()  # user-trusted file (known-bad hashes always win over the allowlist)
            return res
        if known_bad:
            res.add(100, f"Known malware hash: {known_bad}")
        if size <= config.EICAR_MAX_SIZE and EICAR_MARKER in sample:
            res.add(100, "EICAR antivirus test file")

        ctx = FileContext(p, size, sample, res, hard_hit=res.score >= 100)
        self._run_checks(ctx)
        self._apply_signature_discount(ctx)
        res.finalize()
        if self.log and res.verdict in (SUSPICIOUS, MALICIOUS):
            logger.get().warning("%s %s score=%d sha256=%s :: %s", res.verdict.upper(), res.path,
                                 res.score, res.sha256, "; ".join(res.reasons))
        return res

    def _run_checks(self, ctx: FileContext) -> None:
        for check in self.checks:
            if not check.applies(ctx):
                continue
            before = ctx.result.score
            check.run(ctx)
            if check.structural:
                ctx.structural_points += ctx.result.score - before

    def _apply_signature_discount(self, ctx: FileContext) -> None:
        """A valid Authenticode signature (verified offline by Windows) offsets program-structure heuristics such as
        packers, entropy or imports. It never offsets a double extension, scripts, ransomware signs or known-bad
        hashes, because signed tools can still be renamed or abused."""
        res = ctx.result
        if (ctx.is_pe and ctx.structural_points > 0 and not ctx.hard_hit and res.score >= config.SUSPICIOUS_THRESHOLD
                and self.verify_signature(str(ctx.path))):
            cut = min(ctx.structural_points, config.SIGNATURE_MAX_DISCOUNT)
            res.score -= cut
            res.reasons.append(f"Valid digital signature verified by Windows (risk lowered by {cut})")

    @staticmethod
    def _load_allowlist() -> set:
        try:
            lines = config.ALLOWLIST_FILE.read_text(errors="ignore").splitlines()
        except OSError:
            return set()
        out = set()
        for line in lines:
            parts = line.split()
            if parts and not parts[0].startswith("#") and len(parts[0]) == 64:
                out.add(parts[0].lower())
        return out

    def scan_tree(self, root, cancel=None) -> Iterator[ScanResult]:
        root = Path(root)
        if root.is_file():
            yield self.scan_file(root)
            return
        skip = {norm_path(config.QUARANTINE_DIR)}
        for dirpath, dirnames, filenames in os.walk(root, followlinks=False):
            dirnames[:] = [d for d in dirnames if norm_path(os.path.join(dirpath, d)) not in skip]
            for fn in filenames:
                if cancel is not None and cancel.is_set():
                    return
                fp = os.path.join(dirpath, fn)
                if os.path.islink(fp):
                    continue
                yield self.scan_file(fp)


def add_to_allowlist(sha256: str, note: str = ""):
    """Trust a file hash so the scanner stops flagging it (false-positive handling)."""
    config.ensure_dirs()
    with open(config.ALLOWLIST_FILE, "a", encoding="utf-8") as f:
        f.write(f"{sha256.lower()} {note}".rstrip() + "\n")
