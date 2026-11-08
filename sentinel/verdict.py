"""The one definition of a verdict and of how a 0-100 risk score maps onto it."""
from __future__ import annotations

from enum import StrEnum

from . import config


class Verdict(StrEnum):
    """Outcome of scanning a file or checking a URL. A str subclass, so it compares equal to, and serialises as,
    its plain text value ("clean", "suspicious", "malicious", "error")."""
    CLEAN = "clean"
    SUSPICIOUS = "suspicious"
    MALICIOUS = "malicious"
    ERROR = "error"

    @classmethod
    def from_score(cls, score: int) -> "Verdict":
        if score >= config.MALICIOUS_THRESHOLD:
            return cls.MALICIOUS
        if score >= config.SUSPICIOUS_THRESHOLD:
            return cls.SUSPICIOUS
        return cls.CLEAN
