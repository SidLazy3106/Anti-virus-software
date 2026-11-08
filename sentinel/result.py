"""What a scan produces: a risk score, a verdict and the reasons behind it."""
from __future__ import annotations

from dataclasses import dataclass, field

from .verdict import Verdict


@dataclass
class ScanResult:
    path: str
    verdict: Verdict = Verdict.CLEAN
    score: int = 0
    sha256: str = ""
    reasons: list[str] = field(default_factory=list)

    def add(self, points: int, reason: str):
        self.score += points
        self.reasons.append(reason)

    def finalize(self):
        self.score = min(self.score, 100)
        if self.verdict == Verdict.ERROR:
            return
        self.verdict = Verdict.from_score(self.score)
