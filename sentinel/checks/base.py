"""The contract every scan check follows, and the per-file context they share."""
from __future__ import annotations

from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from pathlib import Path

from ..result import ScanResult


@dataclass
class FileContext:
    """Everything a check may look at for one file. Checks add points to ``result``; they never raise for bad input."""
    path: Path
    size: int
    sample: bytes                       # first ENTROPY_SAMPLE bytes of the file
    result: ScanResult
    hard_hit: bool = False              # known-bad hash or EICAR: never softened by a signature
    structural_points: int = 0          # points from program-structure heuristics only (see Check.structural)
    ext: str = field(init=False)
    is_pe: bool = field(init=False)

    def __post_init__(self):
        self.ext = self.path.suffix.lower()
        self.is_pe = self.sample[:2] == b"MZ"


class Check(ABC):
    """One independent detection rule. New rules are added by writing a Check, not by editing the scanner."""
    name: str = ""
    structural: bool = False            # True: its points are program-structure signs a valid signature may offset

    @abstractmethod
    def applies(self, ctx: FileContext) -> bool:
        """Cheap test: is this check relevant for the file?"""

    @abstractmethod
    def run(self, ctx: FileContext) -> None:
        """Inspect the file and add points/reasons to ``ctx.result``."""
