"""NTFS alternate data streams: hidden streams are scanned like files."""
from __future__ import annotations

from pathlib import Path
from typing import Callable

from .. import ads, config
from ..result import ScanResult
from ..verdict import Verdict
from .base import Check, FileContext

ScanFile = Callable[[str], ScanResult]
StreamLister = Callable[[Path], list[tuple[str, int]]]


class AlternateStreamCheck(Check):
    name = "alternate-streams"

    def __init__(self, scan_file: ScanFile, list_streams: StreamLister = ads.suspicious_streams,
                 enabled: bool = ads.IS_WIN):
        self.scan_file, self.list_streams, self.enabled = scan_file, list_streams, enabled

    def applies(self, ctx: FileContext) -> bool:
        return self.enabled and ":" not in ctx.path.name      # never recurse into a stream's streams

    def run(self, ctx: FileContext) -> None:
        for sname, _size in self.list_streams(ctx.path)[:config.MAX_STREAMS_SCANNED]:
            self._check_stream(ctx.path, sname, ctx.result)

    def _check_stream(self, p: Path, sname: str, res: ScanResult) -> None:
        """Scan one hidden stream like a file. A program hidden in a stream is a strong sign by itself."""
        spath = f"{p}:{sname}"
        try:
            with open(spath, "rb") as f:
                head = f.read(4)
        except OSError:
            return
        sub = self.scan_file(spath)
        hidden_program = head[:2] == b"MZ"
        pts = (50 if hidden_program else 0) + (sub.score if sub.verdict != Verdict.ERROR else 0)
        if pts >= 20:
            what = "a hidden program" if hidden_program else "hidden risky content"
            detail = ("; ".join(sub.reasons[:2])) if sub.reasons else ""
            res.add(min(pts, 100), f"Alternate data stream ':{sname}' holds {what}" + (f" ({detail})" if detail else ""))
