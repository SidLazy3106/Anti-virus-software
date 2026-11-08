"""Scan checks. Each one is a small class with the same two methods (see base.Check); the Scanner runs them in order.

To add a detection rule: write a Check subclass in the matching module and list it in ``default_checks``.
"""
from __future__ import annotations

from typing import Callable

from .. import ads
from .base import Check, FileContext
from .documents import ArchiveCheck, LegacyOfficeCheck
from .identity import DisguisedExecutableCheck, DoubleExtensionCheck, RansomwareNameCheck
from .pe import PeHeuristicsCheck
from .script import ScriptCheck
from .streams import AlternateStreamCheck
from .yara_check import YaraCheck

__all__ = ["Check", "FileContext", "default_checks"]


def default_checks(rules, scan_file: Callable, list_streams: Callable = ads.suspicious_streams) -> list[Check]:
    """The standard rule set, in the order it is applied (the order decides how reasons are listed)."""
    return [
        DisguisedExecutableCheck(),
        DoubleExtensionCheck(),
        RansomwareNameCheck(),
        PeHeuristicsCheck(),
        ScriptCheck(),
        ArchiveCheck(),
        LegacyOfficeCheck(),
        YaraCheck(rules),
        AlternateStreamCheck(scan_file, list_streams),
    ]
