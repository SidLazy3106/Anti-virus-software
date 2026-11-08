"""Loader for the shared URL/file-name risk rules (sentinel/data/url_rules.json).

The same JSON feeds the browser extension and the website (through the generated url_rules.js), so the lists of
brands, official domains, risky TLDs and so on are written down exactly once.
"""
from __future__ import annotations

import json
from functools import lru_cache

from . import config


@lru_cache(maxsize=1)
def load() -> dict:
    """The rules dictionary. Raises OSError/ValueError if the bundled file is missing or damaged."""
    return json.loads(config.URL_RULES_FILE.read_text(encoding="utf-8"))
