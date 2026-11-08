"""Shannon entropy, used to spot packed or encrypted data."""
from __future__ import annotations

import math
from collections import Counter


def shannon_entropy(data: bytes) -> float:
    if not data:
        return 0.0
    n = len(data)
    return -sum((c / n) * math.log2(c / n) for c in Counter(data).values())
