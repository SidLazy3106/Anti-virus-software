"""Optional YARA rule matching (needs the yara-python package and .yar files in sentinel/rules)."""
from __future__ import annotations

from .. import config, logger
from .base import Check, FileContext

try:
    import yara
except ImportError:  # pragma: no cover - optional dependency
    yara = None


def load_rules(log: bool = True):
    """Compiled YARA rules, or None when YARA or the rule files are missing or broken."""
    if yara is None or not config.RULES_DIR.is_dir():
        return None
    files = {p.stem: str(p) for p in config.RULES_DIR.glob("*.yar")}
    if not files:
        return None
    try:
        return yara.compile(filepaths=files)
    except yara.Error as e:          # a broken rule file must not stop scanning, but it must not be silent
        if log:
            logger.get().warning("YARA rules not loaded: %s", e)
        return None


class YaraCheck(Check):
    name = "yara"

    def __init__(self, rules):
        self.rules = rules

    def applies(self, ctx: FileContext) -> bool:
        return self.rules is not None and ctx.size <= config.MAX_HEURISTIC_SIZE

    def run(self, ctx: FileContext) -> None:
        try:
            for m in self.rules.match(filepath=str(ctx.path)):
                ctx.result.add(60, f"YARA rule matched: {m.rule}")
        except (yara.Error, OSError) as e:
            logger.get().debug("YARA could not scan %s: %s", ctx.path, e)
