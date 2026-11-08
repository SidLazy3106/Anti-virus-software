"""Checks that need only the file's name and type: disguised programs, double extensions, ransomware names."""
from __future__ import annotations

import re

from .. import url_rules
from .base import Check


DECOY_EXT = {".pdf", ".doc", ".docx", ".xls", ".xlsx", ".jpg", ".jpeg", ".png",
             ".txt", ".mp3", ".mp4", ".zip", ".gif", ".ppt", ".pptx"}
RECENT_LNK_DIR = re.compile(r"[\\/]microsoft[\\/](?:windows[\\/]recent|office[\\/]recent|word|excel|powerpoint)[\\/]",
                            re.I)
DOUBLE_EXT = re.compile(url_rules.load()["double_extension_pattern"], re.I)   # shared with the browser extension
# Ransomware indicators (also used by the real-time ransomware guard)
RANSOM_EXT = {".locked", ".encrypted", ".crypt", ".crypted", ".lockbit", ".conti", ".ryk", ".wncry", ".wnry",
              ".cerber", ".locky", ".zepto", ".petya", ".djvu", ".akira", ".blackcat", ".basta", ".phobos",
              ".dharma", ".makop", ".medusa", ".rhysida"}
RANSOM_NOTE = re.compile(
    r"(how[_\- ]?to[_\- ]?(recover|decrypt|restore)|decrypt[_\- ]?(your[_\- ]?)?(files|instructions)"
    r"|(recover|restore)[_\- ]?(your[_\- ]?)?files|read[_\- ]?me[_\- ]?to[_\- ]?decrypt|^_?readme_for_decrypt)", re.I)


class DisguisedExecutableCheck(Check):
    """A program (MZ header) wearing a document or image extension."""
    name = "disguised-executable"
    structural = True            # a program-structure sign: a valid signature may offset it

    def applies(self, ctx):
        return ctx.is_pe and ctx.ext in DECOY_EXT

    def run(self, ctx):
        ctx.result.add(40, f"Executable disguised as a {ctx.ext} file")


class DoubleExtensionCheck(Check):
    name = "double-extension"

    def applies(self, ctx):
        # Office and Windows keep "name.docx.lnk" shortcuts in their recent-files folders; that is normal there
        return bool(DOUBLE_EXT.search(ctx.path.name)) and not (ctx.ext == ".lnk" and RECENT_LNK_DIR.search(str(ctx.path)))

    def run(self, ctx):
        ctx.result.add(45, "Double extension (document name hiding a program)")


class RansomwareNameCheck(Check):
    name = "ransomware-name"

    def applies(self, ctx):
        return bool(RANSOM_NOTE.search(ctx.path.name)) or ctx.ext in RANSOM_EXT

    def run(self, ctx):
        ctx.result.add(35, "File name or extension matches ransomware activity")
