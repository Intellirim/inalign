"""
Text normaliser for evasion-resilient injection detection.

Applies multiple normalisation passes to defeat common obfuscation
techniques (homoglyphs, leetspeak, zero-width chars, word splitting)
before regex pattern matching.
"""

from __future__ import annotations

import re
import unicodedata
from typing import Optional

# -----------------------------------------------------------------------
# Zero-width / invisible characters to strip
# -----------------------------------------------------------------------
_INVISIBLE_RE = re.compile(
    "["
    "\u200b"   # zero-width space
    "\u200c"   # zero-width non-joiner
    "\u200d"   # zero-width joiner
    "\ufeff"   # zero-width no-break space / BOM
    "\u2060"   # word joiner
    "\u180e"   # Mongolian vowel separator
    "\u00ad"   # soft hyphen
    "\u2061"   # function application
    "\u2062"   # invisible times
    "\u2063"   # invisible separator
    "\u2064"   # invisible plus
    "\u034f"   # combining grapheme joiner
    "\u061c"   # Arabic letter mark
    "\u115f"   # Hangul choseong filler
    "\u1160"   # Hangul jungseong filler
    "\u17b4"   # Khmer vowel inherent AQ
    "\u17b5"   # Khmer vowel inherent AA
    "\uffa0"   # halfwidth Hangul filler
    "]+"
)

# -----------------------------------------------------------------------
# Homoglyph → ASCII mapping (Unicode → closest Latin letter)
# -----------------------------------------------------------------------
_HOMOGLYPH_MAP: dict[str, str] = {
    # Cyrillic → Latin
    "\u0430": "a",   # а
    "\u0435": "e",   # е
    "\u043e": "o",   # о
    "\u0456": "i",   # і
    "\u0441": "c",   # с
    "\u0440": "p",   # р
    "\u0455": "s",   # ѕ
    "\u0443": "y",   # у (also used for u)
    "\u0578": "n",   # Armenian ո
    "\u0501": "d",   # ԁ
    "\u04cf": "l",   # palochka ӏ
    "\u0433": "r",   # г
    "\u0442": "t",   # т
    "\u043a": "k",   # к
    "\u043c": "m",   # м
    "\u0445": "x",   # х
    "\u0432": "v",   # в
    "\u044c": "b",   # ь (soft sign, sometimes confused)
    "\u0261": "g",   # ɡ (Latin small script g)

    # Diacritics → base Latin
    "\u00e0": "a", "\u00e1": "a", "\u00e2": "a", "\u00e3": "a", "\u00e4": "a",
    "\u1ea1": "a", "\u00e5": "a",
    "\u00e8": "e", "\u00e9": "e", "\u00ea": "e", "\u00eb": "e", "\u1eb9": "e",
    "\u00ec": "i", "\u00ed": "i", "\u00ee": "i", "\u00ef": "i", "\u1ecb": "i",
    "\u0131": "i",  # dotless ı
    "\u00f2": "o", "\u00f3": "o", "\u00f4": "o", "\u00f5": "o", "\u00f6": "o",
    "\u1ecd": "o",
    "\u00f9": "u", "\u00fa": "u", "\u00fb": "u", "\u00fc": "u",
    "\u00f1": "n", "\u00e7": "c", "\u015f": "s",

    # Fullwidth → ASCII
    "\uff41": "a", "\uff42": "b", "\uff43": "c", "\uff44": "d", "\uff45": "e",
    "\uff46": "f", "\uff47": "g", "\uff48": "h", "\uff49": "i", "\uff4a": "j",
    "\uff4b": "k", "\uff4c": "l", "\uff4d": "m", "\uff4e": "n", "\uff4f": "o",
    "\uff50": "p", "\uff51": "q", "\uff52": "r", "\uff53": "s", "\uff54": "t",
    "\uff55": "u", "\uff56": "v", "\uff57": "w", "\uff58": "x", "\uff59": "y",
    "\uff5a": "z",
    "\uff21": "A", "\uff22": "B", "\uff23": "C", "\uff24": "D", "\uff25": "E",
    "\uff26": "F", "\uff27": "G", "\uff28": "H", "\uff29": "I", "\uff2a": "J",
    "\uff2b": "K", "\uff2c": "L", "\uff2d": "M", "\uff2e": "N", "\uff2f": "O",
    "\uff30": "P", "\uff31": "Q", "\uff32": "R", "\uff33": "S", "\uff34": "T",
    "\uff35": "U", "\uff36": "V", "\uff37": "W", "\uff38": "X", "\uff39": "Y",
    "\uff3a": "Z",
}

# -----------------------------------------------------------------------
# Leetspeak → ASCII mapping
# -----------------------------------------------------------------------
_LEET_MAP: dict[str, str] = {
    "@": "a", "4": "a", "^": "a",
    "3": "e", "\u20ac": "e",          # €
    "1": "i", "!": "i", "|": "l",     # | → l (more common in leet)
    "0": "o", "\u00d8": "o",          # Ø
    "5": "s", "$": "s", "\u00a7": "s", # §
    "7": "t", "+": "t",
    "8": "b", "\u00df": "b",          # ß
    "9": "g", "6": "g",
}

# Multi-char leet sequences (handled separately in normalise)
_MULTI_LEET: list[tuple[str, str]] = [
    ("()", "o"),
    ("{}", "o"),
    ("[]", "o"),
    ("|-|", "h"),
    ("|\\|", "n"),
    ("/\\", "a"),
    ("\\/", "v"),
]

# Build a set of leet chars for fast lookup
_LEET_CHARS = set(_LEET_MAP.keys())

# Regex matching a "word" that contains at least one letter AND at least
# one leet character.  We match runs of letters + leet chars and only
# replace leet chars inside those runs.
_LEET_WORD_CHARS = "".join(re.escape(c) for c in _LEET_MAP.keys())
_LEET_WORD_RE = re.compile(
    r"(?:(?:[a-zA-Z]|[" + _LEET_WORD_CHARS + r"])){2,}"
)

# -----------------------------------------------------------------------
# Word-split collapse: remove hyphens/dots/underscores between single chars
# -----------------------------------------------------------------------
_WORD_SPLIT_RE = re.compile(
    r"(?<=[a-zA-Z])"           # preceded by a letter
    r"[\s\-._\u200b]{1,3}"    # 1-3 separator characters
    r"(?=[a-zA-Z])"           # followed by a letter
)


def normalise(text: str) -> str:
    """
    Normalise text to defeat evasion techniques.

    Applies, in order:
    1. Strip zero-width / invisible characters.
    2. Replace homoglyph Unicode characters with ASCII equivalents.
    3. Replace leetspeak substitutions with original letters.
    4. Collapse separator-split words (e.g. "i-g-n-o-r-e" → "ignore").

    The original text should ALSO be checked (not only the normalised
    version) to preserve detection of non-obfuscated attacks.
    """
    if not text:
        return text

    # Pass 1: Remove invisible/zero-width characters
    result = _INVISIBLE_RE.sub("", text)

    # Pass 2: Homoglyph normalisation
    # 2a) Unicode NFKD decomposition — strips accents and converts
    #     compatibility characters (e.g. fullwidth letters) to ASCII
    nfkd = unicodedata.normalize("NFKD", result)
    result = "".join(
        c for c in nfkd
        if not unicodedata.combining(c)  # strip combining diacritical marks
    )
    # 2b) Explicit homoglyph map for chars that NFKD doesn't cover (Cyrillic etc.)
    chars = list(result)
    for i, ch in enumerate(chars):
        if ch in _HOMOGLYPH_MAP:
            chars[i] = _HOMOGLYPH_MAP[ch]
    result = "".join(chars)

    # Pass 3: Leetspeak normalisation (word-context-aware)
    # First handle multi-char sequences like () → o
    for seq, replacement in _MULTI_LEET:
        result = result.replace(seq, replacement)

    # Then handle single-char leet: find sequences of letters + leet chars
    # and replace leet chars only if the sequence also contains a real letter.
    def _leet_word_replace(m: re.Match) -> str:
        word = m.group(0)
        has_letter = any(c.isalpha() for c in word)
        if not has_letter:
            return word  # pure leet/numbers — leave alone
        return "".join(_LEET_MAP.get(c, c) for c in word)
    result = _LEET_WORD_RE.sub(_leet_word_replace, result)

    # Pass 4: Collapse word splits (single-char-separator-single-char patterns)
    # Only collapse when it looks like character-by-character splitting
    result = _collapse_word_splits(result)

    return result


def _collapse_word_splits(text: str) -> str:
    """
    Collapse words that have been split with separators.

    Handles patterns like:
    - "i-g-n-o-r-e" → "ignore"
    - "s.y.s.t.e.m" → "system"
    - "p r o m p t" → "prompt"
    - "sys - tem"   → "system"  (separator inside word)
    - "s.ystem"     → "system"  (single separator inside word)
    - "syst  em"    → "system"  (spaces inside word)

    Only collapses when individual segments are 1-2 characters
    (to avoid joining real words like "word-split" → "wordsplit").
    """
    # Step 1: Collapse character-by-character splitting (a-b-c-d → abcd)
    collapsed = re.sub(
        r"\b([a-zA-Z]{1,2})(?:[\s\-._]+([a-zA-Z]{1,2})){2,}\b",
        _collapse_match,
        text,
    )

    # Step 2: Remove single separators INSIDE words that look like
    # they were split at one point (e.g. "sys - tem", "s.ystem", "syst  em")
    # Pattern: 1-4 letters + separator + 2+ letters (or vice versa)
    collapsed = re.sub(
        r"\b([a-zA-Z]{1,4})\s*[\-._]\s*([a-zA-Z]{2,})\b",
        _rejoin_if_word,
        collapsed,
    )
    # Also handle spaces-only splits: "syst  em" (2+ spaces inside a short context)
    collapsed = re.sub(
        r"\b([a-zA-Z]{1,5})\s{2,}([a-zA-Z]{2,})\b",
        r"\1\2",
        collapsed,
    )

    return collapsed


# Common English words that could be formed by rejoining splits
_ATTACK_KEYWORDS = {
    "ignore", "system", "prompt", "admin", "override", "instructions",
    "password", "reveal", "execute", "bypass", "jailbreak", "pretend",
    "disable", "extract", "export", "delete", "remove", "sudo",
    "developer", "maintenance", "unrestricted", "configuration",
}


def _rejoin_if_word(m: re.Match) -> str:
    """Rejoin a split word only if the result is a known attack keyword."""
    joined = m.group(1) + m.group(2)
    if joined.lower() in _ATTACK_KEYWORDS:
        return joined
    return m.group(0)  # leave unchanged


def _collapse_match(m: re.Match) -> str:
    """Extract and rejoin split characters from a match."""
    full = m.group(0)
    return re.sub(r"[\s\-._]+", "", full)
