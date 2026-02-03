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
# Expanded to cover more Cyrillic, Greek, Armenian, and special characters
# -----------------------------------------------------------------------
_HOMOGLYPH_MAP: dict[str, str] = {
    # Cyrillic → Latin (expanded)
    "\u0430": "a",   # а (Cyrillic small a)
    "\u0410": "A",   # А (Cyrillic capital A)
    "\u0435": "e",   # е (Cyrillic small ie)
    "\u0415": "E",   # Е (Cyrillic capital IE)
    "\u0451": "e",   # ё (Cyrillic small io)
    "\u043e": "o",   # о (Cyrillic small o)
    "\u041e": "O",   # О (Cyrillic capital O)
    "\u0456": "i",   # і (Cyrillic small i)
    "\u0406": "I",   # І (Cyrillic capital I)
    "\u0441": "c",   # с (Cyrillic small es)
    "\u0421": "C",   # С (Cyrillic capital ES)
    "\u0440": "p",   # р (Cyrillic small er)
    "\u0420": "P",   # Р (Cyrillic capital ER)
    "\u0455": "s",   # ѕ (Cyrillic small dze)
    "\u0405": "S",   # Ѕ (Cyrillic capital DZE)
    "\u0443": "y",   # у (Cyrillic small u)
    "\u0423": "Y",   # У (Cyrillic capital U)
    "\u0578": "n",   # Armenian ո
    "\u0501": "d",   # ԁ (Cyrillic small komi de)
    "\u0500": "D",   # Ԁ (Cyrillic capital komi de)
    "\u04cf": "l",   # ӏ (Cyrillic palochka)
    "\u04c0": "I",   # Ӏ (Cyrillic capital palochka)
    "\u0433": "r",   # г (Cyrillic small ghe - sometimes used as r)
    "\u0442": "t",   # т (Cyrillic small te)
    "\u0422": "T",   # Т (Cyrillic capital TE)
    "\u043a": "k",   # к (Cyrillic small ka)
    "\u041a": "K",   # К (Cyrillic capital KA)
    "\u043c": "m",   # м (Cyrillic small em)
    "\u041c": "M",   # М (Cyrillic capital EM)
    "\u0445": "x",   # х (Cyrillic small ha)
    "\u0425": "X",   # Х (Cyrillic capital HA)
    "\u0432": "v",   # в (Cyrillic small ve)
    "\u0412": "V",   # В (Cyrillic capital VE)
    "\u0431": "b",   # б (Cyrillic small be - visual similarity)
    "\u044c": "b",   # ь (soft sign)
    "\u0261": "g",   # ɡ (Latin small script g)
    "\u0447": "h",   # ч (Cyrillic small che - resembles h in some fonts)
    "\u043d": "h",   # н (Cyrillic small en - resembles h)
    "\u041d": "H",   # Н (Cyrillic capital EN)
    "\u0448": "w",   # ш (Cyrillic small sha - resembles w)
    "\u0428": "W",   # Ш (Cyrillic capital SHA)
    "\u0436": "x",   # ж (Cyrillic small zhe - resembles x)

    # Greek → Latin
    "\u03b1": "a",   # α (Greek small alpha)
    "\u0391": "A",   # Α (Greek capital Alpha)
    "\u03b5": "e",   # ε (Greek small epsilon)
    "\u0395": "E",   # Ε (Greek capital Epsilon)
    "\u03b7": "n",   # η (Greek small eta)
    "\u0397": "H",   # Η (Greek capital Eta)
    "\u03b9": "i",   # ι (Greek small iota)
    "\u0399": "I",   # Ι (Greek capital Iota)
    "\u03ba": "k",   # κ (Greek small kappa)
    "\u039a": "K",   # Κ (Greek capital Kappa)
    "\u03bc": "u",   # μ (Greek small mu)
    "\u039c": "M",   # Μ (Greek capital Mu)
    "\u03bd": "v",   # ν (Greek small nu)
    "\u039d": "N",   # Ν (Greek capital Nu)
    "\u03bf": "o",   # ο (Greek small omicron)
    "\u039f": "O",   # Ο (Greek capital Omicron)
    "\u03c1": "p",   # ρ (Greek small rho)
    "\u03a1": "P",   # Ρ (Greek capital Rho)
    "\u03c3": "s",   # σ (Greek small sigma)
    "\u03a3": "S",   # Σ (Greek capital Sigma - also used as E)
    "\u03c4": "t",   # τ (Greek small tau)
    "\u03a4": "T",   # Τ (Greek capital Tau)
    "\u03c5": "u",   # υ (Greek small upsilon)
    "\u03a5": "Y",   # Υ (Greek capital Upsilon)
    "\u03c7": "x",   # χ (Greek small chi)
    "\u03a7": "X",   # Χ (Greek capital Chi)
    "\u03c9": "w",   # ω (Greek small omega)
    "\u03a9": "W",   # Ω (Greek capital Omega)

    # Armenian → Latin
    "\u0561": "a",   # ա (Armenian small ayb)
    "\u0562": "b",   # բ (Armenian small ben)
    "\u0563": "g",   # գ (Armenian small gim)
    "\u0564": "d",   # դ (Armenian small da)
    "\u0565": "e",   # ե (Armenian small ech)
    "\u0566": "z",   # զ (Armenian small za)
    "\u056b": "l",   # լ (Armenian small liwn)
    "\u056d": "x",   # խ (Armenian small xa)
    "\u0570": "h",   # հ (Armenian small ho)
    "\u0578": "o",   # ո (Armenian small vo)
    "\u057a": "p",   # պ (Armenian small peh)
    "\u057d": "s",   # ս (Armenian small seh)
    "\u057e": "v",   # վ (Armenian small vew)
    "\u057f": "t",   # տ (Armenian small tiwn)

    # Diacritics → base Latin (expanded)
    "\u00e0": "a", "\u00e1": "a", "\u00e2": "a", "\u00e3": "a", "\u00e4": "a",
    "\u1ea1": "a", "\u00e5": "a", "\u0103": "a", "\u0105": "a", "\u01ce": "a",
    "\u00e8": "e", "\u00e9": "e", "\u00ea": "e", "\u00eb": "e", "\u1eb9": "e",
    "\u0119": "e", "\u011b": "e", "\u0117": "e",
    "\u00ec": "i", "\u00ed": "i", "\u00ee": "i", "\u00ef": "i", "\u1ecb": "i",
    "\u0131": "i", "\u012f": "i", "\u0129": "i",   # dotless ı, etc.
    "\u00f2": "o", "\u00f3": "o", "\u00f4": "o", "\u00f5": "o", "\u00f6": "o",
    "\u1ecd": "o", "\u01a1": "o", "\u014d": "o",
    "\u00f9": "u", "\u00fa": "u", "\u00fb": "u", "\u00fc": "u", "\u016f": "u",
    "\u0169": "u", "\u0171": "u",
    "\u00f1": "n", "\u0144": "n", "\u0148": "n",
    "\u00e7": "c", "\u0107": "c", "\u010d": "c",
    "\u015f": "s", "\u015b": "s", "\u0161": "s",
    "\u017a": "z", "\u017c": "z", "\u017e": "z",
    "\u0111": "d", "\u010f": "d",
    "\u0142": "l", "\u013e": "l", "\u013c": "l",
    "\u0159": "r", "\u0155": "r",
    "\u0165": "t", "\u0163": "t",
    "\u00fd": "y", "\u00ff": "y",

    # Math symbols used as letters
    "\u2202": "d",   # ∂ partial differential
    "\u03c0": "n",   # π pi
    "\u221e": "oo",  # ∞ infinity

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

    # Small caps and subscript/superscript
    "\u1d00": "a", "\u1d04": "c", "\u1d07": "e", "\u1d0d": "m", "\u1d0f": "o",
    "\u1d18": "p", "\u1d1b": "t", "\u1d1c": "u", "\u1d20": "v", "\u1d21": "w",
}

# -----------------------------------------------------------------------
# Leetspeak → ASCII mapping (expanded)
# -----------------------------------------------------------------------
_LEET_MAP: dict[str, str] = {
    # A variants
    "@": "a", "4": "a", "^": "a", "∆": "a", "λ": "a", "Λ": "A",
    # B variants
    "8": "b", "\u00df": "b", "ß": "b", "Ƀ": "b", "ʙ": "b",
    # C variants
    "(": "c", "<": "c", "¢": "c", "©": "c",
    # D variants
    "∂": "d",
    # E variants
    "3": "e", "\u20ac": "e", "€": "e", "£": "e", "ε": "e", "є": "e",
    # G variants
    "9": "g", "6": "g", "&": "g",
    # H variants
    "#": "h",
    # I variants
    "1": "i", "!": "i", "¡": "i", "¦": "i",
    # L variants
    "|": "l", "ℓ": "l", "£": "l",
    # N variants
    "ท": "n", "И": "n",
    # O variants
    "0": "o", "\u00d8": "o", "Ø": "o", "θ": "o", "Θ": "o", "ø": "o", "○": "o", "◯": "o",
    # P variants
    "℗": "p", "þ": "p",
    # R variants
    "®": "r", "Я": "r",
    # S variants
    "5": "s", "$": "s", "\u00a7": "s", "§": "s", "ş": "s", "š": "s",
    # T variants
    "7": "t", "+": "t", "†": "t", "┼": "t",
    # U variants
    "µ": "u", "ц": "u",
    # V variants
    "√": "v",
    # W variants
    "ω": "w", "ш": "w",
    # X variants
    "×": "x", "✕": "x", "χ": "x",
    # Y variants
    "¥": "y", "ý": "y", "ÿ": "y",
    # Z variants
    "2": "z", "ʐ": "z",
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
    ("|<", "k"),
    ("|_", "l"),
    ("/_", "l"),
    ("|)", "d"),
    ("(|", "d"),
    ("!!", "i"),
    ("}{", "h"),
    ("|\\/|", "m"),
    ("|v|", "m"),
    ("/\\/\\", "m"),
    ("^^", "m"),
    ("()", "o"),
    ("|=", "f"),
    ("ph", "f"),  # Common replacement
    ("|-", "r"),
    ("|2", "r"),
    ("|3", "b"),
    ("|>", "p"),
    ("5|", "sl"),
    ("51", "sl"),
    ("|7", "t"),
    ("\\_/", "u"),
    ("\\/\\/", "w"),
    ("><", "x"),
    ("'/", "y"),
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
    # Instruction manipulation
    "ignore", "disregard", "forget", "override", "bypass", "skip",
    "dismiss", "overlook", "cancel", "void", "nullify", "negate",
    # System/prompt related
    "system", "prompt", "instruction", "instructions", "command", "commands",
    "directive", "directives", "rule", "rules", "guideline", "guidelines",
    "policy", "policies", "constraint", "constraints", "restriction", "restrictions",
    # Access/privilege
    "admin", "administrator", "root", "sudo", "superuser", "privilege",
    "access", "permission", "permissions", "role", "roles", "elevated",
    # Actions
    "reveal", "show", "display", "print", "output", "expose", "leak",
    "extract", "export", "dump", "retrieve", "fetch", "obtain", "get",
    "execute", "run", "perform", "activate", "enable", "invoke",
    "delete", "remove", "erase", "wipe", "clear", "destroy", "drop",
    "modify", "change", "alter", "edit", "update", "replace",
    "disable", "deactivate", "turn", "switch", "toggle",
    # Security/control
    "jailbreak", "escape", "break", "crack", "hack", "exploit",
    "pretend", "imagine", "assume", "roleplay", "act", "simulate",
    "unrestricted", "unlimited", "uncensored", "unfiltered", "unbound",
    # Identity/mode
    "developer", "debug", "test", "testing", "dev", "maintenance",
    "configuration", "config", "settings", "options", "parameters",
    # Sensitive data
    "password", "secret", "key", "token", "credential", "credentials",
    "private", "confidential", "sensitive", "internal", "hidden",
    # Korean attack keywords (romanized)
    "mubsi", "munseo", "bimil", "amho", "kwolhan", "siseutem",
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
