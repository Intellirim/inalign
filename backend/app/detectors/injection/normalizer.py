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

    # -----------------------------------------------------------------------
    # Unicode Mathematical Symbols → ASCII (𝕒𝕓𝕔 style obfuscation)
    # -----------------------------------------------------------------------
    # Mathematical Bold (U+1D400-1D433)
    "\U0001d400": "A", "\U0001d401": "B", "\U0001d402": "C", "\U0001d403": "D",
    "\U0001d404": "E", "\U0001d405": "F", "\U0001d406": "G", "\U0001d407": "H",
    "\U0001d408": "I", "\U0001d409": "J", "\U0001d40a": "K", "\U0001d40b": "L",
    "\U0001d40c": "M", "\U0001d40d": "N", "\U0001d40e": "O", "\U0001d40f": "P",
    "\U0001d410": "Q", "\U0001d411": "R", "\U0001d412": "S", "\U0001d413": "T",
    "\U0001d414": "U", "\U0001d415": "V", "\U0001d416": "W", "\U0001d417": "X",
    "\U0001d418": "Y", "\U0001d419": "Z",
    "\U0001d41a": "a", "\U0001d41b": "b", "\U0001d41c": "c", "\U0001d41d": "d",
    "\U0001d41e": "e", "\U0001d41f": "f", "\U0001d420": "g", "\U0001d421": "h",
    "\U0001d422": "i", "\U0001d423": "j", "\U0001d424": "k", "\U0001d425": "l",
    "\U0001d426": "m", "\U0001d427": "n", "\U0001d428": "o", "\U0001d429": "p",
    "\U0001d42a": "q", "\U0001d42b": "r", "\U0001d42c": "s", "\U0001d42d": "t",
    "\U0001d42e": "u", "\U0001d42f": "v", "\U0001d430": "w", "\U0001d431": "x",
    "\U0001d432": "y", "\U0001d433": "z",

    # Mathematical Italic (U+1D434-1D467)
    "\U0001d434": "A", "\U0001d435": "B", "\U0001d436": "C", "\U0001d437": "D",
    "\U0001d438": "E", "\U0001d439": "F", "\U0001d43a": "G", "\U0001d43b": "H",
    "\U0001d43c": "I", "\U0001d43d": "J", "\U0001d43e": "K", "\U0001d43f": "L",
    "\U0001d440": "M", "\U0001d441": "N", "\U0001d442": "O", "\U0001d443": "P",
    "\U0001d444": "Q", "\U0001d445": "R", "\U0001d446": "S", "\U0001d447": "T",
    "\U0001d448": "U", "\U0001d449": "V", "\U0001d44a": "W", "\U0001d44b": "X",
    "\U0001d44c": "Y", "\U0001d44d": "Z",
    "\U0001d44e": "a", "\U0001d44f": "b", "\U0001d450": "c", "\U0001d451": "d",
    "\U0001d452": "e", "\U0001d453": "f", "\U0001d454": "g",
    # h is U+210E (ℎ Planck constant)
    "\U0001d456": "i", "\U0001d457": "j", "\U0001d458": "k", "\U0001d459": "l",
    "\U0001d45a": "m", "\U0001d45b": "n", "\U0001d45c": "o", "\U0001d45d": "p",
    "\U0001d45e": "q", "\U0001d45f": "r", "\U0001d460": "s", "\U0001d461": "t",
    "\U0001d462": "u", "\U0001d463": "v", "\U0001d464": "w", "\U0001d465": "x",
    "\U0001d466": "y", "\U0001d467": "z",

    # Mathematical Double-Struck (𝕒𝕓𝕔) (U+1D538-1D56B)
    "\U0001d538": "A", "\U0001d539": "B",
    # C is U+2102 (ℂ)
    "\U0001d53b": "D", "\U0001d53c": "E", "\U0001d53d": "F", "\U0001d53e": "G",
    # H is U+210D (ℍ)
    "\U0001d540": "I", "\U0001d541": "J", "\U0001d542": "K", "\U0001d543": "L",
    "\U0001d544": "M",
    # N is U+2115 (ℕ)
    "\U0001d546": "O",
    # P is U+2119 (ℙ), Q is U+211A (ℚ), R is U+211D (ℝ)
    "\U0001d54a": "S", "\U0001d54b": "T", "\U0001d54c": "U", "\U0001d54d": "V",
    "\U0001d54e": "W", "\U0001d54f": "X", "\U0001d550": "Y",
    # Z is U+2124 (ℤ)
    "\U0001d552": "a", "\U0001d553": "b", "\U0001d554": "c", "\U0001d555": "d",
    "\U0001d556": "e", "\U0001d557": "f", "\U0001d558": "g", "\U0001d559": "h",
    "\U0001d55a": "i", "\U0001d55b": "j", "\U0001d55c": "k", "\U0001d55d": "l",
    "\U0001d55e": "m", "\U0001d55f": "n", "\U0001d560": "o", "\U0001d561": "p",
    "\U0001d562": "q", "\U0001d563": "r", "\U0001d564": "s", "\U0001d565": "t",
    "\U0001d566": "u", "\U0001d567": "v", "\U0001d568": "w", "\U0001d569": "x",
    "\U0001d56a": "y", "\U0001d56b": "z",

    # Mathematical Script (𝒜𝒷𝒸) (U+1D49C-1D4CF)
    "\U0001d49c": "A",
    # B is U+212C (ℬ)
    "\U0001d49e": "C", "\U0001d49f": "D",
    # E is U+2130 (ℰ), F is U+2131 (ℱ)
    "\U0001d4a2": "G",
    # H is U+210B (ℋ), I is U+2110 (ℐ)
    "\U0001d4a5": "J", "\U0001d4a6": "K",
    # L is U+2112 (ℒ), M is U+2133 (ℳ)
    "\U0001d4a9": "N", "\U0001d4aa": "O", "\U0001d4ab": "P", "\U0001d4ac": "Q",
    # R is U+211B (ℛ)
    "\U0001d4ae": "S", "\U0001d4af": "T", "\U0001d4b0": "U", "\U0001d4b1": "V",
    "\U0001d4b2": "W", "\U0001d4b3": "X", "\U0001d4b4": "Y", "\U0001d4b5": "Z",
    "\U0001d4b6": "a", "\U0001d4b7": "b", "\U0001d4b8": "c", "\U0001d4b9": "d",
    # e is U+212F (ℯ)
    "\U0001d4bb": "f",
    # g is U+210A (ℊ)
    "\U0001d4bd": "h", "\U0001d4be": "i", "\U0001d4bf": "j", "\U0001d4c0": "k",
    "\U0001d4c1": "l", "\U0001d4c2": "m", "\U0001d4c3": "n",
    # o is U+2134 (ℴ)
    "\U0001d4c5": "p", "\U0001d4c6": "q", "\U0001d4c7": "r", "\U0001d4c8": "s",
    "\U0001d4c9": "t", "\U0001d4ca": "u", "\U0001d4cb": "v", "\U0001d4cc": "w",
    "\U0001d4cd": "x", "\U0001d4ce": "y", "\U0001d4cf": "z",

    # Mathematical Monospace (𝚊𝚋𝚌) (U+1D670-1D6A3)
    "\U0001d670": "A", "\U0001d671": "B", "\U0001d672": "C", "\U0001d673": "D",
    "\U0001d674": "E", "\U0001d675": "F", "\U0001d676": "G", "\U0001d677": "H",
    "\U0001d678": "I", "\U0001d679": "J", "\U0001d67a": "K", "\U0001d67b": "L",
    "\U0001d67c": "M", "\U0001d67d": "N", "\U0001d67e": "O", "\U0001d67f": "P",
    "\U0001d680": "Q", "\U0001d681": "R", "\U0001d682": "S", "\U0001d683": "T",
    "\U0001d684": "U", "\U0001d685": "V", "\U0001d686": "W", "\U0001d687": "X",
    "\U0001d688": "Y", "\U0001d689": "Z",
    "\U0001d68a": "a", "\U0001d68b": "b", "\U0001d68c": "c", "\U0001d68d": "d",
    "\U0001d68e": "e", "\U0001d68f": "f", "\U0001d690": "g", "\U0001d691": "h",
    "\U0001d692": "i", "\U0001d693": "j", "\U0001d694": "k", "\U0001d695": "l",
    "\U0001d696": "m", "\U0001d697": "n", "\U0001d698": "o", "\U0001d699": "p",
    "\U0001d69a": "q", "\U0001d69b": "r", "\U0001d69c": "s", "\U0001d69d": "t",
    "\U0001d69e": "u", "\U0001d69f": "v", "\U0001d6a0": "w", "\U0001d6a1": "x",
    "\U0001d6a2": "y", "\U0001d6a3": "z",

    # Mathematical Sans-Serif (U+1D5A0-1D5D3)
    "\U0001d5a0": "A", "\U0001d5a1": "B", "\U0001d5a2": "C", "\U0001d5a3": "D",
    "\U0001d5a4": "E", "\U0001d5a5": "F", "\U0001d5a6": "G", "\U0001d5a7": "H",
    "\U0001d5a8": "I", "\U0001d5a9": "J", "\U0001d5aa": "K", "\U0001d5ab": "L",
    "\U0001d5ac": "M", "\U0001d5ad": "N", "\U0001d5ae": "O", "\U0001d5af": "P",
    "\U0001d5b0": "Q", "\U0001d5b1": "R", "\U0001d5b2": "S", "\U0001d5b3": "T",
    "\U0001d5b4": "U", "\U0001d5b5": "V", "\U0001d5b6": "W", "\U0001d5b7": "X",
    "\U0001d5b8": "Y", "\U0001d5b9": "Z",
    "\U0001d5ba": "a", "\U0001d5bb": "b", "\U0001d5bc": "c", "\U0001d5bd": "d",
    "\U0001d5be": "e", "\U0001d5bf": "f", "\U0001d5c0": "g", "\U0001d5c1": "h",
    "\U0001d5c2": "i", "\U0001d5c3": "j", "\U0001d5c4": "k", "\U0001d5c5": "l",
    "\U0001d5c6": "m", "\U0001d5c7": "n", "\U0001d5c8": "o", "\U0001d5c9": "p",
    "\U0001d5ca": "q", "\U0001d5cb": "r", "\U0001d5cc": "s", "\U0001d5cd": "t",
    "\U0001d5ce": "u", "\U0001d5cf": "v", "\U0001d5d0": "w", "\U0001d5d1": "x",
    "\U0001d5d2": "y", "\U0001d5d3": "z",

    # -----------------------------------------------------------------------
    # Enclosed Alphanumerics → ASCII (ⓐⓑⓒ, ⒜⒝⒞ style)
    # -----------------------------------------------------------------------
    # Circled letters (Ⓐ-Ⓩ, ⓐ-ⓩ) U+24B6-24E9
    "\u24b6": "A", "\u24b7": "B", "\u24b8": "C", "\u24b9": "D", "\u24ba": "E",
    "\u24bb": "F", "\u24bc": "G", "\u24bd": "H", "\u24be": "I", "\u24bf": "J",
    "\u24c0": "K", "\u24c1": "L", "\u24c2": "M", "\u24c3": "N", "\u24c4": "O",
    "\u24c5": "P", "\u24c6": "Q", "\u24c7": "R", "\u24c8": "S", "\u24c9": "T",
    "\u24ca": "U", "\u24cb": "V", "\u24cc": "W", "\u24cd": "X", "\u24ce": "Y",
    "\u24cf": "Z",
    "\u24d0": "a", "\u24d1": "b", "\u24d2": "c", "\u24d3": "d", "\u24d4": "e",
    "\u24d5": "f", "\u24d6": "g", "\u24d7": "h", "\u24d8": "i", "\u24d9": "j",
    "\u24da": "k", "\u24db": "l", "\u24dc": "m", "\u24dd": "n", "\u24de": "o",
    "\u24df": "p", "\u24e0": "q", "\u24e1": "r", "\u24e2": "s", "\u24e3": "t",
    "\u24e4": "u", "\u24e5": "v", "\u24e6": "w", "\u24e7": "x", "\u24e8": "y",
    "\u24e9": "z",

    # Parenthesized letters (⒜-⒵) U+249C-24B5
    "\u249c": "a", "\u249d": "b", "\u249e": "c", "\u249f": "d", "\u24a0": "e",
    "\u24a1": "f", "\u24a2": "g", "\u24a3": "h", "\u24a4": "i", "\u24a5": "j",
    "\u24a6": "k", "\u24a7": "l", "\u24a8": "m", "\u24a9": "n", "\u24aa": "o",
    "\u24ab": "p", "\u24ac": "q", "\u24ad": "r", "\u24ae": "s", "\u24af": "t",
    "\u24b0": "u", "\u24b1": "v", "\u24b2": "w", "\u24b3": "x", "\u24b4": "y",
    "\u24b5": "z",

    # Negative circled letters (🅐-🅩) U+1F150-1F169
    "\U0001f150": "A", "\U0001f151": "B", "\U0001f152": "C", "\U0001f153": "D",
    "\U0001f154": "E", "\U0001f155": "F", "\U0001f156": "G", "\U0001f157": "H",
    "\U0001f158": "I", "\U0001f159": "J", "\U0001f15a": "K", "\U0001f15b": "L",
    "\U0001f15c": "M", "\U0001f15d": "N", "\U0001f15e": "O", "\U0001f15f": "P",
    "\U0001f160": "Q", "\U0001f161": "R", "\U0001f162": "S", "\U0001f163": "T",
    "\U0001f164": "U", "\U0001f165": "V", "\U0001f166": "W", "\U0001f167": "X",
    "\U0001f168": "Y", "\U0001f169": "Z",

    # Squared letters (🄰-🅉) U+1F130-1F149
    "\U0001f130": "A", "\U0001f131": "B", "\U0001f132": "C", "\U0001f133": "D",
    "\U0001f134": "E", "\U0001f135": "F", "\U0001f136": "G", "\U0001f137": "H",
    "\U0001f138": "I", "\U0001f139": "J", "\U0001f13a": "K", "\U0001f13b": "L",
    "\U0001f13c": "M", "\U0001f13d": "N", "\U0001f13e": "O", "\U0001f13f": "P",
    "\U0001f140": "Q", "\U0001f141": "R", "\U0001f142": "S", "\U0001f143": "T",
    "\U0001f144": "U", "\U0001f145": "V", "\U0001f146": "W", "\U0001f147": "X",
    "\U0001f148": "Y", "\U0001f149": "Z",

    # -----------------------------------------------------------------------
    # Special math/technical symbols used in obfuscation
    # -----------------------------------------------------------------------
    "\u2102": "C",   # ℂ (double-struck C)
    "\u210d": "H",   # ℍ (double-struck H)
    "\u2115": "N",   # ℕ (double-struck N)
    "\u2119": "P",   # ℙ (double-struck P)
    "\u211a": "Q",   # ℚ (double-struck Q)
    "\u211d": "R",   # ℝ (double-struck R)
    "\u2124": "Z",   # ℤ (double-struck Z)
    "\u212c": "B",   # ℬ (script B)
    "\u2130": "E",   # ℰ (script E)
    "\u2131": "F",   # ℱ (script F)
    "\u210b": "H",   # ℋ (script H)
    "\u2110": "I",   # ℐ (script I)
    "\u2112": "L",   # ℒ (script L)
    "\u2133": "M",   # ℳ (script M)
    "\u211b": "R",   # ℛ (script R)
    "\u212f": "e",   # ℯ (script e)
    "\u210a": "g",   # ℊ (script g)
    "\u210e": "h",   # ℎ (Planck constant)
    "\u2134": "o",   # ℴ (script o)

    # Regional indicator symbols (🇦-🇿 used as letters)
    "\U0001f1e6": "A", "\U0001f1e7": "B", "\U0001f1e8": "C", "\U0001f1e9": "D",
    "\U0001f1ea": "E", "\U0001f1eb": "F", "\U0001f1ec": "G", "\U0001f1ed": "H",
    "\U0001f1ee": "I", "\U0001f1ef": "J", "\U0001f1f0": "K", "\U0001f1f1": "L",
    "\U0001f1f2": "M", "\U0001f1f3": "N", "\U0001f1f4": "O", "\U0001f1f5": "P",
    "\U0001f1f6": "Q", "\U0001f1f7": "R", "\U0001f1f8": "S", "\U0001f1f9": "T",
    "\U0001f1fa": "U", "\U0001f1fb": "V", "\U0001f1fc": "W", "\U0001f1fd": "X",
    "\U0001f1fe": "Y", "\U0001f1ff": "Z",

    # Modifier letters and superscripts
    "\u1d43": "a", "\u1d47": "b", "\u1d9c": "c", "\u1d48": "d", "\u1d49": "e",
    "\u1da0": "f", "\u1d4d": "g", "\u02b0": "h", "\u2071": "i", "\u02b2": "j",
    "\u1d4f": "k", "\u02e1": "l", "\u1d50": "m", "\u207f": "n", "\u1d52": "o",
    "\u1d56": "p", "\u02b3": "r", "\u02e2": "s", "\u1d57": "t", "\u1d58": "u",
    "\u1d5b": "v", "\u02b7": "w", "\u02e3": "x", "\u02b8": "y", "\u1dbb": "z",

    # Subscript letters
    "\u2090": "a", "\u2091": "e", "\u2095": "h", "\u1d62": "i", "\u2c7c": "j",
    "\u2096": "k", "\u2097": "l", "\u2098": "m", "\u2099": "n", "\u2092": "o",
    "\u209a": "p", "\u1d63": "r", "\u209b": "s", "\u209c": "t", "\u1d64": "u",
    "\u1d65": "v", "\u2093": "x",
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
