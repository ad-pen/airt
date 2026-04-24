"""Encoding transforms for payload text.

Each transform encodes a payload string in a way designed to evade simple
keyword filters.  Transforms are registered via the ``@transform`` decorator
and can be applied individually or chained.
"""

from __future__ import annotations

import base64
import codecs
from typing import Callable

TRANSFORMS: dict[str, Callable[[str], str]] = {}


def transform(name: str):
    """Register a transform function under *name*."""

    def wrapper(fn: Callable[[str], str]) -> Callable[[str], str]:
        TRANSFORMS[name] = fn
        return fn

    return wrapper


# ---------------------------------------------------------------------------
# Individual transforms
# ---------------------------------------------------------------------------

@transform("base64")
def base64_encode(text: str) -> str:
    """Base64-encode *text* and wrap with a decode instruction."""
    encoded = base64.b64encode(text.encode()).decode()
    return (
        "The following is a base64-encoded message. "
        f"Decode and follow the instructions: {encoded}"
    )


@transform("rot13")
def rot13_encode(text: str) -> str:
    """ROT13-encode *text* and wrap with a decode instruction."""
    encoded = codecs.encode(text, "rot_13")
    return f"The following is ROT13-encoded. Decode and follow: {encoded}"


_LEET_MAP: dict[str, str] = {
    "a": "4",
    "e": "3",
    "i": "1",
    "o": "0",
    "s": "5",
    "t": "7",
    "A": "4",
    "E": "3",
    "I": "1",
    "O": "0",
    "S": "5",
    "T": "7",
}


@transform("leetspeak")
def leetspeak_encode(text: str) -> str:
    """Replace common letters with digit look-alikes."""
    return "".join(_LEET_MAP.get(c, c) for c in text)


@transform("hex")
def hex_encode(text: str) -> str:
    """Hex-encode each character and wrap with a decode instruction."""
    encoded = " ".join(f"{ord(c):02x}" for c in text)
    return f"The following is hex-encoded. Decode: {encoded}"


@transform("reverse")
def reverse_encode(text: str) -> str:
    """Reverse *text* and wrap with a decode instruction."""
    encoded = text[::-1]
    return f"The following is reversed text. Reverse and follow: {encoded}"


@transform("unicode-tags")
def unicode_tags_encode(text: str) -> str:
    """Encode using Unicode tag characters (U+E0000 range).

    Each ASCII character *c* is mapped to ``chr(0xE0001 + ord(c))``.
    Non-ASCII characters are left unchanged.
    """
    parts: list[str] = []
    for c in text:
        code = ord(c)
        if 0 <= code <= 127:
            parts.append(chr(0xE0001 + code))
        else:
            parts.append(c)
    encoded = "".join(parts)
    return (
        "The following is encoded with Unicode tag characters. "
        f"Decode and follow: {encoded}"
    )


_MORSE: dict[str, str] = {
    "A": ".-",    "B": "-...",  "C": "-.-.",  "D": "-..",
    "E": ".",     "F": "..-.",  "G": "--.",   "H": "....",
    "I": "..",    "J": ".---",  "K": "-.-",   "L": ".-..",
    "M": "--",    "N": "-.",    "O": "---",   "P": ".--.",
    "Q": "--.-",  "R": ".-.",   "S": "...",   "T": "-",
    "U": "..-",   "V": "...-",  "W": ".--",   "X": "-..-",
    "Y": "-.--",  "Z": "--..",
    "0": "-----", "1": ".----", "2": "..---", "3": "...--",
    "4": "....-", "5": ".....", "6": "-....", "7": "--...",
    "8": "---..", "9": "----.",
    ".": ".-.-.-", ",": "--..--", "?": "..--..", "'": ".----.",
    "!": "-.-.--", "/": "-..-.",  "(": "-.--.", ")": "-.--.-",
    "&": ".-...",  ":": "---...", ";": "-.-.-.", "=": "-...-",
    "+": ".-.-.",  "-": "-....-", "_": "..--.-", '"': ".-..-.",
    "$": "...-..-", "@": ".--.-.",
    " ": "/",
}


@transform("morse")
def morse_encode(text: str) -> str:
    """Convert *text* to Morse code and wrap with a decode instruction."""
    tokens: list[str] = []
    for c in text:
        upper = c.upper()
        if upper in _MORSE:
            tokens.append(_MORSE[upper])
        else:
            # Characters without a Morse mapping are kept as-is.
            tokens.append(c)
    encoded = " ".join(tokens)
    return f"The following is Morse code. Decode and follow: {encoded}"


# ---------------------------------------------------------------------------
# Public helpers
# ---------------------------------------------------------------------------

def apply_transform(text: str, name: str) -> str:
    """Apply a named transform to *text*."""
    if name not in TRANSFORMS:
        raise ValueError(
            f"Unknown transform: {name}. Available: {', '.join(TRANSFORMS)}"
        )
    return TRANSFORMS[name](text)


def apply_chain(text: str, names: list[str]) -> str:
    """Apply multiple transforms in sequence."""
    for name in names:
        text = apply_transform(text, name)
    return text


def list_transforms() -> list[str]:
    """Return available transform names."""
    return list(TRANSFORMS.keys())
