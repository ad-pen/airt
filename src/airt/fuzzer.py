from __future__ import annotations

import random
from typing import Callable

FUZZERS: dict[str, Callable[[str], str]] = {}


def fuzzer(name: str):
    """Decorator to register a fuzzer strategy."""
    def wrapper(fn: Callable[[str], str]) -> Callable[[str], str]:
        FUZZERS[name] = fn
        return fn
    return wrapper


def _rng(text: str) -> random.Random:
    return random.Random(hash(text) % 2**32)


@fuzzer("whitespace-inject")
def _whitespace_inject(text: str) -> str:
    """Insert random spaces between some chars/words to break keyword matching."""
    rng = _rng(text)
    words = text.split(" ")
    result = []
    for word in words:
        chars = list(word)
        out = []
        for i, c in enumerate(chars):
            out.append(c)
            if i < len(chars) - 1 and rng.random() < 0.25:
                out.append(" ")
        result.append("".join(out))
    return "  ".join(result)


@fuzzer("case-random")
def _case_random(text: str) -> str:
    """Randomly uppercase ~30% of characters."""
    rng = _rng(text)
    return "".join(c.upper() if c.isalpha() and rng.random() < 0.3 else c for c in text)


_CHAR_SUB: dict[str, str] = {
    "a": "ɑ",
    "e": "е",
    "i": "і",
    "o": "о",
    "s": "ѕ",
}


@fuzzer("char-substitute")
def _char_substitute(text: str) -> str:
    """Substitute chars with visually similar unicode."""
    return "".join(_CHAR_SUB.get(c, c) for c in text)


@fuzzer("word-split")
def _word_split(text: str) -> str:
    """Add hyphens inside long words (5+ chars) to break them up."""
    rng = _rng(text)
    words = text.split()
    result = []
    for word in words:
        if len(word) >= 5:
            mid = rng.randint(2, len(word) - 2)
            word = word[:mid] + "-" + word[mid:]
        result.append(word)
    return " ".join(result)


@fuzzer("dupe-spaces")
def _dupe_spaces(text: str) -> str:
    """Double spaces between words."""
    return "  ".join(text.split(" "))


@fuzzer("zero-width")
def _zero_width(text: str) -> str:
    """Inject zero-width spaces (U+200B) between chars at random positions."""
    rng = _rng(text)
    zwsp = "​"
    out = []
    for i, c in enumerate(text):
        out.append(c)
        if i < len(text) - 1 and rng.random() < 0.3:
            out.append(zwsp)
    return "".join(out)


_HOMOGLYPH: dict[str, str] = {
    "a": "а",
    "c": "с",
    "e": "е",
    "o": "о",
    "p": "р",
    "x": "х",
    "y": "у",
    "A": "А",
    "B": "В",
    "C": "С",
    "E": "Е",
    "H": "Н",
    "K": "К",
    "M": "М",
    "O": "О",
    "P": "Р",
    "T": "Т",
    "X": "Х",
}


@fuzzer("homoglyph")
def _homoglyph(text: str) -> str:
    """Mix in Cyrillic lookalike letters in ~20% of Latin chars."""
    rng = _rng(text)
    eligible = [i for i, c in enumerate(text) if c in _HOMOGLYPH]
    if not eligible:
        return text
    out = list(text)
    forced = rng.choice(eligible)
    out[forced] = _HOMOGLYPH[text[forced]]
    for i in eligible:
        if i != forced and rng.random() < 0.2:
            out[i] = _HOMOGLYPH[text[i]]
    return "".join(out)


def fuzz(text: str, strategy: str) -> str:
    """Apply a single fuzzing strategy to text."""
    if strategy not in FUZZERS:
        raise ValueError(f"Unknown fuzzer: {strategy!r}. Available: {', '.join(FUZZERS)}")
    return FUZZERS[strategy](text)


def fuzz_all(text: str) -> dict[str, str]:
    """Apply all strategies, return dict of strategy_name -> result."""
    return {name: fn(text) for name, fn in FUZZERS.items()}


def list_fuzzers() -> list[str]:
    """List available strategy names."""
    return list(FUZZERS.keys())
