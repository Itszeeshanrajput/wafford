"""Wordlist generation for the Wafford framework."""

from __future__ import annotations

import itertools
import logging
from pathlib import Path
from typing import Any

logger = logging.getLogger(__name__)

COMMON_MUTATIONS: list[str] = [
    "capitalize",
    "uppercase",
    "lowercase",
    "leet_speak",
    "append_numbers",
    "prepend_numbers",
    "append_symbols",
    "prepend_symbols",
    "duplicates",
    "reverse",
    "common_suffixes",
    "toggle_case",
    "duplicate_last",
    "wrap_number",
]

LEET_MAP: dict[str, list[str]] = {
    "a": ["a", "4", "@"],
    "b": ["b", "8"],
    "e": ["e", "3"],
    "g": ["g", "9"],
    "i": ["i", "1", "!", "|"],
    "l": ["l", "1", "|"],
    "o": ["o", "0"],
    "s": ["s", "5", "$"],
    "t": ["t", "7", "+"],
    "z": ["z", "2"],
}

KEYBOARD_WALKS: list[list[str]] = [
    ["q", "w", "e", "r", "t", "y"],
    ["a", "s", "d", "f", "g", "h"],
    ["z", "x", "c", "v", "b", "n"],
    ["q", "a", "z"],
    ["w", "s", "x"],
    ["e", "d", "c"],
    ["1", "2", "3", "4", "5"],
    ["!1", "@2", "#3"],
]

COMMON_SUFFIXES: list[str] = [
    "123",
    "1234",
    "12345",
    "123456",
    "!@#",
    "!!!",
    "1",
    "01",
    "001",
    "2024",
    "2025",
    "2026",
    "99",
    "69",
    "007",
    "666",
    "888",
    "00",
    "11",
    "22",
    "33",
    "44",
    "55",
    "77",
]

COMMON_SYMBOLS: list[str] = ["!", "@", "#", "$", "%", "&", "*", "?", "+", "-"]
COMMON_NUMBERS: list[str] = ["0", "1", "2", "3", "4", "5", "6", "7", "8", "9"]


class WordlistGenerator:
    """Generates custom wordlists from base words and mutation rules."""

    def __init__(self) -> None:
        self._available_rules = COMMON_MUTATIONS

    def generate(
        self,
        base_words: list[str],
        rules: list[str],
        output: Path | str,
        max_mutations: int = 100000,
    ) -> Path:
        out = Path(output)
        out.parent.mkdir(parents=True, exist_ok=True)

        all_variants: set[str] = set()

        for word in base_words:
            all_variants.add(word)
            all_variants.add(word.lower())
            all_variants.add(word.upper())
            all_variants.add(word.capitalize())

        for word in base_words:
            for rule in rules:
                variants = self._apply_rule(word, rule)
                all_variants.update(variants)

        result = sorted(all_variants)

        if len(result) > max_mutations:
            result = result[:max_mutations]

        with out.open("w", encoding="utf-8") as f:
            for variant in result:
                f.write(variant + "\n")

        logger.info(
            "Generated %d mutations from %d base words → %s",
            len(result), len(base_words), out,
        )
        return out

    def _apply_rule(self, word: str, rule: str) -> list[str]:
        handlers: dict[str, Any] = {
            "uppercase": self._rule_uppercase,
            "lowercase": self._rule_lowercase,
            "capitalize": self._rule_capitalize,
            "leet_speak": self._rule_leet,
            "append_numbers": self._rule_append_numbers,
            "prepend_numbers": self._rule_prepend_numbers,
            "append_symbols": self._rule_append_symbols,
            "prepend_symbols": self._rule_prepend_symbols,
            "duplicates": self._rule_duplicates,
            "reverse": self._rule_reverse,
            "common_suffixes": self._rule_common_suffixes,
            "toggle_case": self._rule_toggle_case,
            "duplicate_last": self._rule_duplicate_last,
            "wrap_number": self._rule_wrap_number,
        }

        handler = handlers.get(rule)
        if handler:
            return handler(word)
        logger.debug("Unknown rule: %s", rule)
        return []

    @staticmethod
    def _rule_uppercase(word: str) -> list[str]:
        return [word.upper()]

    @staticmethod
    def _rule_lowercase(word: str) -> list[str]:
        return [word.lower()]

    @staticmethod
    def _rule_capitalize(word: str) -> list[str]:
        return [word.capitalize(), word.title()]

    def _rule_leet(self, word: str) -> list[str]:
        results: list[str] = []
        candidates = [[]]

        for char in word.lower():
            replacements = LEET_MAP.get(char, [char])
            new_candidates: list[list[str]] = []
            for candidate in candidates:
                for replacement in replacements:
                    new_candidates.append(candidate + [replacement])
            candidates = new_candidates

        for candidate in candidates:
            result = "".join(candidate)
            if result != word.lower():
                results.append(result)

        return results[:50]

    @staticmethod
    def _rule_append_numbers(word: str) -> list[str]:
        results: list[str] = []
        for i in range(10):
            results.append(f"{word}{i}")
        results.append(f"{word}12")
        results.append(f"{word}123")
        results.append(f"{word}1234")
        results.append(f"{word}12345")
        results.append(f"{word}69")
        results.append(f"{word}007")
        return results

    @staticmethod
    def _rule_prepend_numbers(word: str) -> list[str]:
        results: list[str] = []
        for i in range(10):
            results.append(f"{i}{word}")
        results.append(f"12{word}")
        results.append(f"123{word}")
        return results

    @staticmethod
    def _rule_append_symbols(word: str) -> list[str]:
        return [f"{word}{s}" for s in COMMON_SYMBOLS]

    @staticmethod
    def _rule_prepend_symbols(word: str) -> list[str]:
        return [f"{s}{word}" for s in COMMON_SYMBOLS]

    @staticmethod
    def _rule_duplicates(word: str) -> list[str]:
        return [word + word, word + word[:2], word[-2:] + word]

    @staticmethod
    def _rule_reverse(word: str) -> list[str]:
        return [word[::-1]]

    @staticmethod
    def _rule_common_suffixes(word: str) -> list[str]:
        return [f"{word}{s}" for s in COMMON_SUFFIXES]

    @staticmethod
    def _rule_toggle_case(word: str) -> list[str]:
        if len(word) < 2:
            return []
        results: list[str] = []
        chars = list(word)
        for i in range(len(chars)):
            toggled = chars.copy()
            toggled[i] = toggled[i].swapcase()
            results.append("".join(toggled))
        return results

    @staticmethod
    def _rule_duplicate_last(word: str) -> list[str]:
        if not word:
            return []
        return [
            word + word[-1],
            word + word[-1] * 2,
            word + word[-1] * 3,
        ]

    @staticmethod
    def _rule_wrap_number(word: str) -> list[str]:
        return [
            f"{word}0",
            f"{word}00",
            f"{word}000",
        ]

    def generate_pins(self, length: int = 4, output: Path | str | None = None) -> list[str]:
        pins: list[str] = []
        start = 10 ** (length - 1) if length > 1 else 0
        end = 10 ** length
        for num in range(start, end):
            pins.append(str(num).zfill(length))

        if output:
            out = Path(output)
            out.parent.mkdir(parents=True, exist_ok=True)
            with out.open("w", encoding="utf-8") as f:
                for pin in pins:
                    f.write(pin + "\n")
            logger.info("Generated %d PINs → %s", len(pins), out)

        return pins

    def generate_dates(
        self,
        fmt: str = "YYYYMMDD",
        output: Path | str | None = None,
        start_year: int = 1970,
        end_year: int = 2027,
    ) -> list[str]:
        dates: list[str] = []

        common_months = range(1, 13)
        common_days = range(1, 32)

        for year in range(start_year, end_year + 1):
            for month in common_months:
                for day in common_days:
                    try:
                        from datetime import date
                        d = date(year, month, day)
                    except ValueError:
                        continue

                    if fmt == "YYYYMMDD":
                        dates.append(d.strftime("%Y%m%d"))
                    elif fmt == "MMDDYYYY":
                        dates.append(d.strftime("%m%d%Y"))
                    elif fmt == "DDMMYYYY":
                        dates.append(d.strftime("%d%m%Y"))
                    elif fmt == "YYMMDD":
                        dates.append(d.strftime("%y%m%d"))
                    elif fmt == "MMDDYY":
                        dates.append(d.strftime("%m%d%y"))
                    elif fmt == "YYYY":
                        dates.append(str(year))
                        break
                    elif fmt == "MMYYYY":
                        dates.append(d.strftime("%m%Y"))
                        break
                    else:
                        dates.append(d.strftime(fmt))

        short_dates: list[str] = []
        for year in range(start_year, end_year + 1):
            for month in common_months:
                for day in common_days:
                    try:
                        from datetime import date
                        d = date(year, month, day)
                    except ValueError:
                        continue
                    short_dates.append(d.strftime("%m%d"))
                    short_dates.append(d.strftime("%d%m"))

        combined = list(dict.fromkeys(dates + short_dates))

        if output:
            out = Path(output)
            out.parent.mkdir(parents=True, exist_ok=True)
            with out.open("w", encoding="utf-8") as f:
                for d in combined:
                    f.write(d + "\n")
            logger.info("Generated %d date patterns → %s", len(combined), out)

        return combined

    def generate_from_pattern(
        self,
        pattern: str,
        output: Path | str | None = None,
    ) -> list[str]:
        results: list[str] = []

        charset_map: dict[str, str] = {
            "?d": "0123456789",
            "?l": "abcdefghijklmnopqrstuvwxyz",
            "?u": "ABCDEFGHIJKLMNOPQRSTUVWXYZ",
            "?a": "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789",
            "?s": "!@#$%^&*()",
            "?n": "0123456789",
        }

        if pattern in charset_map:
            for char in charset_map[pattern]:
                results.append(char)
            if output:
                out = Path(output)
                out.parent.mkdir(parents=True, exist_ok=True)
                with out.open("w", encoding="utf-8") as f:
                    for r in results:
                        f.write(r + "\n")
            return results

        segments: list[list[str]] = []
        i = 0
        while i < len(pattern):
            if i + 1 < len(pattern) and pattern[i] == "?" and pattern[i + 1] in charset_map:
                segments.append(list(charset_map[pattern[i + 1]]))
                i += 2
            else:
                segments.append([pattern[i]])
                i += 1

        for combo in itertools.product(*segments):
            results.append("".join(combo))

        if output:
            out = Path(output)
            out.parent.mkdir(parents=True, exist_ok=True)
            with out.open("w", encoding="utf-8") as f:
                for r in results:
                    f.write(r + "\n")
            logger.info(
                "Generated %d words from pattern '%s' → %s",
                len(results), pattern, out,
            )

        return results

    def generate_keyboard_walks(self, output: Path | str | None = None) -> list[str]:
        results: list[str] = []

        for walk in KEYBOARD_WALKS:
            for length in range(3, min(8, len(walk) + 1)):
                for i in range(len(walk) - length + 1):
                    results.append("".join(walk[i : i + length]))
                    results.append("".join(reversed(walk[i : i + length])))
                    results.append("".join(walk[i : i + length]).capitalize())

        results = list(dict.fromkeys(results))

        if output:
            out = Path(output)
            out.parent.mkdir(parents=True, exist_ok=True)
            with out.open("w", encoding="utf-8") as f:
                for r in results:
                    f.write(r + "\n")
            logger.info("Generated %d keyboard walks → %s", len(results), out)

        return results

    @staticmethod
    def get_available_rules() -> list[str]:
        return list(COMMON_MUTATIONS)
