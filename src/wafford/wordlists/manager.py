"""Wordlist management for the Wafford framework."""

from __future__ import annotations

import hashlib
import logging
import math
from collections import Counter
from dataclasses import dataclass
from pathlib import Path
from typing import Any

logger = logging.getLogger(__name__)

WORDLIST_DIR = Path.home() / ".wafford" / "wordlists"


@dataclass
class WordlistInfo:
    """Metadata for a wordlist file."""

    name: str
    path: Path
    size: int
    word_count: int
    entropy: float
    avg_length: float
    charset: str
    md5: str = ""
    sha256: str = ""
    encoding: str = "utf-8"
    first_word: str = ""
    last_word: str = ""

    def to_dict(self) -> dict[str, Any]:
        return {
            "name": self.name,
            "path": str(self.path),
            "size": self.size,
            "size_human": self._human_size(self.size),
            "word_count": self.word_count,
            "entropy": round(self.entropy, 4),
            "avg_length": round(self.avg_length, 2),
            "charset": self.charset,
            "md5": self.md5,
            "sha256": self.sha256,
            "encoding": self.encoding,
            "first_word": self.first_word,
            "last_word": self.last_word,
        }

    @staticmethod
    def _human_size(size: int) -> str:
        for unit in ("B", "KB", "MB", "GB", "TB"):
            if size < 1024:
                return f"{size:.1f} {unit}"
            size /= 1024
        return f"{size:.1f} PB"


class WordlistManager:
    """Manages wordlists for WiFi password auditing."""

    def __init__(self, wordlist_dir: Path | str | None = None) -> None:
        self._dir = Path(wordlist_dir) if wordlist_dir else WORDLIST_DIR
        self._dir.mkdir(parents=True, exist_ok=True)
        self._info_cache: dict[str, WordlistInfo] = {}

    @property
    def directory(self) -> Path:
        return self._dir

    def list_wordlists(self) -> list[WordlistInfo]:
        wordlists: list[WordlistInfo] = []
        if not self._dir.exists():
            return wordlists

        for entry in sorted(self._dir.rglob("*.txt")):
            try:
                info = self.get_info(entry)
                wordlists.append(info)
            except Exception:
                logger.debug("Failed to read wordlist: %s", entry, exc_info=True)

        for entry in sorted(self._dir.rglob("*.lst")):
            try:
                info = self.get_info(entry)
                wordlists.append(info)
            except Exception:
                logger.debug("Failed to read wordlist: %s", entry, exc_info=True)

        return wordlists

    def get_info(self, wordlist_path: Path | str) -> WordlistInfo:
        path = Path(wordlist_path).resolve()
        cache_key = str(path)
        if cache_key in self._info_cache:
            return self._info_cache[cache_key]

        if not path.exists():
            raise FileNotFoundError(f"Wordlist not found: {path}")

        stat = path.stat()
        stats = self.get_stats(path)

        md5 = hashlib.md5()  # noqa: S324
        sha256 = hashlib.sha256()
        with path.open("rb") as f:
            for chunk in iter(lambda: f.read(8192), b""):
                md5.update(chunk)
                sha256.update(chunk)

        first_word = ""
        last_word = ""
        try:
            with path.open(encoding="utf-8", errors="replace") as f:
                for line in f:
                    stripped = line.strip()
                    if stripped:
                        first_word = stripped
                        break
                for line in f:
                    stripped = line.strip()
                    if stripped:
                        last_word = stripped
        except OSError:
            pass

        info = WordlistInfo(
            name=path.name,
            path=path,
            size=stat.st_size,
            word_count=stats["word_count"],
            entropy=stats["entropy"],
            avg_length=stats["avg_length"],
            charset=stats["charset"],
            md5=md5.hexdigest(),
            sha256=sha256.hexdigest(),
            first_word=first_word,
            last_word=last_word,
        )

        self._info_cache[cache_key] = info
        return info

    def get_stats(self, wordlist_path: Path | str) -> dict[str, Any]:
        path = Path(wordlist_path)
        if not path.exists():
            raise FileNotFoundError(f"Wordlist not found: {path}")

        word_count = 0
        total_length = 0
        char_counter: Counter[str] = Counter()
        max_length = 0
        min_length = float("inf")

        try:
            with path.open(encoding="utf-8", errors="replace") as f:
                for line in f:
                    word = line.strip()
                    if not word:
                        continue
                    word_count += 1
                    word_len = len(word)
                    total_length += word_len
                    max_length = max(max_length, word_len)
                    min_length = min(min_length, word_len)
                    for char in word:
                        char_counter[char] += 1
        except OSError as exc:
            logger.error("Failed to read wordlist %s: %s", path, exc)
            return {
                "word_count": 0,
                "avg_length": 0,
                "min_length": 0,
                "max_length": 0,
                "entropy": 0,
                "charset": "",
            }

        if word_count == 0:
            return {
                "word_count": 0,
                "avg_length": 0,
                "min_length": 0,
                "max_length": 0,
                "entropy": 0,
                "charset": "",
            }

        avg_length = total_length / word_count

        total_chars = sum(char_counter.values())
        entropy = 0.0
        for count in char_counter.values():
            prob = count / total_chars
            if prob > 0:
                entropy -= prob * math.log2(prob)

        charset_parts: list[str] = []
        for char, count in sorted(char_counter.items(), key=lambda x: -x[1]):
            if char.isalpha():
                if char == char.lower():
                    charset_parts.append(f"lower({count})")
                else:
                    charset_parts.append(f"upper({count})")
            elif char.isdigit():
                charset_parts.append(f"digits({count})")
            else:
                charset_parts.append(f"special({count})")

        charset = ", ".join(charset_parts[:10])

        return {
            "word_count": word_count,
            "avg_length": avg_length,
            "min_length": min_length if min_length != float("inf") else 0,
            "max_length": max_length,
            "entropy": entropy,
            "charset": charset,
        }

    def preview(self, wordlist_path: Path | str, lines: int = 50) -> list[str]:
        path = Path(wordlist_path)
        if not path.exists():
            raise FileNotFoundError(f"Wordlist not found: {path}")

        result: list[str] = []
        try:
            with path.open(encoding="utf-8", errors="replace") as f:
                for i, line in enumerate(f):
                    if i >= lines:
                        break
                    result.append(line.strip())
        except OSError as exc:
            logger.error("Failed to preview wordlist: %s", exc)

        return result

    @staticmethod
    def sort(wordlist_path: Path | str, output: Path | str) -> Path:
        path = Path(wordlist_path)
        out = Path(output)
        if not path.exists():
            raise FileNotFoundError(f"Wordlist not found: {path}")

        words: list[str] = []
        with path.open(encoding="utf-8", errors="replace") as f:
            for line in f:
                words.append(line.strip())

        words.sort()

        out.parent.mkdir(parents=True, exist_ok=True)
        with out.open("w", encoding="utf-8") as f:
            for word in words:
                f.write(word + "\n")

        logger.info("Sorted %d words to %s", len(words), out)
        return out

    @staticmethod
    def deduplicate(wordlist_path: Path | str, output: Path | str) -> Path:
        path = Path(wordlist_path)
        out = Path(output)
        if not path.exists():
            raise FileNotFoundError(f"Wordlist not found: {path}")

        seen: set[str] = set()
        unique: list[str] = []
        duplicates = 0

        with path.open(encoding="utf-8", errors="replace") as f:
            for line in f:
                word = line.strip()
                if word not in seen:
                    seen.add(word)
                    unique.append(word)
                else:
                    duplicates += 1

        out.parent.mkdir(parents=True, exist_ok=True)
        with out.open("w", encoding="utf-8") as f:
            for word in unique:
                f.write(word + "\n")

        logger.info(
            "Deduplicated %s: %d unique words, %d duplicates removed",
            path.name, len(unique), duplicates,
        )
        return out

    @staticmethod
    def merge(wordlist_paths: list[Path | str], output: Path | str) -> Path:
        out = Path(output)
        all_words: list[str] = []
        for path_str in wordlist_paths:
            path = Path(path_str)
            if not path.exists():
                logger.warning("Wordlist not found, skipping: %s", path)
                continue
            try:
                with path.open(encoding="utf-8", errors="replace") as f:
                    for line in f:
                        word = line.strip()
                        if word:
                            all_words.append(word)
            except OSError as exc:
                logger.error("Failed to read %s: %s", path, exc)

        out.parent.mkdir(parents=True, exist_ok=True)
        with out.open("w", encoding="utf-8") as f:
            for word in all_words:
                f.write(word + "\n")

        logger.info(
            "Merged %d wordlists into %s (%d words)", len(wordlist_paths), out, len(all_words)
        )
        return out

    @staticmethod
    def filter_by_length(
        wordlist_path: Path | str,
        min_len: int,
        max_len: int,
        output: Path | str,
    ) -> Path:
        path = Path(wordlist_path)
        out = Path(output)
        if not path.exists():
            raise FileNotFoundError(f"Wordlist not found: {path}")

        filtered: list[str] = []
        with path.open(encoding="utf-8", errors="replace") as f:
            for line in f:
                word = line.strip()
                if min_len <= len(word) <= max_len:
                    filtered.append(word)

        out.parent.mkdir(parents=True, exist_ok=True)
        with out.open("w", encoding="utf-8") as f:
            for word in filtered:
                f.write(word + "\n")

        logger.info(
            "Filtered by length [%d-%d]: %d words remain", min_len, max_len, len(filtered)
        )
        return out

    @staticmethod
    def filter_by_charset(
        wordlist_path: Path | str,
        charset: str,
        output: Path | str,
    ) -> Path:
        path = Path(wordlist_path)
        out = Path(output)
        if not path.exists():
            raise FileNotFoundError(f"Wordlist not found: {path}")

        allowed = set(charset)
        filtered: list[str] = []
        with path.open(encoding="utf-8", errors="replace") as f:
            for line in f:
                word = line.strip()
                if all(c in allowed for c in word):
                    filtered.append(word)

        out.parent.mkdir(parents=True, exist_ok=True)
        with out.open("w", encoding="utf-8") as f:
            for word in filtered:
                f.write(word + "\n")

        logger.info(
            "Filtered by charset '%s': %d words remain", charset, len(filtered)
        )
        return out

    @staticmethod
    def split(
        wordlist_path: Path | str,
        parts: int,
        output_dir: Path | str,
    ) -> list[Path]:
        path = Path(wordlist_path)
        out_dir = Path(output_dir)
        if not path.exists():
            raise FileNotFoundError(f"Wordlist not found: {path}")
        if parts < 1:
            raise ValueError("Parts must be at least 1")

        out_dir.mkdir(parents=True, exist_ok=True)

        all_words: list[str] = []
        with path.open(encoding="utf-8", errors="replace") as f:
            for line in f:
                word = line.strip()
                if word:
                    all_words.append(word)

        chunk_size = math.ceil(len(all_words) / parts)
        stem = path.stem

        output_files: list[Path] = []
        for i in range(parts):
            start = i * chunk_size
            end = min(start + chunk_size, len(all_words))
            chunk = all_words[start:end]
            if not chunk:
                break

            out_path = out_dir / f"{stem}_part{i + 1}.txt"
            with out_path.open("w", encoding="utf-8") as f:
                for word in chunk:
                    f.write(word + "\n")
            output_files.append(out_path)

        logger.info("Split into %d parts in %s", len(output_files), out_dir)
        return output_files

    @staticmethod
    def delete(wordlist_path: Path | str) -> bool:
        path = Path(wordlist_path)
        if not path.exists():
            logger.warning("Wordlist not found for deletion: %s", path)
            return False

        try:
            if path.is_file():
                path.unlink()
                logger.info("Deleted wordlist: %s", path)
                return True
            if path.is_dir():
                import shutil
                shutil.rmtree(path)
                logger.info("Deleted wordlist directory: %s", path)
                return True
        except OSError as exc:
            logger.error("Failed to delete %s: %s", path, exc)
            return False

        return False
