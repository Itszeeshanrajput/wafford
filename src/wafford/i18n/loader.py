import json
import logging
import os
import threading
from pathlib import Path
from typing import Any

logger = logging.getLogger("wafford.i18n")

LOCALE_DIR = Path(
    os.environ.get("WAFFORD_LOCALE_DIR", Path(__file__).resolve().parent / "locales")
)

SUPPORTED_LANGUAGES = ["en", "es", "fr", "de", "pt", "ru", "zh", "ja", "ar"]
DEFAULT_LANGUAGE = "en"
FALLBACK_LANGUAGE = "en"


def _deep_get(data: dict[str, Any], keys: list[str]) -> Any:
    current = data
    for key in keys:
        if not isinstance(current, dict):
            return None
        current = current.get(key)
    return current


def _deep_set(data: dict[str, Any], keys: list[str], value: Any):
    current = data
    for key in keys[:-1]:
        if not isinstance(current.get(key), dict):
            current[key] = {}
        current = current[key]
    current[keys[-1]] = value


class I18nLoader:
    def __init__(self, locale_dir: Path | None = None):
        self._locale_dir = Path(locale_dir) if locale_dir else LOCALE_DIR
        self._translations: dict[str, dict[str, Any]] = {}
        self._lock = threading.RLock()
        self._current_language = DEFAULT_LANGUAGE
        self._fallback_language = FALLBACK_LANGUAGE

    def load_language(self, lang_code: str) -> bool:
        lang_code = lang_code.lower()
        file_path = self._locale_dir / f"{lang_code}.json"
        if not file_path.exists():
            logger.warning("Locale file not found for language '%s' at %s", lang_code, file_path)
            return False
        try:
            with file_path.open(encoding="utf-8") as fh:
                data = json.load(fh)
        except (json.JSONDecodeError, OSError) as exc:
            logger.error("Failed to load locale '%s': %s", lang_code, exc)
            return False
        with self._lock:
            self._translations[lang_code] = data
        logger.info("Loaded language '%s' (%d top-level groups)", lang_code, len(data))
        return True

    def set_language(self, lang_code: str) -> bool:
        lang_code = lang_code.lower()
        if lang_code not in self._translations:
            if not self.load_language(lang_code):
                return False
        if lang_code not in self._translations:
            return False
        with self._lock:
            self._current_language = lang_code
        return True

    def get_language(self) -> str:
        with self._lock:
            return self._current_language

    def available_languages(self) -> list[str]:
        languages = []
        for file_path in self._locale_dir.glob("*.json"):
            languages.append(file_path.stem.lower())
        languages.sort()
        return languages

    def t(self, key: str, **kwargs: Any) -> str:
        with self._lock:
            current = self._translations.get(self._current_language, {})
            fallback = self._translations.get(self._fallback_language, {})

        value = _deep_get(current, key.split("."))
        if value is None:
            value = _deep_get(fallback, key.split("."))
        if value is None:
            return key

        if not isinstance(value, str):
            return str(value)

        return self._interpolate(value, kwargs)

    def translate(self, key: str, **kwargs: Any) -> str:
        return self.t(key, **kwargs)

    def _interpolate(self, template: str, kwargs: dict[str, Any]) -> str:
        if not kwargs:
            return template
        result = template
        for name, value in kwargs.items():
            result = result.replace("{" + name + "}", str(value))
        return result

    def get(self, key: str, default: str | None = None, **kwargs: Any) -> str:
        value = self.t(key, **kwargs)
        if value == key and default is not None:
            return default
        return value

    def has_key(self, key: str) -> bool:
        with self._lock:
            current = self._translations.get(self._current_language, {})
            fallback = self._translations.get(self._fallback_language, {})
        return _deep_get(current, key.split(".")) is not None or \
            _deep_get(fallback, key.split(".")) is not None

    def all_translations(self, lang_code: str | None = None) -> dict[str, Any]:
        code = lang_code or self._current_language
        with self._lock:
            return dict(self._translations.get(code, {}))

    def add_translation(self, lang_code: str, key: str, value: Any):
        with self._lock:
            if lang_code not in self._translations:
                self._translations[lang_code] = {}
            _deep_set(self._translations[lang_code], key.split("."), value)

    def preload_all(self):
        for lang in SUPPORTED_LANGUAGES:
            if lang not in self._translations:
                self.load_language(lang)

    def format(self, key: str, **kwargs: Any) -> str:
        return self.t(key, **kwargs)


LocaleManager = I18nLoader


_global = I18nLoader()
_global.preload_all()
