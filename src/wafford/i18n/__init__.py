from wafford.i18n.loader import I18nLoader, LocaleManager

_default_loader = I18nLoader()

t = _default_loader.t
set_language = _default_loader.set_language
get_language = _default_loader.get_language
available_languages = _default_loader.available_languages
gettext = _default_loader.t

__all__ = [
    "I18nLoader",
    "LocaleManager",
    "t",
    "set_language",
    "get_language",
    "available_languages",
    "gettext",
]
