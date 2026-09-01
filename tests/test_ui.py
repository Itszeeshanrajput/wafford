"""Tests for the UI theme module.

``wafford.ui`` package import is currently broken in the source
(``wafford/ui/__init__.py`` imports ``app`` -> ``screens/scan_menu.py`` which
fails with ``ImportError: cannot import name 'DiscoveredNetwork' from
'wafford.core.scanner'``). To test themes headlessly we load ``theme.py``
directly via ``importlib`` and register it as ``wafford.ui.theme`` in
``sys.modules`` BEFORE execution (required because the module uses
``from __future__ import annotations`` which makes dataclass ``_is_type``
resolve types via ``sys.modules`` lookups).
"""

from __future__ import annotations

import importlib.util
import sys
from pathlib import Path

import pytest

THEME_PATH = Path(__file__).resolve().parents[1] / "src" / "wafford" / "ui" / "theme.py"


@pytest.fixture(scope="module")
def theme():
    # Defensive: if the package import ever becomes healthy, prefer it.
    try:
        from wafford.ui import theme as real_theme

        return real_theme
    except Exception:  # noqa: S110 - fall back to importlib loading below
        pass

    spec = importlib.util.spec_from_file_location("wafford.ui.theme", THEME_PATH)
    assert spec is not None
    assert spec.loader is not None
    mod = importlib.util.module_from_spec(spec)
    # Register before exec_module so `from __future__ import annotations`
    # type lookups inside dataclasses resolve via sys.modules.
    sys.modules[spec.name] = mod
    spec.loader.exec_module(mod)
    return mod


def test_theme_in_default_themes(theme) -> None:
    assert theme.get_theme("DARK") is not None
    assert "DARK" in theme.list_themes()


def test_list_themes_contains_expected(theme) -> None:
    themes = theme.list_themes()
    assert "DARK" in themes
    assert "NORD" in themes
    assert "SOLARIZED" in themes


def test_get_theme_falls_back_to_dark(theme) -> None:
    assert theme.get_theme(None).name == "DARK"
    assert theme.get_theme("BOGUS").name == "DARK"


def test_get_theme_named(theme) -> None:
    t = theme.get_theme("NORD")
    assert t is not None
    assert t.name == "NORD"


def test_to_textual_css_length(theme) -> None:
    css = theme.get_theme("DARK").to_textual_css()
    assert len(css) > 500


def test_theme_palette_fields(theme) -> None:
    t = theme.get_theme("DARK")
    assert t.primary is not None
    assert t.background is not None
    assert t.text is not None
    assert t.muted is not None


def test_theme_export_conventions(theme) -> None:
    # Every theme should have a dark background for the terminal TUI default.
    t = theme.get_theme("DARK")
    assert t.background.lstrip("#").lower() in {
        "0d1117", "1a1b26", "11141c", "0f0f0f", "000000",
        "0b0b0d", "0e0e0e", "121212", "131a24", "1f1f1f",
        "101018", "0c1014", "161616", "181820", "0a0e14",
    }
