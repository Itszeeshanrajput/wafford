"""Shared pytest fixtures for the wafford test suite."""

from __future__ import annotations

import sys
from pathlib import Path

import pytest

import wafford.config as config_mod

SRC = Path(__file__).resolve().parent.parent / "src"
if str(SRC) not in sys.path:
    sys.path.insert(0, str(SRC))


@pytest.fixture
def wafford_home(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> Path:
    """Redirect all wafford filesystem constants under a temp directory.

    This keeps tests fully headless and prevents creating real dirs under
    ``~/.wafford`` (e.g. when ``ConfigManager.load()`` creates directories).
    """
    home = tmp_path / "wafford_home"
    data = home / "data"
    logs = home / "logs"
    reports = home / "reports"
    plugins = home / "plugins"
    backups = home / "backups"
    temp = home / "tmp"

    for name, value in (
        ("WAFFORD_HOME", home),
        ("DATA_DIR", data),
        ("LOG_DIR", logs),
        ("REPORT_DIR", reports),
        ("PLUGIN_DIR", plugins),
        ("BACKUP_DIR", backups),
        ("TEMP_DIR", temp),
    ):
        monkeypatch.setattr(config_mod, name, Path(value))
    monkeypatch.setenv("WAFFORD_HOME", str(home))
    return home
