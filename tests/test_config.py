# ruff: noqa: SLF001, S108, ARG001
"""Tests for the wafford configuration system."""

from __future__ import annotations

import pytest
import yaml
from pydantic import ValidationError

from wafford.config import ConfigManager, WaffordConfig


def test_default_config_values() -> None:
    cfg = WaffordConfig()
    assert cfg.scan.duration == 30
    assert cfg.scan.signal_threshold == -80
    assert cfg.scan.channel_hop_dwell_ms == 50
    assert cfg.attack.deauth_packets == 5
    assert cfg.crack.attack_mode == "dictionary"
    assert cfg.crack.gpu_device_index == 0
    assert cfg.ui.theme == "DARK"
    assert cfg.network.mac_randomize is False
    assert cfg.mitm.proxy_port == 8080
    assert cfg.eapol.timeout_ms == 5000
    assert cfg.report.report_format == "html"


def test_validation_rejects_bad_duration() -> None:
    with pytest.raises(ValidationError):
        WaffordConfig(scan={"duration": 2})


def test_validation_rejects_bad_timeout() -> None:
    with pytest.raises(ValidationError):
        WaffordConfig(attack={"attack_timeout": 5})


def test_validation_rejects_bad_gps_port() -> None:
    with pytest.raises(ValidationError):
        WaffordConfig(gps={"port": 99999})


def test_minconfig_returns_lightweight_dict() -> None:
    data = ConfigManager.minconfig()
    assert data["scan"]["duration"] == 20
    assert data["scan"]["channels"] == [1, 6, 11]
    assert data["ui"]["theme"] == "DEFAULT"
    assert data["network"]["preferred_interface"] == ""
    assert data["eapol"]["enabled"] is True
    # A minconfig dict should be usable to build a WaffordConfig
    cfg = WaffordConfig(**data)
    assert cfg.scan.duration == 20


def test_load_applies_yaml_file(wafford_home, tmp_path) -> None:
    path = tmp_path / "cfg.yaml"
    path.write_text(
        yaml.safe_dump({"scan": {"duration": 120}, "ui": {"theme": "NORD"}}),
        encoding="utf-8",
    )
    mgr = ConfigManager(config_path=path)
    cfg = mgr.load()
    assert cfg.scan.duration == 120
    assert cfg.ui.theme == "NORD"
    # untouched subsections keep defaults
    assert cfg.attack.deauth_packets == 5


def test_load_uses_defaults_when_missing(wafford_home, tmp_path) -> None:
    mgr = ConfigManager(config_path=tmp_path / "nope.yaml")
    cfg = mgr.load()
    assert cfg.scan.duration == 30


def test_env_overrides_applied(wafford_home, tmp_path, monkeypatch) -> None:
    monkeypatch.setenv("WAFFORD_THEME", "OLED")
    monkeypatch.setenv("WAFFORD_LOG_LEVEL", "DEBUG")
    monkeypatch.setenv("WAFFORD_WORDLIST", "/tmp/secret.txt")
    monkeypatch.setenv("WAFFORD_INTERFACE", "wlan1")
    mgr = ConfigManager(config_path=tmp_path / "cfg.yaml")
    cfg = mgr.load()
    assert cfg.ui.theme == "OLED"
    assert cfg.logging.log_level == "DEBUG"
    assert cfg.crack.wordlist_path == "/tmp/secret.txt"
    assert cfg.network.preferred_interface == "wlan1"


def test_env_numeric_coercion(wafford_home, tmp_path, monkeypatch) -> None:
    monkeypatch.setenv("WAFFORD_GPS_PORT", "2949")
    monkeypatch.setenv("WAFFORD_GPU_INDEX", "3")
    mgr = ConfigManager(config_path=tmp_path / "cfg.yaml")
    cfg = mgr.load()
    assert cfg.gps.port == 2949
    assert cfg.crack.gpu_device_index == 3


def test_config_path_from_env(wafford_home, tmp_path, monkeypatch) -> None:
    path = tmp_path / "env_cfg.yaml"
    path.write_text(yaml.safe_dump({"scan": {"duration": 90}}), encoding="utf-8")
    monkeypatch.setenv("WAFFORD_CONFIG", str(path))
    mgr = ConfigManager()
    cfg = mgr.load()
    assert cfg.scan.duration == 90


def test_save_and_reload_roundtrip(wafford_home, tmp_path) -> None:
    path = tmp_path / "cfg.yaml"
    mgr = ConfigManager(config_path=path)
    cfg = mgr.load()
    cfg.scan.duration = 240
    cfg.ui.theme = "CYBERPUNK"
    mgr.save()

    mgr2 = ConfigManager(config_path=path)
    cfg2 = mgr2.load()
    assert cfg2.scan.duration == 240
    assert cfg2.ui.theme == "CYBERPUNK"


def test_get_dotted_accessor(wafford_home, tmp_path) -> None:
    mgr = ConfigManager(config_path=tmp_path / "cfg.yaml")
    mgr.load()
    assert mgr.get("scan.duration") == 30
    assert mgr.get("missing.key", "fallback") == "fallback"


def test_set_dotted_accessor(wafford_home, tmp_path) -> None:
    mgr = ConfigManager(config_path=tmp_path / "cfg.yaml")
    mgr.load()
    mgr.set("scan.duration", 60)
    assert mgr.get("scan.duration") == 60


def test_set_unknown_key_raises(wafford_home, tmp_path) -> None:
    mgr = ConfigManager(config_path=tmp_path / "cfg.yaml")
    mgr.load()
    with pytest.raises(KeyError):
        mgr.set("scan.bogus_field", 1)


def test_config_property_raises_before_load(wafford_home, tmp_path) -> None:
    mgr = ConfigManager(config_path=tmp_path / "cfg.yaml")
    with pytest.raises(RuntimeError):
        _ = mgr.config


def test_reset_returns_defaults(wafford_home, tmp_path) -> None:
    path = tmp_path / "cfg.yaml"
    mgr = ConfigManager(config_path=path)
    mgr.load()
    mgr.set("scan.duration", 300)
    reset_cfg = mgr.reset()
    assert reset_cfg.scan.duration == 30


def test_to_dict_contains_sections(wafford_home, tmp_path) -> None:
    mgr = ConfigManager(config_path=tmp_path / "cfg.yaml")
    mgr.load()
    data = mgr.to_dict()
    for key in (
        "scan", "attack", "crack", "ui", "network", "gps",
        "mitm", "eapol", "report", "logging",
    ):
        assert key in data


def test_profiles_applied(wafford_home, tmp_path) -> None:
    mgr = ConfigManager(config_path=tmp_path / "cfg.yaml", profile="minimal")
    cfg = mgr.load()
    assert cfg.scan.duration == 20
    assert cfg.ui.color_output is False
    assert cfg.logging.log_to_file is False
    assert mgr.profile == "minimal"


def test_full_profile_applied(wafford_home, tmp_path) -> None:
    mgr = ConfigManager(config_path=tmp_path / "cfg.yaml", profile="full")
    cfg = mgr.load()
    assert cfg.scan.duration == 120
    assert cfg.network.mac_randomize is True
    assert cfg.autopwn.enabled is True


def test_unknown_profile_falls_back(wafford_home, tmp_path) -> None:
    mgr = ConfigManager(config_path=tmp_path / "cfg.yaml", profile="bogus")
    cfg = mgr.load()
    assert mgr.profile == "default"
    assert cfg.scan.duration == 30


def test_list_profiles() -> None:
    profiles = ConfigManager.list_profiles()
    assert "default" in profiles
    assert "minimal" in profiles
    assert "full" in profiles


def test_headless_mode(wafford_home, tmp_path) -> None:
    mgr = ConfigManager(config_path=tmp_path / "cfg.yaml", headless=True)
    assert mgr.is_headless is True
    cfg = mgr.load()
    assert cfg.scan.duration == 30
    assert mgr.profile == "default"


def test_load_headless_classmethod(wafford_home) -> None:
    cfg = ConfigManager.load_headless()
    assert cfg.scan.duration == 30


def test_validate_reports_missing_wordlist(wafford_home, tmp_path) -> None:
    mgr = ConfigManager(config_path=tmp_path / "cfg.yaml")
    mgr.load()
    # Set a non-existent wordlist path to trigger validation warning
    mgr.set("crack.wordlist_path", "/nonexistent/wordlist.txt")
    warnings = mgr.validate()
    assert any("Wordlist not found" in w for w in warnings)


def test_deep_merge() -> None:
    base = {"scan": {"duration": 30, "channels": [1, 6, 11]}}
    override = {"scan": {"duration": 60}}
    merged = ConfigManager._deep_merge(base, override)
    assert merged["scan"]["duration"] == 60
    assert merged["scan"]["channels"] == [1, 6, 11]
