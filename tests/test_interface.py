# ruff: noqa: SLF001, S108, ARG005
"""Tests for interface detection, monitor mode, and MAC randomisation."""

from __future__ import annotations

from unittest import mock

import pytest

from wafford.core.interface import AdapterInfo, InterfaceManager

# ── AdapterInfo ────────────────────────────────────────────────────────────

def test_adapter_info_to_dict() -> None:
    info = AdapterInfo(
        name="wlan0",
        mac="00:11:22:33:44:55",
        chipset="rtl8812au",
        driver="rtl8812au",
        physical_id="phy0",
        supported_bands=["2.4GHz", "5GHz"],
        mode="monitor",
    )
    d = info.to_dict()
    assert d["name"] == "wlan0"
    assert d["mac"] == "00:11:22:33:44:55"
    assert d["mode"] == "monitor"
    assert d["is_physical"] is True


def test_adapter_info_defaults() -> None:
    info = AdapterInfo(name="wlan1")
    assert info.mac == ""
    assert info.mode == "managed"
    assert info.supported_bands == []


# ── Vendor lookup & signal helpers ─────────────────────────────────────────

def test_lookup_vendor_known() -> None:
    assert InterfaceManager.lookup_vendor("00:1B:2F:AA:BB:CC") == "Netgear"


def test_lookup_vendor_case_insensitive_prefix() -> None:
    assert InterfaceManager.lookup_vendor("b8:27:eb:00:00:01") == "Raspberry-Pi"


def test_lookup_vendor_unknown() -> None:
    assert InterfaceManager.lookup_vendor("DE:AD:BE:EF:00:01") == "Unknown"


def test_signal_to_bar_boundaries() -> None:
    assert InterfaceManager.signal_to_bar(-20) == "▂▄▆█"
    assert InterfaceManager.signal_to_bar(-40) == "▂▄▆░"
    assert InterfaceManager.signal_to_bar(-58) == "▂▄░░"
    assert InterfaceManager.signal_to_bar(-68) == "▂░░░"
    assert InterfaceManager.signal_to_bar(-80) == "░░░░"
    assert InterfaceManager.signal_to_bar(-100) == ""


def test_signal_to_percent() -> None:
    assert InterfaceManager.signal_to_percent(-110) == 0
    assert InterfaceManager.signal_to_percent(-50) == 100
    assert InterfaceManager.signal_to_percent(-75) == 50


# ── MAC output parsing ─────────────────────────────────────────────────────

def test_parse_macchanger_output() -> None:
    out = "Current MAC:   00:11:22:33:44:55 (unknown)\nPermanent MAC: aa:bb:cc:dd:ee:ff"
    assert InterfaceManager._parse_macchanger_output(out, "Current MAC") == "00:11:22:33:44:55"


def test_parse_macchanger_output_missing() -> None:
    assert InterfaceManager._parse_macchanger_output("no mac here", "Current MAC") == ""


# ── Renamed interface detection ────────────────────────────────────────────

def test_detect_renamed_interface_from_output() -> None:
    mgr = InterfaceManager()
    out = "monitor mode enabled on wlan0mon\n"
    assert mgr._detect_renamed_interface("wlan0", out) == "wlan0mon"


def test_detect_renamed_interface_fallback_original() -> None:
    mgr = InterfaceManager()
    assert mgr._detect_renamed_interface("wlan0", "") == "wlan0"


# ── Monitor mode toggle ────────────────────────────────────────────────────

def _fake_proc(returncode: int = 0, stdout: str = "", stderr: str = ""):
    return mock.Mock(returncode=returncode, stdout=stdout, stderr=stderr)


def test_set_monitor_mode_success(monkeypatch) -> None:
    mgr = InterfaceManager()
    monkeypatch.setattr(
        "wafford.core.interface.shutil.which",
        lambda name: "/usr/bin/" + name,
    )
    monkeypatch.setattr(
        "wafford.core.interface.subprocess.run",
        lambda *a, **k: _fake_proc(stdout="monitor mode enabled on wlan0mon"),
    )
    monkeypatch.setattr(
        mgr, "_build_adapter_info",
        lambda iface: AdapterInfo(name=iface, mode="monitor"),
    )
    monkeypatch.setattr(mgr, "kill_conflicting_processes", list)
    info = mgr.set_monitor_mode("wlan0")
    assert info.name == "wlan0mon"
    assert info.mode == "monitor"


def test_set_monitor_mode_missing_tool(monkeypatch) -> None:
    mgr = InterfaceManager()
    monkeypatch.setattr("wafford.core.interface.shutil.which", lambda name: None)
    from wafford.exceptions import ToolNotFoundError

    with pytest.raises(ToolNotFoundError):
        mgr.set_monitor_mode("wlan0")


def test_set_monitor_mode_failure(monkeypatch) -> None:
    mgr = InterfaceManager()
    monkeypatch.setattr(
        "wafford.core.interface.shutil.which",
        lambda name: "/usr/bin/" + name,
    )
    monkeypatch.setattr(
        "wafford.core.interface.subprocess.run",
        lambda *a, **k: _fake_proc(returncode=1, stderr="airmon-ng error"),
    )
    monkeypatch.setattr(mgr, "kill_conflicting_processes", list)
    from wafford.exceptions import InterfaceError

    with pytest.raises(InterfaceError):
        mgr.set_monitor_mode("wlan0")


def test_set_managed_mode_success(monkeypatch) -> None:
    mgr = InterfaceManager()
    monkeypatch.setattr(
        "wafford.core.interface.shutil.which",
        lambda name: "/usr/bin/" + name,
    )
    monkeypatch.setattr(
        "wafford.core.interface.subprocess.run",
        lambda *a, **k: _fake_proc(),
    )
    monkeypatch.setattr(
        mgr, "_build_adapter_info",
        lambda iface: AdapterInfo(name=iface, mode="managed"),
    )
    info = mgr.set_managed_mode("wlan0mon")
    assert info.name == "wlan0"
    assert info.mode == "managed"


# ── MAC randomisation with mocked subprocess ───────────────────────────────

def test_randomize_mac_success(monkeypatch) -> None:
    mgr = InterfaceManager()
    monkeypatch.setattr(
        "wafford.core.interface.shutil.which",
        lambda name: "/usr/bin/" + name,
    )
    captured: list[list[str]] = []

    def fake_run(argv, **_kwargs):
        captured.append(list(argv))
        return _fake_proc(stdout="Current MAC:   ab:cd:ef:00:11:22 (randomized)")

    monkeypatch.setattr("wafford.core.interface.subprocess.run", fake_run)
    new_mac = mgr.randomize_mac("wlan0")
    assert new_mac == "ab:cd:ef:00:11:22"
    # interface taken down then brought back up
    assert ["ip", "link", "set", "wlan0", "down"] in captured
    assert ["ip", "link", "set", "wlan0", "up"] in captured


# ── Interface auto-selection ───────────────────────────────────────────────

def test_auto_select_interface_returns_none_when_empty(monkeypatch) -> None:
    mgr = InterfaceManager()
    monkeypatch.setattr(mgr, "detect_interfaces", list)
    assert mgr.auto_select_interface() is None


def test_auto_select_prefers_injection_driver(monkeypatch) -> None:
    mgr = InterfaceManager()
    adapters = [
        AdapterInfo(name="wlan1", driver="wlcore", supported_bands=["2.4GHz"]),
        AdapterInfo(name="wlan0", driver="ath9k", supported_bands=["2.4GHz", "5GHz"]),
    ]
    monkeypatch.setattr(mgr, "detect_interfaces", lambda: adapters)
    selected = mgr.auto_select_interface()
    assert selected is not None
    assert selected.name == "wlan0"
