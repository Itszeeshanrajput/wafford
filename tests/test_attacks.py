# ruff: noqa: SLF001, S108, ARG001, S105
"""Tests for attack modules: deauth, handshake, PMKID, WEP, evil twin,
captive portal and DoS.

Only pure-logic / command-building / parsing methods are exercised here.
Anything that would require hardware, root, or real system tools is either
mocked (``_run_cmd``, ``subprocess``, ``shell.run``) or skipped.
"""

from __future__ import annotations

from pathlib import Path
from unittest import mock

import pytest

from wafford.core.captive_portal import CaptivePortal
from wafford.core.deauth import DeauthAttack, DeauthStats
from wafford.core.dos import DoSAttack, DoSMethod, DoSProgress
from wafford.core.evil_twin import EvilTwin
from wafford.core.handshake import HandshakeCapture
from wafford.core.pmkid import PMKIDAttack
from wafford.core.wep import WEPAttack, WEPStats
from wafford.exceptions import ValidationError


def _read(p: Path) -> str:
    return Path(p).read_text(encoding="utf-8", errors="replace")


def _allow_tools(attack) -> None:
    """Monkeypatch tool availability so no real binaries are needed."""
    attack._require_tool = mock.Mock(return_value="/usr/bin/tool")


# ── Deauth ─────────────────────────────────────────────────────────────────

def test_deauth_validate_mac() -> None:
    DeauthAttack._validate_mac("AA:BB:CC:DD:EE:FF")
    with pytest.raises(ValidationError):
        DeauthAttack._validate_mac("bad-mac")


def test_deauth_aireplay_argv() -> None:
    attack = DeauthAttack(interface="wlan0mon")
    argv = attack._aireplay_argv("AA:BB:CC:DD:EE:FF", "11:22:33:44:55:66", 5)
    assert argv == [
        "aireplay-ng", "--deauth", "5", "-a", "AA:BB:CC:DD:EE:FF",
        "-c", "11:22:33:44:55:66", "--ignore-negative-one", "wlan0mon",
    ]


def test_deauth_mdk4_argv() -> None:
    attack = DeauthAttack(interface="wlan0mon", use_mdk4=True)
    argv = attack._mdk4_deauth_argv("AA:BB:CC:DD:EE:FF", 3, "11:22:33:44:55:66")
    assert argv == [
        "mdk4", "wlan0mon", "d", "-B", "AA:BB:CC:DD:EE:FF",
        "-c", "11:22:33:44:55:66", "-n", "3",
    ]


def test_deauth_stats_properties() -> None:
    stats = DeauthStats(clients_targeted={"aa", "bb"}, clients_deauthed={"aa"})
    assert stats.total_clients == 2
    assert stats.deauthed_count == 1


async def test_deauth_targeted_sends_command() -> None:
    attack = DeauthAttack(interface="wlan0mon")
    _allow_tools(attack)
    captured: list[list[str]] = []

    async def fake_run(argv, timeout=None, capture=True):
        captured.append(list(argv))
        return (0, "", "")

    attack._run_cmd = fake_run
    result = await attack.targeted_deauth("AA:BB:CC:DD:EE:FF", "11:22:33:44:55:66", count=4)
    assert result.success
    assert "aireplay-ng" in captured[0]
    assert attack.stats.packets_sent == 8


async def test_deauth_selective_empty_list_raises() -> None:
    attack = DeauthAttack(interface="wlan0mon")
    with pytest.raises(ValidationError):
        await attack.selective_deauth("AA:BB:CC:DD:EE:FF", [])


# ── Handshake ──────────────────────────────────────────────────────────────

def test_handshake_validate_mac() -> None:
    HandshakeCapture._validate_mac("AA:BB:CC:DD:EE:FF")
    with pytest.raises(ValidationError):
        HandshakeCapture._validate_mac("nope")


async def test_handshake_capture_invalid_channel() -> None:
    hs = HandshakeCapture(interface="wlan0mon", output_dir="/tmp")
    with pytest.raises(ValidationError):
        await hs.capture("AA:BB:CC:DD:EE:FF", channel=999)


def test_handshake_find_cap_file(tmp_path) -> None:
    hs = HandshakeCapture(interface="wlan0mon", output_dir=tmp_path)
    base = tmp_path / "capture"
    (tmp_path / "capture-01.cap").write_text("x", encoding="utf-8")
    assert hs._find_cap_file(base) == str(tmp_path / "capture-01.cap")


def test_handshake_find_cap_file_none(tmp_path) -> None:
    hs = HandshakeCapture(interface="wlan0mon", output_dir=tmp_path)
    assert hs._find_cap_file(tmp_path / "missing") is None


async def test_handshake_validate_internal_complete(tmp_path) -> None:
    hs = HandshakeCapture(interface="wlan0mon", output_dir=tmp_path)
    cap = tmp_path / "hs.cap"
    cap.write_text("fake", encoding="utf-8")

    async def fake_run(argv, timeout=None, capture=True):
        if argv[0] == "aircrack-ng":
            return (0, "00:1B:2F:AA:BB:CC WPA (1 handshake)  WPA2", "")
        return (0, "100 packets captured", "")

    hs._run_cmd = fake_run
    info = await hs.validate_handshake(str(cap))
    assert info.status == "complete"
    assert info.packets == 100
    assert info.packets == 100


async def test_handshake_convert_to_hccapx(tmp_path) -> None:
    hs = HandshakeCapture(interface="wlan0mon", output_dir=tmp_path)
    _allow_tools(hs)

    async def fake_run(argv, timeout=None, capture=True):
        return (0, "", "")

    hs._run_cmd = fake_run
    out = await hs.convert_to_hccapx("/tmp/in.cap", "/tmp/out.hccapx")
    assert out == "/tmp/out.hccapx"


# ── PMKID ──────────────────────────────────────────────────────────────────

def test_pmkid_validate_mac() -> None:
    PMKIDAttack._validate_mac("AA:BB:CC:DD:EE:FF")
    with pytest.raises(ValidationError):
        PMKIDAttack._validate_mac("zz")


async def test_pmkid_capture_invalid_channel() -> None:
    pm = PMKIDAttack(interface="wlan0mon", output_dir="/tmp")
    with pytest.raises(ValidationError):
        await pm.capture("AA:BB:CC:DD:EE:FF", channel=0)


def test_pmkid_find_pcapng(tmp_path) -> None:
    pm = PMKIDAttack(interface="wlan0mon", output_dir=tmp_path)
    (tmp_path / "base-01.pcapng").write_text("x", encoding="utf-8")
    assert pm._find_pcapng(tmp_path / "base") == str(tmp_path / "base-01.pcapng")


async def test_pmkid_extract_pmkid(tmp_path) -> None:
    pm = PMKIDAttack(interface="wlan0mon", output_dir=tmp_path)
    _allow_tools(pm)
    hash_file = tmp_path / "h.22000"
    hash_file.write_text("1234", encoding="utf-8")

    async def fake_run(argv, timeout=None, capture=True):
        return (0, "PMKID : a1b2c3d4e5f60718293a4b5c6d7e8f90\n 123 packets", "")

    pm._run_cmd = fake_run
    await pm._extract_pmkid("/tmp/in.pcapng", str(hash_file))
    assert pm.pmkid.pmkid_found is True
    assert pm.pmkid.pmkid_hex == "a1b2c3d4e5f60718293a4b5c6d7e8f90"
    assert pm.pmkid.packets_captured == 123


# ── WEP ────────────────────────────────────────────────────────────────────

def test_wep_validate_mac() -> None:
    WEPAttack._validate_mac("AA:BB:CC:DD:EE:FF")
    with pytest.raises(ValidationError):
        WEPAttack._validate_mac("x")


def test_wep_stats_progress() -> None:
    stats = WEPStats(key_length=64, ivs_captured=2500)
    assert stats.progress == pytest.approx(0.5)
    stats128 = WEPStats(key_length=128, ivs_captured=10000)
    assert stats128.progress == 1.0


async def test_wep_ptw_invalid_iv_target() -> None:
    attack = WEPAttack(interface="wlan0mon", output_dir="/tmp")
    with pytest.raises(ValidationError):
        await attack.ptw_attack("AA:BB:CC:DD:EE:FF", 6, iv_target=100)


async def test_wep_crack_finds_key(tmp_path) -> None:
    attack = WEPAttack(interface="wlan0mon", output_dir=tmp_path)
    _allow_tools(attack)
    cap = tmp_path / "ivs.cap"
    cap.write_text("x", encoding="utf-8")

    async def fake_run(argv, timeout=None, capture=True):
        return (0, "KEY FOUND! [ AA:BB:CC:DD:EE:FF ]", "")

    attack._run_cmd = fake_run
    result = await attack.crack(str(cap))
    assert result.success
    assert result.password == "AA:BB:CC:DD:EE:FF"


# ── Evil Twin ──────────────────────────────────────────────────────────────

def test_evil_twin_hostapd_config_open(tmp_path) -> None:
    et = EvilTwin(interface="wlan0mon", config_dir=tmp_path)
    path = et._write_hostapd_config("MyNet", 6, "open")
    content = _read(path)
    assert "interface=wlan0mon" in content
    assert "ssid=MyNet" in content
    assert "channel=6" in content
    assert "wpa=2" not in content


def test_evil_twin_hostapd_config_wpa2(tmp_path) -> None:
    et = EvilTwin(interface="wlan0mon", config_dir=tmp_path)
    path = et._write_hostapd_config("MyNet", 6, "wpa2")
    content = _read(path)
    assert "wpa=2" in content
    assert "wpa_passphrase=wafford12345" in content


def test_evil_twin_dnsmasq_config(tmp_path) -> None:
    et = EvilTwin(interface="wlan0mon", config_dir=tmp_path)
    path = et._write_dnsmasq_config("10.0.0.1", "8.8.8.8")
    content = _read(path)
    assert "interface=wlan0mon" in content
    assert "dhcp-range=10.0.0.100,10.0.0.254,255.255.255.0,1h" in content
    assert "address=/#/10.0.0.1" in content


async def test_evil_twin_start_empty_ssid() -> None:
    et = EvilTwin(interface="wlan0mon", config_dir="/tmp")
    with pytest.raises(ValidationError):
        await et.start(ssid="")


async def test_evil_twin_monitor_clients() -> None:
    et = EvilTwin(interface="wlan0mon", config_dir="/tmp")
    async def fake_run(argv, timeout=None, capture=True):
        return (0, "AA:BB:CC:DD:EE:FF\n11:22:33:44:55:66\n", "")

    et._run_cmd = fake_run
    macs = await et.monitor_connected_clients()
    assert macs == ["AA:BB:CC:DD:EE:FF", "11:22:33:44:55:66"]
    assert et.twin.clients_connected == {"AA:BB:CC:DD:EE:FF", "11:22:33:44:55:66"}


# ── Captive Portal ─────────────────────────────────────────────────────────

def test_captive_portal_generate_known_template() -> None:
    cp = CaptivePortal()
    html = cp.generate_portal("generic")
    assert "<h2>WiFi Access</h2>" in html
    assert html == cp.generate_portal("generic")  # stable


def test_captive_portal_unknown_template() -> None:
    cp = CaptivePortal()
    with pytest.raises(ValidationError):
        cp.generate_portal("does_not_exist")


def test_captive_portal_custom_requires_html() -> None:
    cp = CaptivePortal()
    with pytest.raises(ValidationError):
        cp.generate_portal("custom")


def test_captive_portal_custom_html() -> None:
    cp = CaptivePortal()
    html = cp.generate_portal("custom", custom_html="<h1>privacy</h1>")
    assert html == "<h1>privacy</h1>"


def test_captive_portal_harvest_empty() -> None:
    cp = CaptivePortal()
    assert cp.harvest_credentials() == []
    assert cp.get_captured_count() == 0


def test_captive_portal_deauth_decoding_uses_unquote_plus() -> None:
    # The POST body decoder uses urllib.parse.unquote_plus, so special
    # characters in passwords survive (plan flagged this historically).
    import urllib.parse

    assert urllib.parse.unquote_plus("p%40ss%2Bword") == "p@ss+word"
    assert urllib.parse.unquote_plus("hello+world") == "hello world"


# ── DoS ────────────────────────────────────────────────────────────────────

async def test_dos_check_injection_ok() -> None:
    attack = DoSAttack(interface="wlan0mon")
    attack.shell.run = mock.Mock(return_value=mock.Mock(returncode=0))
    assert await attack._check_injection() is True


async def test_dos_check_injection_fail() -> None:
    attack = DoSAttack(interface="wlan0mon")
    attack.shell.run = mock.Mock(return_value=mock.Mock(returncode=1))
    assert await attack._check_injection() is False


async def test_dos_set_channel() -> None:
    attack = DoSAttack(interface="wlan0mon")
    attack.shell.run = mock.Mock(return_value=mock.Mock(returncode=0))
    await attack._set_channel(6)
    attack.shell.run.assert_called_once()


def test_dos_progress_callback() -> None:
    attack = DoSAttack(interface="wlan0mon")
    received: list[DoSProgress] = []
    attack.on_progress(received.append)
    progress = DoSProgress(method="deauth", target="X")
    attack._emit_progress(progress)
    assert received == [progress]


def test_dos_enum_values() -> None:
    assert DoSMethod.AUTH_FLOOD.value == "auth"
    assert DoSMethod.DEAUTH_FLOOD.value == "deauth"
    assert DoSMethod.BEACON_FLOOD.value == "beacon"
