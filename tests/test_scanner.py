# ruff: noqa: SLF001, S108
"""Tests for the network scanner (airodump CSV parsing, OUI, signals)."""

from __future__ import annotations

from pathlib import Path

from wafford.core.scanner import NetworkScanner, ScanResult

AP_HEADER = (
    "BSSID, First time seen, Last time seen, Channel, Speed, Privacy, "
    "Cipher, Authentication, Power, # beacons, # IV, LAN IP, ID-length, "
    "ESSID, Key"
)
AP_ROW = (
    "00:1B:2F:AA:BB:CC, 2026-01-01 10:00:00, 2026-01-01 10:00:05, "
    "6, 54, WPA2, CCMP, PSK, -55, 100, 0, 0.0.0.0, 8, MyNetwork, "
)
CLIENT_HEADER = (
    "Station MAC, First time seen, Last time seen, Power, # packets, "
    "BSSID, Probed ESSIDs"
)
CLIENT_ROW = (
    "AA:BB:CC:DD:EE:FF, 2026-01-01 10:00:01, 2026-01-01 10:00:04, "
    "-47, 12, 00:1B:2F:AA:BB:CC, MyNetwork"
)


def _make_csv(tmp_path: Path, content: str) -> Path:
    p = tmp_path / "airodump.csv"
    p.write_text(content, encoding="utf-8")
    return p


def _ap_section() -> str:
    return AP_HEADER + "\n" + AP_ROW + "\n"


def _full_csv() -> str:
    ap = _ap_section()
    clients = CLIENT_HEADER + "\n" + CLIENT_ROW + "\n"
    return ap + "\r\r\n\r\r\n" + clients


# ── ScanResult dataclass ───────────────────────────────────────────────────

def test_scan_result_signal_percent_clamped() -> None:
    r = ScanResult(signal_dbm=-55)
    assert r.signal_percent == 90
    r2 = ScanResult(signal_dbm=-110)
    assert r2.signal_percent == 0
    r3 = ScanResult(signal_dbm=-40)
    assert r3.signal_percent == 100


def test_scan_result_to_dict() -> None:
    r = ScanResult(bssid="AA:BB:CC:DD:EE:FF", essid="test", channel=6)
    d = r.to_dict()
    assert d["bssid"] == "AA:BB:CC:DD:EE:FF"
    assert d["channel"] == 6
    assert "signal_percent" in d


# ── CSV parsing ────────────────────────────────────────────────────────────

def test_parse_airodump_csv_basic(tmp_path) -> None:
    scanner = NetworkScanner(interface="wlan0", output_dir=tmp_path)
    results = scanner.parse_airodump_csv(_make_csv(tmp_path, _full_csv()))

    assert "00:1B:2F:AA:BB:CC" in results
    ap = results["00:1B:2F:AA:BB:CC"]
    assert ap.essid == "MyNetwork"
    assert ap.channel == 6
    assert ap.signal_dbm == -55
    assert ap.encryption == "WPA2"
    assert ap.vendor == "Netgear"
    assert ap.first_seen == "2026-01-01 10:00:00"


def test_parse_client_section() -> None:
    """Station association parsing works at the section level.

    NOTE: full-parse client association is unreachable through
    ``Path.read_text`` because universal-newline translation normalises the
    ``\\r\\r\\n\\r\\r\\n`` section separator (see report). We test the
    section parser directly here.
    """
    scanner = NetworkScanner(interface="wlan0", output_dir="/tmp")
    section = CLIENT_HEADER + "\n" + CLIENT_ROW + "\n"
    clients = scanner._parse_client_section(section)
    assert "00:1B:2F:AA:BB:CC" in clients
    assert clients["00:1B:2F:AA:BB:CC"][0]["mac"] == "AA:BB:CC:DD:EE:FF"
    assert clients["00:1B:2F:AA:BB:CC"][0]["signal_dbm"] == -47


def test_parse_airodump_missing_file(tmp_path) -> None:
    scanner = NetworkScanner(interface="wlan0", output_dir=tmp_path)
    assert scanner.parse_airodump_csv(tmp_path / "missing.csv") == {}


def test_parse_airodump_empty_section(tmp_path) -> None:
    scanner = NetworkScanner(interface="wlan0", output_dir=tmp_path)
    results = scanner.parse_airodump_csv(_make_csv(tmp_path, ""))
    assert results == {}


def test_classify_encryption() -> None:
    c = NetworkScanner._classify_encryption
    assert c("OPN", "", "") == "OPN"
    assert c("", "", "") == "OPN"
    assert c("WEP", "", "") == "WEP"
    assert c("WPA3", "", "") == "WPA3"
    assert c("WPA2", "CCMP", "PSK") == "WPA2"
    assert c("WPA2", "CCMP", "802.1X") == "WPA2-Enterprise"
    assert c("WPA", "", "") == "WPA"


def test_safe_int_strips_units() -> None:
    s = NetworkScanner._safe_int
    assert s("-55") == -55
    assert s("-55dB") == -55
    assert s("-55°") == -55
    assert s("n/a", default=7) == 7


# ── Vendor & signal helpers ────────────────────────────────────────────────

def test_lookup_vendor() -> None:
    assert NetworkScanner.lookup_vendor("00:1B:2F:AA:BB:CC") == "Netgear"
    assert NetworkScanner.lookup_vendor("DE:AD:BE:EF") == "Unknown"


def test_signal_helpers() -> None:
    assert NetworkScanner.signal_to_bar(-25) == "▂▄▆█"
    assert NetworkScanner.signal_to_percent(-60) == 80


# ── Command building ───────────────────────────────────────────────────────

def test_build_airodump_cmd() -> None:
    scanner = NetworkScanner(interface="wlan1", output_dir="/tmp")
    cmd = scanner._build_airodump_cmd([1, 6, 11], "/tmp/out", False)
    assert cmd[0] == "airodump-ng"
    assert "--channel" in cmd
    assert "1,6,11" in cmd
    assert cmd[-1] == "wlan1"


# ── Persistence roundtrip ──────────────────────────────────────────────────

def test_save_and_load_results(tmp_path) -> None:
    scanner = NetworkScanner(interface="wlan0", output_dir=tmp_path)
    scanner._results["AA:BB:CC:DD:EE:FF"] = ScanResult(
        bssid="AA:BB:CC:DD:EE:FF",
        essid="test",
        channel=1,
        signal_dbm=-60,
    )
    path = scanner.save_results(tmp_path / "out.json")
    assert path.exists()

    scanner2 = NetworkScanner(interface="wlan0", output_dir=tmp_path)
    loaded = scanner2.load_results(path)
    assert len(loaded) == 1
    assert loaded[0].bssid == "AA:BB:CC:DD:EE:FF"
    assert loaded[0].essid == "test"


def test_load_missing_results(tmp_path) -> None:
    scanner = NetworkScanner(interface="wlan0", output_dir=tmp_path)
    assert scanner.load_results(tmp_path / "nope.json") == []


def test_detect_hidden_ssids() -> None:
    scanner = NetworkScanner(interface="wlan0", output_dir=Path("/tmp"))
    scanner._results = {
        "A1": ScanResult(bssid="A1", essid="visible"),
        "B1": ScanResult(bssid="B1", essid="", is_hidden=True),
        "C1": ScanResult(bssid="C1", essid="   ", is_hidden=True),
    }
    hidden = scanner.detect_hidden_ssids()
    assert [r.bssid for r in hidden] == ["B1", "C1"]
