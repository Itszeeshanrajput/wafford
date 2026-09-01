"""Constants used throughout the Wafford framework."""

from __future__ import annotations

import enum
from pathlib import Path

# ── Filesystem paths ─────────────────────────────────────────────────────────
HOME_DIR: Path = Path.home()
WAFFORD_HOME: Path = Path(
    __import__("os").environ.get("WAFFORD_HOME", str(HOME_DIR / ".wafford"))
)
CONFIG_FILE: Path = WAFFORD_HOME / "config.yaml"
DATA_DIR: Path = WAFFORD_HOME / "data"
DB_PATH: Path = DATA_DIR / "wafford.db"
LOG_DIR: Path = WAFFORD_HOME / "logs"
REPORT_DIR: Path = WAFFORD_HOME / "reports"
PLUGIN_DIR: Path = WAFFORD_HOME / "plugins"
BACKUP_DIR: Path = WAFFORD_HOME / "backups"
TEMP_DIR: Path = WAFFORD_HOME / "tmp"

# ── Required system tools ────────────────────────────────────────────────────
TOOL_PATHS: dict[str, str] = {
    "airmon-ng": "/usr/bin/airmon-ng",
    "airodump-ng": "/usr/bin/airodump-ng",
    "aireplay-ng": "/usr/bin/aireplay-ng",
    "aircrack-ng": "/usr/bin/aircrack-ng",
    "airebase": "/usr/bin/airebase",
    "mdk3": "/usr/bin/mdk3",
    "mdk4": "/usr/bin/mdk4",
    "reaver": "/usr/bin/reaver",
    "bully": "/usr/bin/bully",
    "hashcat": "/usr/bin/hashcat",
    "john": "/usr/bin/john",
    "macchanger": "/usr/bin/macchanger",
    "lsusb": "/usr/bin/lsusb",
    "lspci": "/usr/bin/lspci",
    "iw": "/usr/sbin/iw",
    "iwconfig": "/usr/sbin/iwconfig",
    "ifconfig": "/usr/sbin/ifconfig",
    "ip": "/usr/sbin/ip",
    "rfkill": "/usr/sbin/rfkill",
    "curl": "/usr/bin/curl",
    "python3": "/usr/bin/python3",
}

REQUIRED_TOOLS: list[str] = [
    "airmon-ng",
    "airodump-ng",
    "aireplay-ng",
    "aircrack-ng",
    "iw",
    "rfkill",
    "macchanger",
]

OPTIONAL_TOOLS: list[str] = [
    "mdk3",
    "mdk4",
    "reaver",
    "bully",
    "hashcat",
    "john",
    "airebase",
]


# ── Enums ─────────────────────────────────────────────────────────────────────
class AttackType(enum.Enum):
    """Supported attack types."""

    DEAUTH = "deauth"
    DISASSOC = "disassoc"
    AUTH = "auth"
    BEACON = "beacon"
    NULL = "null"
    QUERY = "query"
    EAPOL = "eapol"
    WPS_PIN = "wps_pin"
    WPS_PIXIE = "wps_pixie"
    HANDSHAKE = "handshake"
    PMKID = "pmkid"
    EVIL_TWIN = "evil_twin"
    CAPTIVE_PORTAL = "captive_portal"
    CAFFE_LATTE = "caffe_latte"
    CHOPCHOP = "chopchop"
    FRAGMENT = "fragment"
    INJECTION = "injection"


class EncryptionType(enum.Enum):
    """Network encryption types."""

    OPN = "OPN"
    WEP = "WEP"
    WPA = "WPA"
    WPA2 = "WPA2"
    WPA3 = "WPA3"
    WPA2_ENTERPRISE = "WPA2-Enterprise"
    UNKNOWN = "Unknown"


class ScanMode(enum.Enum):
    """Scan mode options."""

    PASSIVE = "passive"
    ACTIVE = "active"
    CHANNEL_HOP = "channel_hop"


class MonitorState(enum.Enum):
    """Monitor mode states."""

    MANAGED = "managed"
    MONITOR = "monitor"
    UNKNOWN = "unknown"


class SignalStrength(enum.Enum):
    """Signal strength categories."""

    EXCELLENT = "excellent"
    GOOD = "good"
    FAIR = "fair"
    WEAK = "weak"
    NONE = "none"


# ── WiFi channels ─────────────────────────────────────────────────────────────
WIFI_CHANNELS_2_4_GHZ: list[int] = [
    1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11,
    12, 13, 14,
]

WIFI_CHANNELS_5_GHZ: list[int] = [
    36, 40, 44, 48, 52, 56, 60, 64,
    100, 104, 108, 112, 116, 120, 124, 128,
    132, 136, 140, 144, 149, 153, 157, 161, 165,
    169, 173,
]

WIFI_CHANNELS_6_GHZ: list[int] = [
    1, 5, 9, 13, 17, 21, 25, 29,
    33, 37, 41, 45, 49, 53, 57, 61,
    65, 69, 73, 77, 81, 85, 89, 93,
    97, 101, 105, 109, 113, 117, 121, 125,
]

WIFI_CHANNELS: list[int] = WIFI_CHANNELS_2_4_GHZ + WIFI_CHANNELS_5_GHZ

BANDS: dict[str, list[int]] = {
    "2.4GHz": WIFI_CHANNELS_2_4_GHZ,
    "5GHz": WIFI_CHANNELS_5_GHZ,
    "6GHz": WIFI_CHANNELS_6_GHZ,
    "all": WIFI_CHANNELS,
}

DEFAULT_CHANNELS: list[int] = [1, 6, 11]

# ── Defaults ──────────────────────────────────────────────────────────────────
DEFAULT_WORDLISTS: list[str] = [
    "/usr/share/wordlists/rockyou.txt",
    "/usr/share/wordlists/seclists/Passwords/Common-Credentials/10k-most-common.txt",
    "/usr/share/wordlists/seclists/Passwords/Common-Credentials/100k-most-used.txt",
    "/usr/share/wordlists/fern-wifi/common.txt",
]

DEFAULT_DEAUTH_COUNT: int = 5
DEFAULT_SCAN_DURATION: int = 30
DEFAULT_ATTACK_TIMEOUT: int = 60
DEFAULT_INTERFACE_TIMEOUT: int = 10
DEFAULT_CHANNEL_HOP_INTERVAL: float = 0.5
DEFAULT_SIGNAL_THRESHOLD: int = -80

# ── Portal templates ─────────────────────────────────────────────────────────
PORTAL_TEMPLATES: dict[str, str] = {
    "default": "Captive portal with password prompt",
    "firmware": "Router firmware update page",
    "social": "Social media login page",
    "terms": "Terms of service acceptance page",
    "captive": "Generic captive portal redirect",
}

# ── UI strings ────────────────────────────────────────────────────────────────
BANNER: str = r"""
    __        __   _    _  _______ _______
    \ \      / /  | |  | |/ / ____|_   _|
     \ \ /\ / /__ | |__/ // /__   | |
      \ V  V / _ \|  __  /| '__|  | |
       \   //  __/| |  | || |     | |
        \_/ \___/|_|  |_||_|     |_|
        WiFi Auditing Framework v{version}
"""

# ── Exit codes ────────────────────────────────────────────────────────────────
class ExitCode(enum.IntEnum):
    """Process exit codes."""

    SUCCESS = 0
    GENERAL_ERROR = 1
    USAGE_ERROR = 2
    NO_ROOT = 3
    NO_INTERFACE = 4
    TOOL_MISSING = 5
    CONFIG_ERROR = 6
    DATABASE_ERROR = 7
    ATTACK_FAILED = 8
    SCAN_FAILED = 9
    CRACK_FAILED = 10
    PLUGIN_ERROR = 11
    INTERRUPTED = 130
