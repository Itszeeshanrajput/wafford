"""External tool detection for the Wafford framework."""

from __future__ import annotations

import logging
import os
import re
import shutil
from pathlib import Path
from typing import Any

logger = logging.getLogger(__name__)

SEARCH_PATHS: list[str] = [
    "/usr/bin",
    "/usr/local/bin",
    "/usr/sbin",
    "/usr/local/sbin",
    "/opt",
    "/snap/bin",
    "/home",
]

REQUIRED_TOOLS: dict[str, dict[str, Any]] = {
    "aircrack-ng": {"package": "aircrack-ng", "version_flag": "--version"},
    "aireplay-ng": {"package": "aircrack-ng", "version_flag": "--version"},
    "airodump-ng": {"package": "aircrack-ng", "version_flag": "--version"},
    "airmon-ng": {"package": "aircrack-ng", "version_flag": "--version"},
    "hashcat": {"package": "hashcat", "version_flag": "--version"},
    "hostapd": {"package": "hostapd", "version_flag": "-v"},
    "dnsmasq": {"package": "dnsmasq", "version_flag": "--version"},
    "mdk4": {"package": "mdk4", "version_flag": "--version"},
    "macchanger": {"package": "macchanger", "version_flag": "--version"},
    "hcxdumptool": {"package": "hcxdumptool", "version_flag": "--version"},
    "hcxpcapngtool": {"package": "hcxtools", "version_flag": "--version"},
    "iw": {"package": "iw", "version_flag": "--version"},
    "rfkill": {"package": "rfkill", "version_flag": "--version"},
    "iwlist": {"package": "wireless-tools", "version_flag": "--version"},
}

OPTIONAL_TOOLS: dict[str, dict[str, Any]] = {
    "reaver": {"package": "reaver", "version_flag": "-h"},
    "bully": {"package": "bully", "version_flag": "--version"},
    "pixiewps": {"package": "pixiewps", "version_flag": "--version"},
    "john": {"package": "john", "version_flag": "--help"},
    "nmap": {"package": "nmap", "version_flag": "--version"},
    "mdk3": {"package": "mdk3", "version_flag": "--version"},
    "ettercap": {"package": "ettercap-text-only", "version_flag": "--version"},
    "mitmproxy": {"package": "mitmproxy", "version_flag": "--version"},
}


class ToolDetector:
    """Detects external tools installed on the system."""

    def __init__(self) -> None:
        self._tool_cache: dict[str, dict[str, Any]] = {}
        self._search_paths: list[Path] = self._build_search_paths()

    @staticmethod
    def _build_search_paths() -> list[Path]:
        paths: list[Path] = []
        for base in SEARCH_PATHS:
            p = Path(base)
            if p.exists():
                paths.append(p)
        path_env = os.environ.get("PATH", "")
        for segment in path_env.split(os.pathsep):
            p = Path(segment)
            if p.exists() and p not in paths:
                paths.append(p)
        return paths

    def detect_all(self) -> dict[str, dict[str, Any]]:
        all_tools: dict[str, dict[str, Any]] = {}
        for name, _meta in REQUIRED_TOOLS.items():
            all_tools[name] = self.detect_tool(name)
            all_tools[name]["required"] = True
        for name, _meta in OPTIONAL_TOOLS.items():
            all_tools[name] = self.detect_tool(name)
            all_tools[name]["required"] = False
        return all_tools

    def detect_tool(self, name: str) -> dict[str, Any]:
        if name in self._tool_cache:
            return dict(self._tool_cache[name])

        result: dict[str, Any] = {
            "found": False,
            "version": None,
            "path": None,
            "required": name in REQUIRED_TOOLS,
        }

        binary = self._find_binary(name)
        if binary is None:
            self._tool_cache[name] = result
            return dict(result)

        result["found"] = True
        result["path"] = str(binary)
        result["version"] = self.get_version(binary)

        self._tool_cache[name] = result
        return dict(result)

    def _find_binary(self, name: str) -> Path | None:
        found = shutil.which(name)
        if found:
            return Path(found)

        for base_dir in self._search_paths:
            candidate = base_dir / name
            if candidate.is_file() and os.access(candidate, os.X_OK):
                return candidate

        for base_dir in self._search_paths:
            if not base_dir.exists():
                continue
            try:
                for entry in base_dir.rglob(name):
                    if entry.is_file() and os.access(entry, os.X_OK):
                        return entry
            except PermissionError:
                continue
        return None

    def get_version(self, binary_path: Path | str) -> str | None:
        path = Path(binary_path)
        meta = REQUIRED_TOOLS.get(path.name) or OPTIONAL_TOOLS.get(path.name)
        flag = meta["version_flag"] if meta else "--version"

        try:
            import subprocess

            result = subprocess.run(
                [str(path), flag],
                capture_output=True,
                text=True,
                timeout=10,
            )
            output = result.stdout + result.stderr
            return self._parse_version(output)
        except (subprocess.TimeoutExpired, FileNotFoundError, OSError):
            return None

    @staticmethod
    def _parse_version(output: str) -> str | None:
        patterns = [
            r"(?:version|v)\s*(\d+\.\d+(?:\.\d+)?(?:[a-zA-Z0-9._-]*)?)",
            r"(\d+\.\d+\.\d+)",
            r"(\d+\.\d+)",
        ]
        for pattern in patterns:
            match = re.search(pattern, output, re.IGNORECASE)
            if match:
                return match.group(1)
        return None

    def get_status(self) -> dict[str, dict[str, Any]]:
        return self.detect_all()

    def get_summary(self) -> str:
        status = self.get_status()
        required_found = sum(
            1 for name in REQUIRED_TOOLS if status.get(name, {}).get("found", False)
        )
        total_required = len(REQUIRED_TOOLS)
        optional_found = sum(
            1 for name in OPTIONAL_TOOLS if status.get(name, {}).get("found", False)
        )
        total_optional = len(OPTIONAL_TOOLS)
        return (
            f"{required_found}/{total_required} required tools found, "
            f"{optional_found}/{total_optional} optional tools found"
        )

    @staticmethod
    def check_root() -> bool:
        return os.geteuid() == 0

    @staticmethod
    def check_wifi_adapter() -> list[str]:
        wireless_dir = Path("/sys/class/net")
        interfaces: list[str] = []
        if not wireless_dir.exists():
            return interfaces
        for iface_dir in wireless_dir.iterdir():
            wireless_path = iface_dir / "wireless"
            if wireless_path.exists():
                interfaces.append(iface_dir.name)
        return interfaces

    @staticmethod
    def get_adapter_info(iface: str) -> dict[str, Any]:
        info: dict[str, Any] = {
            "interface": iface,
            "driver": None,
            "chipset": None,
            "capabilities": [],
            "mac": None,
            "supported_modes": [],
        }

        driver_link = Path(f"/sys/class/net/{iface}/device/driver")
        if driver_link.exists():
            try:
                info["driver"] = driver_link.resolve().name
            except OSError:
                pass

        uevent_path = Path(f"/sys/class/net/{iface}/device/uevent")
        if uevent_path.exists():
            try:
                content = uevent_path.read_text(encoding="utf-8", errors="replace")
                for line in content.splitlines():
                    if line.startswith("DRIVER="):
                        info["driver"] = line.split("=", 1)[1]
                    elif line.startswith("PCI_ID="):
                        info["chipset"] = line.split("=", 1)[1]
            except OSError:
                pass

        address_path = Path(f"/sys/class/net/{iface}/address")
        if address_path.exists():
            try:
                info["mac"] = address_path.read_text(encoding="utf-8").strip()
            except OSError:
                pass

        try:
            import subprocess

            result = subprocess.run(
                ["iw", "dev", iface, "info"],
                capture_output=True,
                text=True,
                timeout=5,
            )
            for line in result.stdout.splitlines():
                stripped = line.strip()
                if stripped.startswith("type "):
                    mode = stripped.split(None, 1)[1]
                    info["supported_modes"].append(mode)
                elif "supports " in stripped or "command set:" in stripped:
                    info["capabilities"].append(stripped)
        except (FileNotFoundError, subprocess.TimeoutExpired, OSError):
            pass

        try:
            import subprocess

            result = subprocess.run(
                ["ethtool", "-i", iface],
                capture_output=True,
                text=True,
                timeout=5,
            )
            for line in result.stdout.splitlines():
                if line.strip().startswith("driver:"):
                    info["driver"] = line.split(":", 1)[1].strip()
                elif line.strip().startswith("bus-info:"):
                    info["chipset"] = line.split(":", 1)[1].strip()
        except (FileNotFoundError, subprocess.TimeoutExpired, OSError):
            pass

        try:
            import subprocess

            result = subprocess.run(
                ["iw", "dev", iface, "info"],
                capture_output=True,
                text=True,
                timeout=5,
            )
            modes: list[str] = []
            for line in result.stdout.splitlines():
                stripped = line.strip()
                if stripped.startswith("Supported "):
                    modes.append(stripped)
            if modes:
                info["capabilities"].extend(modes)
        except (FileNotFoundError, subprocess.TimeoutExpired, OSError):
            pass

        phy_path = Path(f"/sys/class/net/{iface}/phy80211/name")
        if phy_path.exists():
            try:
                phy_name = phy_path.read_text(encoding="utf-8").strip()
                info["phy"] = phy_name
                info["supported_modes"] = ToolDetector._get_phy_modes(phy_name)
            except OSError:
                pass

        return info

    @staticmethod
    def _get_phy_modes(phy_name: str) -> list[str]:
        modes: list[str] = []
        try:
            import subprocess

            result = subprocess.run(
                ["iw", "phy", phy_name, "info"],
                capture_output=True,
                text=True,
                timeout=5,
            )
            in_modes = False
            for line in result.stdout.splitlines():
                if "Supported interface modes:" in line:
                    in_modes = True
                    continue
                if in_modes:
                    stripped = line.strip()
                    if stripped and not stripped.startswith("*"):
                        modes.append(stripped)
                    elif stripped.startswith("*") and modes:
                        break
        except (FileNotFoundError, subprocess.TimeoutExpired, OSError):
            pass
        return modes
