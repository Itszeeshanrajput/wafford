"""Wireless interface detection, monitor mode management, and MAC randomisation."""

from __future__ import annotations

import logging
import re
import shutil
import subprocess
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

logger = logging.getLogger(__name__)

# ── OUI vendor prefixes (small local subset) ─────────────────────────────────
_OUI_DB: dict[str, str] = {
    "00:14:6C": "Pelco",
    "00:1A:2B": "Ayecom",
    "00:1B:2F": "Netgear",
    "00:1E:58": "D-Link",
    "00:22:6B": "Cisco-Linksys",
    "00:24:01": "D-Link",
    "00:26:F2": "Netgear",
    "00:90:4C": "Epigram",
    "04:A1:51": "Netgear",
    "08:36:69": "Ubiquiti",
    "0C:80:63": "TP-Link",
    "10:0C:6B": "Netgear",
    "10:DA:43": "Netgear",
    "14:59:C0": "Netgear",
    "14:91:82": "Belkin",
    "18:E8:29": "Ubiquiti",
    "1C:3B:F3": "Huawei",
    "20:E5:2A": "Netgear",
    "24:05:0F": "Ubiquiti",
    "2C:B0:5D": "Netgear",
    "30:B5:C2": "TP-Link",
    "34:97:F6": "ASUSTek",
    "38:2C:4A": "ASUSTek",
    "3C:37:86": "Netgear",
    "40:4A:03": "ZyXEL",
    "44:94:FC": "Ubiquiti",
    "48:EE:0C": "D-Link",
    "4C:ED:FB": "ASUSTek",
    "50:6A:03": "Netgear",
    "54:04:A6": "ASUSTek",
    "58:EF:68": "Belkin",
    "5C:CF:7F": "Espressif",
    "60:38:E0": "Belkin",
    "60:45:CB": "Belkin",
    "60:A4:4C": "ASUSTek",
    "64:66:B3": "D-Link",
    "68:72:51": "Ubiquiti",
    "6C:99:61": "Sagemcom",
    "70:4D:7B": "ASUSTek",
    "74:AC:B9": "Ubiquiti",
    "78:8A:20": "Ubiquiti",
    "7C:8B:CA": "TP-Link",
    "80:2A:A8": "Ubiquiti",
    "84:1B:5E": "D-Link",
    "88:DC:96": "EnGenius",
    "8C:3B:AD": "Netgear",
    "90:72:40": "Apple",
    "94:10:3E": "Belkin",
    "98:DE:D0": "TP-Link",
    "9C:3D:CF": "Netgear",
    "A0:04:60": "Netgear",
    "A0:20:A6": "Aruba",
    "A0:63:91": "Netgear",
    "A4:2B:B0": "TP-Link",
    "A8:5E:45": "ASUSTek",
    "AC:22:0B": "TP-Link",
    "AC:84:C6": "TP-Link",
    "B0:4E:26": "TP-Link",
    "B0:7F:B9": "Netgear",
    "B0:BE:76": "TP-Link",
    "B4:FB:E4": "Ubiquiti",
    "B8:27:EB": "Raspberry-Pi",
    "B8:EE:65": "Netgear",
    "BC:EE:7B": "ASUSTek",
    "C0:25:E9": "TP-Link",
    "C0:4A:00": "TP-Link",
    "C4:6E:1F": "TP-Link",
    "C4:71:54": "TP-Link",
    "C8:3A:35": "Tenda",
    "CC:40:D0": "Netgear",
    "D0:21:F9": "Ubiquiti",
    "D4:6E:5E": "TP-Link",
    "D4:AA:FF": "Microchip",
    "D8:07:B6": "TP-Link",
    "D8:50:E6": "ASUSTek",
    "DC:9F:DB": "Ubiquiti",
    "DC:A6:32": "Raspberry-Pi",
    "E0:63:DA": "Ubiquiti",
    "E4:F0:04": "Google",
    "E8:94:F6": "TP-Link",
    "EC:08:6B": "TP-Link",
    "EC:1A:59": "Belkin",
    "F0:9F:C2": "Ubiquiti",
    "F0:9F:E2": "Ubiquiti",
    "F4:EC:38": "TP-Link",
    "F8:1A:67": "TP-Link",
    "FC:EC:DA": "Ubiquiti",
}


@dataclass
class AdapterInfo:
    """Describes a wireless adapter detected on the system."""

    name: str
    mac: str = ""
    chipset: str = ""
    driver: str = ""
    physical_id: str = ""
    supported_bands: list[str] = field(default_factory=list)
    mode: str = "managed"
    is_physical: bool = True

    def to_dict(self) -> dict[str, Any]:
        return {
            "name": self.name,
            "mac": self.mac,
            "chipset": self.chipset,
            "driver": self.driver,
            "physical_id": self.physical_id,
            "supported_bands": self.supported_bands,
            "mode": self.mode,
            "is_physical": self.is_physical,
        }


class InterfaceManager:
    """Detect, configure, and manage wireless interfaces."""

    # ── Detection ────────────────────────────────────────────────────────
    def detect_interfaces(self) -> list[AdapterInfo]:
        adapters: list[AdapterInfo] = []
        seen: set[str] = set()

        # Scan /sys/class/net for wireless interfaces
        net_dir = Path("/sys/class/net")
        if net_dir.exists():
            for entry in net_dir.iterdir():
                wireless_dir = entry / "wireless"
                if wireless_dir.exists():
                    name = entry.name
                    if name in seen:
                        continue
                    seen.add(name)
                    info = self._build_adapter_info(name)
                    adapters.append(info)

        # Also scan USB devices via lsusb for chipset hints
        usb_map = self._parse_lsusb()
        for adapter in adapters:
            if adapter.driver in usb_map:
                adapter.chipset = usb_map[adapter.driver]

        # Scan PCI devices via lspci
        pci_map = self._parse_lspci()
        for adapter in adapters:
            if not adapter.chipset and adapter.driver in pci_map:
                adapter.chipset = pci_map[adapter.driver]

        logger.info("Detected %d wireless interface(s)", len(adapters))
        return adapters

    def _build_adapter_info(self, iface: str) -> AdapterInfo:
        mac = self._read_sys(f"/sys/class/net/{iface}/address")
        driver = self._read_sys(f"/sys/class/net/{iface}/device/driver/module/drivers") or ""
        if not driver:
            driver_path = Path(f"/sys/class/net/{iface}/device/driver")
            if driver_path.is_symlink():
                driver = driver_path.resolve().name
        physical_id = ""
        phys_path = Path(f"/sys/class/net/{iface}/phy80211/name")
        if phys_path.exists():
            physical_id = phys_path.read_text().strip()
        elif Path(f"/sys/class/net/{iface}/device/uevent").exists():
            uevent = Path(f"/sys/class/net/{iface}/device/uevent").read_text()
            for line in uevent.splitlines():
                if line.startswith("PHYSDEVNAME="):
                    physical_id = line.split("=", 1)[1]
                    break

        mode = self.get_mode(iface)
        bands = self._detect_bands(iface)

        return AdapterInfo(
            name=iface,
            mac=mac,
            chipset="",
            driver=driver,
            physical_id=physical_id,
            supported_bands=bands,
            mode=mode,
        )

    def _detect_bands(self, iface: str) -> list[str]:
        bands: list[str] = []
        iw_path = shutil.which("iw")
        if not iw_path:
            return bands
        try:
            result = subprocess.run(
                [iw_path, "phy", iface, "info"],
                capture_output=True, text=True, timeout=5,
            )
            output = result.stdout
            if "2412 MHz" in output or "2.4 GHz" in output or "Band 1" in output:
                bands.append("2.4GHz")
            if "5180 MHz" in output or "5 GHz" in output or "Band 2" in output:
                bands.append("5GHz")
            if "5955 MHz" in output or "6 GHz" in output or "Band 3" in output:
                bands.append("6GHz")
        except (subprocess.SubprocessError, FileNotFoundError):
            pass
        return bands if bands else ["2.4GHz"]

    @staticmethod
    def _read_sys(path: str) -> str:
        try:
            return Path(path).read_text().strip()
        except (OSError, FileNotFoundError):
            return ""

    def _parse_lsusb(self) -> dict[str, str]:
        result: dict[str, str] = {}
        lsusb = shutil.which("lsusb")
        if not lsusb:
            return result
        try:
            proc = subprocess.run([lsusb], capture_output=True, text=True, timeout=5)
            wireless_keywords = {
                "wireless", "wifi", "wlan", "802.11",
                "ath", "rtw", "rtl", "mt76", "iwl",
            }
            for line in proc.stdout.splitlines():
                lower = line.lower()
                if any(kw in lower for kw in wireless_keywords):
                    parts = line.split(" ", 5)
                    if len(parts) >= 6:
                        result[parts[1]] = parts[5]
        except (subprocess.SubprocessError, FileNotFoundError):
            pass
        return result

    def _parse_lspci(self) -> dict[str, str]:
        result: dict[str, str] = {}
        lspci = shutil.which("lspci")
        if not lspci:
            return result
        try:
            proc = subprocess.run([lspci], capture_output=True, text=True, timeout=5)
            wireless_keywords = {"wireless", "wifi", "network", "802.11"}
            for line in proc.stdout.splitlines():
                lower = line.lower()
                if any(kw in lower for kw in wireless_keywords):
                    parts = line.split(":", 2)
                    if len(parts) >= 3:
                        result[line.split()[0]] = parts[2].strip()
        except (subprocess.SubprocessError, FileNotFoundError):
            pass
        return result

    # ── Monitor mode ─────────────────────────────────────────────────────
    def set_monitor_mode(self, iface: str) -> AdapterInfo:
        airmon = shutil.which("airmon-ng")
        if not airmon:
            from wafford.exceptions import ToolNotFoundError
            raise ToolNotFoundError("airmon-ng not found", tool="airmon-ng")

        self.kill_conflicting_processes()

        logger.info("Enabling monitor mode on %s via airmon-ng", iface)
        proc = subprocess.run(
            [airmon, "start", iface],
            capture_output=True, text=True, timeout=30,
        )
        if proc.returncode != 0:
            from wafford.exceptions import InterfaceError
            raise InterfaceError(
                f"Failed to enable monitor mode: {proc.stderr.strip()}",
                interface=iface,
            )

        # airmon-ng may rename the interface (e.g. wlan0 -> wlan0mon)
        new_iface = self._detect_renamed_interface(iface, proc.stdout)
        logger.info("Monitor mode enabled on %s", new_iface)
        return self._build_adapter_info(new_iface)

    def set_managed_mode(self, iface: str) -> AdapterInfo:
        airmon = shutil.which("airmon-ng")
        if not airmon:
            from wafford.exceptions import ToolNotFoundError
            raise ToolNotFoundError("airmon-ng not found", tool="airmon-ng")

        logger.info("Restoring managed mode on %s via airmon-ng", iface)
        proc = subprocess.run(
            [airmon, "stop", iface],
            capture_output=True, text=True, timeout=30,
        )
        if proc.returncode != 0:
            from wafford.exceptions import InterfaceError
            raise InterfaceError(
                f"Failed to restore managed mode: {proc.stderr.strip()}",
                interface=iface,
            )

        original_iface = iface.rstrip("mon")
        logger.info("Managed mode restored on %s", original_iface)
        return self._build_adapter_info(original_iface)

    def _detect_renamed_interface(self, original: str, output: str) -> str:
        """Parse airmon-ng output to find the new monitor interface name."""
        for line in output.splitlines():
            line = line.strip()
            if "monitor mode" in line.lower() or "monitor" in line.lower():
                match = re.search(r"on\s+(\S+)", line)
                if match:
                    return match.group(1)

        # Fallback: check common naming conventions
        for suffix in ("mon", "mon0", "sta"):
            candidate = original + suffix
            if Path(f"/sys/class/net/{candidate}").is_dir():
                return candidate

        return original

    # ── MAC address management ───────────────────────────────────────────
    def randomize_mac(self, iface: str) -> str:
        macchanger = shutil.which("macchanger")
        if not macchanger:
            from wafford.exceptions import ToolNotFoundError
            raise ToolNotFoundError("macchanger not found", tool="macchanger")

        # Must be down to change MAC
        self._set_interface_down(iface)
        try:
            proc = subprocess.run(
                [macchanger, "-r", iface],
                capture_output=True, text=True, timeout=10,
            )
            if proc.returncode != 0:
                from wafford.exceptions import InterfaceError
                raise InterfaceError(
                    f"MAC randomisation failed: {proc.stderr.strip()}",
                    interface=iface,
                )
            new_mac = self._parse_macchanger_output(proc.stdout, "Current MAC")
            logger.info("MAC randomised on %s: %s", iface, new_mac)
            return new_mac
        finally:
            self._set_interface_up(iface)

    def restore_mac(self, iface: str) -> str:
        macchanger = shutil.which("macchanger")
        if not macchanger:
            from wafford.exceptions import ToolNotFoundError
            raise ToolNotFoundError("macchanger not found", tool="macchanger")

        self._set_interface_down(iface)
        try:
            proc = subprocess.run(
                [macchanger, "-p", iface],
                capture_output=True, text=True, timeout=10,
            )
            if proc.returncode != 0:
                from wafford.exceptions import InterfaceError
                raise InterfaceError(
                    f"MAC restore failed: {proc.stderr.strip()}",
                    interface=iface,
                )
            restored = self._parse_macchanger_output(proc.stdout, "Permanent MAC")
            logger.info("MAC restored on %s: %s", iface, restored)
            return restored
        finally:
            self._set_interface_up(iface)

    def _set_interface_down(self, iface: str) -> None:
        subprocess.run(["ip", "link", "set", iface, "down"], capture_output=True, timeout=5)

    def _set_interface_up(self, iface: str) -> None:
        subprocess.run(["ip", "link", "set", iface, "up"], capture_output=True, timeout=5)

    @staticmethod
    def _parse_macchanger_output(output: str, marker: str) -> str:
        for line in output.splitlines():
            if marker in line:
                match = re.search(r"([0-9A-Fa-f]{2}:){5}[0-9A-Fa-f]{2}", line)
                if match:
                    return match.group(0)
        return ""

    # ── Injection test ───────────────────────────────────────────────────
    def check_injection(self, iface: str) -> bool:
        aireplay = shutil.which("aireplay-ng")
        if not aireplay:
            logger.warning("aireplay-ng not found, skipping injection test")
            return False

        logger.info("Testing injection capability on %s", iface)
        try:
            proc = subprocess.run(
                [aireplay, "--test", iface],
                capture_output=True, text=True, timeout=30,
            )
            output = proc.stdout + proc.stderr
            works = "100% injection" in output or "injection is working" in output.lower()
            logger.info("Injection test on %s: %s", iface, "OK" if works else "FAILED")
            return works
        except subprocess.TimeoutExpired:
            logger.warning("Injection test timed out on %s", iface)
            return False

    # ── Mode detection ───────────────────────────────────────────────────
    def get_mode(self, iface: str) -> str:
        type_path = f"/sys/class/net/{iface}/type"
        try:
            with Path(type_path).open() as f:
                iface_type = f.read().strip()
            if iface_type == "803":
                return "monitor"
            return "managed"
        except (OSError, FileNotFoundError):
            pass

        # Fallback: parse `iw`
        iw = shutil.which("iw")
        if iw:
            try:
                proc = subprocess.run(
                    [iw, "dev", iface, "info"],
                    capture_output=True, text=True, timeout=5,
                )
                if "type monitor" in proc.stdout.lower():
                    return "monitor"
                if "type managed" in proc.stdout.lower():
                    return "managed"
            except (subprocess.SubprocessError, FileNotFoundError):
                pass

        return "unknown"

    # ── Channel management ───────────────────────────────────────────────
    def get_channel(self, iface: str) -> int:
        iw = shutil.which("iw")
        if not iw:
            return 0
        try:
            proc = subprocess.run(
                [iw, "dev", iface, "info"],
                capture_output=True, text=True, timeout=5,
            )
            for line in proc.stdout.splitlines():
                match = re.search(r"channel\s+(\d+)", line, re.IGNORECASE)
                if match:
                    return int(match.group(1))
        except (subprocess.SubprocessError, FileNotFoundError):
            pass
        return 0

    def set_channel(self, iface: str, channel: int) -> None:
        iw = shutil.which("iw")
        if not iw:
            from wafford.exceptions import ToolNotFoundError
            raise ToolNotFoundError("iw not found", tool="iw")

        logger.info("Setting channel %d on %s", channel, iface)
        proc = subprocess.run(
            [iw, "dev", iface, "set", "channel", str(channel)],
            capture_output=True, text=True, timeout=10,
        )
        if proc.returncode != 0:
            from wafford.exceptions import InterfaceError
            raise InterfaceError(
                f"Failed to set channel {channel}: {proc.stderr.strip()}",
                interface=iface,
            )

    # ── Kill conflicting processes ───────────────────────────────────────
    def kill_conflicting_processes(self) -> list[str]:
        conflicting = [
            "NetworkManager",
            "wpa_supplicant",
            "dhclient",
            "dhcpcd",
            "plymouth",
            "wpa_cli",
            "connman",
            "iwd",
            "dhcpcui",
            "wpa_actiond",
        ]
        killed: list[str] = []
        for proc_name in conflicting:
            try:
                result = subprocess.run(
                    ["killall", "-q", proc_name],
                    capture_output=True, text=True, timeout=5,
                )
                if result.returncode == 0:
                    killed.append(proc_name)
                    logger.debug("Killed process: %s", proc_name)
            except (subprocess.SubprocessError, FileNotFoundError):
                pass

        if killed:
            logger.info("Killed %d conflicting process(es): %s", len(killed), ", ".join(killed))
        return killed

    # ── Auto-select best interface ──────────────────────────────────────
    def auto_select_interface(self) -> AdapterInfo | None:
        """Auto-detect and return the best WiFi adapter for auditing.

        Priority: supports monitor mode + injection > monitor only > any wireless.
        Returns None if no wireless interface found.
        """
        adapters = self.detect_interfaces()
        if not adapters:
            logger.warning("No wireless interfaces detected")
            return None

        # Rank: prefer adapters that support monitor mode
        monitor_capable = []
        for adapter in adapters:
            if adapter.supported_bands:
                monitor_capable.append(adapter)

        if monitor_capable:
            # Among monitor-capable, prefer ones whose driver suggests injection
            for adapter in monitor_capable:
                driver_lower = adapter.driver.lower()
                known_inject = {"ath9k", "ath9k_htc", "rt2800usb", "rt2800pci",
                                "rtl8812au", "rtl8811au", "mt76", "iwlwifi",
                                "brcmfmac", "carl9170", "p54usb", "zd1211rw"}
                if any(k in driver_lower for k in known_inject):
                    logger.info(
                        "Auto-selected %s (inject-capable driver: %s)",
                        adapter.name, adapter.driver,
                    )
                    return adapter
            # Return first monitor-capable if no known-inject driver found
            logger.info("Auto-selected %s (monitor-capable)", monitor_capable[0].name)
            return monitor_capable[0]

        # Fallback: first wireless interface
        logger.info("Auto-selected %s (fallback)", adapters[0].name)
        return adapters[0]

    def auto_enable_monitor(self) -> AdapterInfo | None:
        """One-click: auto-select best interface and enable monitor mode.

        Returns the adapter info in monitor mode, or None on failure.
        """
        adapter = self.auto_select_interface()
        if adapter is None:
            return None
        if adapter.mode == "monitor":
            logger.info("%s already in monitor mode", adapter.name)
            return adapter
        return self.set_monitor_mode(adapter.name)

    def auto_enable_managed(self) -> AdapterInfo | None:
        """One-click: auto-select interface and restore managed mode.

        Finds the first monitor-mode interface and restores it to managed.
        If no monitor interface, picks the first wireless adapter.
        Returns the adapter info in managed mode, or None on failure.
        """
        adapters = self.detect_interfaces()
        if not adapters:
            return None

        # Prefer restoring a monitor-mode interface
        for adapter in adapters:
            if adapter.mode == "monitor":
                return self.set_managed_mode(adapter.name)

        # No monitor interface found — just return first adapter
        return adapters[0] if adapters else None

    # ── Lookup vendor ────────────────────────────────────────────────────
    @staticmethod
    def lookup_vendor(bssid: str) -> str:
        prefix = bssid.upper()[:8]
        return _OUI_DB.get(prefix, "Unknown")

    # ── Signal helpers ───────────────────────────────────────────────────
    @staticmethod
    def signal_to_bar(dbm: int) -> str:
        if dbm >= -30:
            return "▂▄▆█"
        if dbm >= -50:
            return "▂▄▆░"
        if dbm >= -60:
            return "▂▄░░"
        if dbm >= -70:
            return "▂░░░"
        if dbm >= -80:
            return "░░░░"
        return ""

    @staticmethod
    def signal_to_percent(dbm: int) -> int:
        if dbm <= -100:
            return 0
        if dbm >= -50:
            return 100
        return int(2 * (dbm + 100))
