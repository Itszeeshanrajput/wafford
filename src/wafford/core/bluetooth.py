"""Bluetooth reconnaissance and scanning modules for Wafford."""

from __future__ import annotations

import asyncio
import logging
import re
import time
from dataclasses import dataclass, field
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from collections.abc import Callable

from wafford.scripts.shell import ShellRunner

logger = logging.getLogger("wafford.core.bluetooth")


@dataclass
class BluetoothDevice:
    """Represents a discovered Bluetooth device."""
    mac: str
    name: str = "Unknown"
    device_type: str = "classic"
    rssi: int = 0
    device_class: str = ""
    vendor: str = ""
    services: list[str] = field(default_factory=list)
    first_seen: float = 0.0
    last_seen: float = 0.0


@dataclass
class BluetoothScanResult:
    """Result of a Bluetooth scan operation."""
    scan_type: str = "classic"
    devices: list[BluetoothDevice] = field(default_factory=list)
    duration: float = 0.0
    interface: str = ""
    started_at: float = 0.0
    ended_at: float = 0.0
    success: bool = False
    error: str = ""


# Common Bluetooth device class major categories
DEVICE_CLASS_MAP: dict[int, str] = {
    0x200: "Computer",
    0x204: "Desktop Computer",
    0x208: "Server",
    0x20C: "Laptop",
    0x210: "Handheld PC",
    0x214: "Palm PC",
    0x218: "Wearable Computer",
    0x400: "Phone",
    0x404: "Cell Phone",
    0x408: "Smartphone",
    0x40C: "Wired Modem/Voice Gateway",
    0x410: "Common ISDN Access",
    0x600: "LAN/Network Access Point",
    0x604: "Fully Managed AP",
    0x60C: "Headset",
    0x800: "Audio/Video",
    0x804: "Wearable Headset",
    0x808: "Hands-free",
    0x80C: "Microphone",
    0x810: "Loudspeaker",
    0x814: "Headphones",
    0x818: "Portable Audio",
    0x2000: "Keyboard",
    0x2040: "Pointing Device",
    0x2080: "Combined Keyboard/Mouse",
    0x2FC00: "Medical",
    0x4FC00: "Toy",
    0x5FC00: "Health",
}

# Common OUI prefixes for Bluetooth vendor lookup
BT_VENDOR_OUIS: dict[str, str] = {
    "00:1A:7D": "Cypress (was Bluetooth SIG)",
    "00:1B:DC": "Logitech",
    "00:1E:58": "Dualshock (Sony)",
    "00:21:AC": "Apple",
    "00:25:00": "Apple",
    "40:9C:28": "Apple",
    "54:26:96": "Apple",
    "58:55:CA": "Apple",
    "6C:4D:73": "Apple",
    "70:56:81": "Apple",
    "78:7B:8A": "Apple",
    "88:66:A5": "Apple",
    "A4:83:E7": "Apple",
    "AC:BC:32": "Apple",
    "B0:34:95": "Apple",
    "C8:2A:14": "Apple",
    "DC:29:3A": "Apple",
    "E0:C9:7A": "Apple",
    "F0:18:98": "Apple",
    "00:06:F7": "Intel",
    "00:13:02": "Intel",
    "00:15:17": "Intel",
    "3C:97:0E": "Intel",
    "48:51:B7": "Intel",
    "5C:51:47": "Intel",
    "7C:76:35": "Intel",
    "8C:8D:28": "Intel",
    "B4:69:46": "Intel",
    "DC:53:7C": "Intel",
    "00:12:4C": "Qualcomm",
    "00:1B:5B": "Qualcomm",
    "00:23:D4": "Qualcomm",
    "3C:5A:B4": "Qualcomm",
    "40:ED:98": "Qualcomm",
    "44:07:0B": "Qualcomm",
    "50:55:3A": "Qualcomm",
    "74:E1:B6": "Qualcomm",
    "80:30:49": "Qualcomm",
    "9C:32:CF": "Qualcomm",
    "B4:F0:AB": "Qualcomm",
    "CC:81:DA": "Qualcomm",
    "D4:3B:04": "Qualcomm",
    "F8:F1:B6": "Qualcomm",
    "00:09:6A": "Nokia",
    "00:0E:ED": "Nokia",
    "00:11:9F": "Nokia",
    "00:12:62": "Nokia",
    "00:15:2D": "Nokia",
    "00:19:2D": "Nokia",
    "00:1D:AF": "Nokia",
    "00:21:09": "Nokia",
    "00:23:68": "Nokia",
    "00:25:47": "Nokia",
    "04:00:10": "Nokia",
    "14:10:B4": "Nokia",
    "24:0B:C1": "Nokia",
    "30:39:26": "Nokia",
    "34:CC:2E": "Nokia",
    "38:2C:4A": "Nokia",
    "40:78:B8": "Nokia",
    "44:85:00": "Nokia",
    "4C:04:CE": "Nokia",
    "50:0F:80": "Nokia",
    "58:A4:5E": "Nokia",
    "5C:09:79": "Nokia",
    "5C:26:0A": "Nokia",
    "68:17:29": "Nokia",
    "6C:32:1A": "Nokia",
    "70:91:F3": "Nokia",
    "78:60:5B": "Nokia",
    "7C:4C:A5": "Nokia",
    "80:50:1B": "Nokia",
    "80:9F:B8": "Nokia",
    "84:79:73": "Nokia",
    "88:71:B1": "Nokia",
    "8C:56:9D": "Nokia",
    "90:72:40": "Nokia",
    "98:59:45": "Nokia",
    "9C:D6:43": "Nokia",
    "A0:32:B9": "Nokia",
    "A4:7E:39": "Nokia",
    "A8:1B:6A": "Nokia",
    "AC:5A:14": "Nokia",
    "B0:75:0C": "Nokia",
    "B0:E2:35": "Nokia",
    "B4:99:BA": "Nokia",
    "B8:25:DB": "Nokia",
    "BC:2F:A1": "Nokia",
    "C0:D7:AA": "Nokia",
    "C4:9A:02": "Nokia",
    "C8:C2:C6": "Nokia",
    "D0:03:4B": "Nokia",
    "D0:51:62": "Nokia",
    "D4:60:E3": "Nokia",
    "D4:81:CA": "Nokia",
    "D4:F5:EF": "Nokia",
    "D8:13:2E": "Nokia",
    "DC:33:3D": "Nokia",
    "E0:5F:45": "Nokia",
    "E0:A1:D5": "Nokia",
    "E0:B9:82": "Nokia",
    "E4:28:7F": "Nokia",
    "E4:55:A8": "Nokia",
    "E4:98:D1": "Nokia",
    "E4:CB:5F": "Nokia",
    "E8:3E:B6": "Nokia",
    "EC:9B:2F": "Nokia",
    "F0:43:47": "Nokia",
    "F0:84:C9": "Nokia",
    "F0:A4:75": "Nokia",
    "F0:BD:2E": "Nokia",
    "F0:C3:DA": "Nokia",
    "F4:55:9C": "Nokia",
    "F4:73:2C": "Nokia",
    "F4:C2:48": "Nokia",
    "F4:FA:30": "Nokia",
    "F8:01:13": "Nokia",
    "F8:CA:86": "Nokia",
    "FC:00:12": "Nokia",
    "FC:17:94": "Nokia",
    "FC:D4:F2": "Nokia",
    "FC:E9:98": "Nokia",
    "00:1B:38": "Microsoft",
    "28:18:78": "Microsoft",
    "3C:22:FB": "Microsoft",
    "40:F4:20": "Microsoft",
    "5C:C3:07": "Microsoft",
    "60:45:BD": "Microsoft",
    "7C:1E:52": "Microsoft",
    "8C:EC:4B": "Microsoft",
    "98:01:A7": "Microsoft",
    "A4:C1:38": "Microsoft",
    "B0:83:FE": "Microsoft",
    "C8:3F:26": "Microsoft",
    "DC:B6:9A": "Microsoft",
    "E0:1C:FC": "Microsoft",
    "F0:1D:BC": "Microsoft",
    "F8:33:31": "Microsoft",
    "00:25:DF": "Samsung",
    "00:59:79": "Samsung",
    "04:18:0F": "Samsung",
    "0C:71:5D": "Samsung",
    "10:D5:42": "Samsung",
    "14:49:E0": "Samsung",
    "18:22:7E": "Samsung",
    "1C:62:B8": "Samsung",
    "20:02:0A": "Samsung",
    "24:4B:81": "Samsung",
    "28:98:7B": "Samsung",
    "2C:AE:2B": "Samsung",
    "30:96:FB": "Samsung",
    "34:23:BA": "Samsung",
    "38:01:97": "Samsung",
    "3C:5A:37": "Samsung",
    "40:0E:85": "Samsung",
    "44:4E:1A": "Samsung",
    "48:44:F7": "Samsung",
    "4C:BC:4E": "Samsung",
    "50:F5:20": "Samsung",
    "54:40:AD": "Samsung",
    "58:2A:F7": "Samsung",
    "5C:0A:5B": "Samsung",
    "60:6B:BD": "Samsung",
    "64:77:91": "Samsung",
    "68:59:2F": "Samsung",
    "6C:F3:73": "Samsung",
    "70:F9:27": "Samsung",
    "74:45:CE": "Samsung",
    "78:25:AD": "Samsung",
    "7C:0B:C6": "Samsung",
    "80:65:6D": "Samsung",
    "84:25:DB": "Samsung",
    "88:32:9B": "Samsung",
    "8C:77:12": "Samsung",
    "90:18:7C": "Samsung",
    "94:01:C2": "Samsung",
    "94:35:0A": "Samsung",
    "94:51:03": "Samsung",
    "94:B8:6D": "Samsung",
    "98:0C:82": "Samsung",
    "98:52:B1": "Samsung",
    "9C:02:98": "Samsung",
    "A0:07:98": "Samsung",
    "A0:0B:BA": "Samsung",
    "A0:82:1F": "Samsung",
    "A4:07:B6": "Samsung",
    "A8:06:00": "Samsung",
    "AC:36:13": "Samsung",
    "B0:47:BF": "Samsung",
    "B0:72:BF": "Samsung",
    "B0:EC:71": "Samsung",
    "B4:3A:28": "Samsung",
    "B8:57:D8": "Samsung",
    "BC:14:85": "Samsung",
    "C0:97:27": "Samsung",
    "C4:73:1E": "Samsung",
    "C8:14:51": "Samsung",
    "CC:07:AB": "Samsung",
    "D0:22:BE": "Samsung",
    "D0:87:E2": "Samsung",
    "D4:88:90": "Samsung",
    "D8:57:EF": "Samsung",
    "DC:71:44": "Samsung",
    "E0:CB:EE": "Samsung",
    "E4:7C:F9": "Samsung",
    "E4:92:FB": "Samsung",
    "E4:EC:CE": "Samsung",
    "E8:03:9A": "Samsung",
    "E8:50:8B": "Samsung",
    "EC:1F:72": "Samsung",
    "F0:08:F1": "Samsung",
    "F0:25:B7": "Samsung",
    "F0:5A:09": "Samsung",
    "F4:09:D8": "Samsung",
    "F4:42:8F": "Samsung",
    "F4:7B:5E": "Samsung",
    "F8:04:2E": "Samsung",
    "FC:F1:36": "Samsung",
}


class BluetoothRecon:
    """Bluetooth reconnaissance and device discovery.

    Supports both BLE (Bluetooth Low Energy) and classic Bluetooth scanning.
    Provides device enumeration, service discovery, and vendor identification.
    """

    def __init__(self) -> None:
        self.shell = ShellRunner()
        self._running = False
        self._scan_process: asyncio.subprocess.Process | None = None
        self._devices: dict[str, BluetoothDevice] = {}
        self._callbacks: list[Callable[[BluetoothDevice], None]] = []

    def on_device_found(self, callback: Callable[[BluetoothDevice], None]) -> None:
        """Register callback for new device discoveries."""
        self._callbacks.append(callback)

    def _emit_device(self, device: BluetoothDevice) -> None:
        """Notify all callbacks of a new device."""
        for cb in self._callbacks:
            try:
                cb(device)
            except Exception as e:
                logger.error("Device callback error: %s", e)

    async def scan_ble(
        self,
        duration: int = 30,
        interface: str = "hci0",
    ) -> BluetoothScanResult:
        """Scan for Bluetooth Low Energy devices.

        Uses hcitool lescan to discover BLE peripherals.

        Args:
            duration: Scan duration in seconds.
            interface: Bluetooth interface (hci0, hci1, etc.)
        """
        self._running = True
        self._devices.clear()
        start_time = time.time()

        result = BluetoothScanResult(
            scan_type="ble",
            interface=interface,
            started_at=start_time,
        )

        logger.info("Starting BLE scan: iface=%s duration=%ds", interface, duration)

        try:
            proc = await asyncio.create_subprocess_exec(
                "hcitool", "-i", interface, "lescan",
                "--duplicates",
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE,
            )
            self._scan_process = proc

            end_time = time.time() + duration
            while time.time() < end_time and self._running:
                try:
                    if proc.stdout is None:
                        break
                    line_bytes = await asyncio.wait_for(proc.stdout.readline(), timeout=1.0)
                    if not line_bytes:
                        break
                    line = line_bytes.decode("utf-8", errors="replace").strip()
                    self._parse_ble_line(line)
                except TimeoutError:
                    continue

            if proc.returncode is None:
                proc.terminate()
                try:
                    await asyncio.wait_for(proc.wait(), timeout=3.0)
                except TimeoutError:
                    proc.kill()

            for dev in self._devices.values():
                result.devices.append(dev)

            result.duration = time.time() - start_time
            result.success = True
            result.ended_at = time.time()

        except asyncio.CancelledError:
            logger.info("BLE scan cancelled")
            result.error = "Cancelled by user"
        except FileNotFoundError:
            result.error = "hcitool not found — install bluez package"
            logger.error("hcitool binary not found")
        except Exception as e:
            logger.error("BLE scan failed: %s", e)
            result.error = str(e)
        finally:
            self._running = False
            self._scan_process = None

        return result

    def _parse_ble_line(self, line: str) -> None:
        """Parse a single line from hcitool lescan."""
        if not line or line.startswith("LE Scan"):
            return
        match = re.match(r"([0-9A-Fa-f:]{17})\s*(.*)", line)
        if match:
            mac = match.group(1).upper()
            name = match.group(2).strip() or "Unknown"
            now = time.time()
            if mac in self._devices:
                self._devices[mac].last_seen = now
                if name != "Unknown" and self._devices[mac].name == "Unknown":
                    self._devices[mac].name = name
            else:
                device = BluetoothDevice(
                    mac=mac,
                    name=name,
                    device_type="BLE",
                    vendor=self.lookup_vendor(mac),
                    first_seen=now,
                    last_seen=now,
                )
                self._devices[mac] = device
                self._emit_device(device)

    async def scan_classic(
        self,
        duration: int = 30,
        interface: str = "hci0",
    ) -> BluetoothScanResult:
        """Scan for classic Bluetooth devices.

        Uses hcitool scan to discover BR/EDR devices.

        Args:
            duration: Scan duration in seconds.
            interface: Bluetooth interface (hci0, hci1, etc.)
        """
        self._running = True
        self._devices.clear()
        start_time = time.time()

        result = BluetoothScanResult(
            scan_type="classic",
            interface=interface,
            started_at=start_time,
        )

        logger.info(
            "Starting classic BT scan: iface=%s duration=%ds",
            interface, duration,
        )

        try:
            proc = await asyncio.create_subprocess_exec(
                "hcitool", "-i", interface, "scan",
                "--length", str(duration),
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE,
            )
            self._scan_process = proc

            stdout, stderr = await asyncio.wait_for(
                proc.communicate(),
                timeout=duration + 15,
            )

            output = stdout.decode("utf-8", errors="replace")
            self._parse_classic_scan(output)

            for dev in self._devices.values():
                result.devices.append(dev)

            result.duration = time.time() - start_time
            result.success = True
            result.ended_at = time.time()

        except TimeoutError:
            logger.warning("Classic scan timed out")
            for dev in self._devices.values():
                result.devices.append(dev)
            result.duration = time.time() - start_time
            result.success = bool(result.devices)
            result.ended_at = time.time()
        except asyncio.CancelledError:
            logger.info("Classic scan cancelled")
            result.error = "Cancelled by user"
        except FileNotFoundError:
            result.error = "hcitool not found — install bluez package"
            logger.error("hcitool binary not found")
        except Exception as e:
            logger.error("Classic scan failed: %s", e)
            result.error = str(e)
        finally:
            self._running = False
            self._scan_process = None

        return result

    async def enumerate_services(self, mac: str) -> list[str]:
        """Enumerate services on a discovered Bluetooth device.

        Uses sdptool browse to list available SDP services.

        Args:
            mac: Target device MAC address.
        """
        services: list[str] = []

        logger.info("Enumerating services for %s", mac)

        try:
            proc = await asyncio.create_subprocess_exec(
                "sdptool", "browse", mac,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE,
            )
            stdout, _ = await asyncio.wait_for(proc.communicate(), timeout=15)

            output = stdout.decode("utf-8", errors="replace")
            for line in output.splitlines():
                line = line.strip()
                if line.startswith("Service Name:"):
                    service_name = line.split(":", 1)[1].strip()
                    if service_name:
                        services.append(service_name)

            if mac in self._devices:
                self._devices[mac].services = services

            logger.info("Found %d services for %s", len(services), mac)

        except TimeoutError:
            logger.warning("Service enumeration timed out for %s", mac)
        except FileNotFoundError:
            logger.error("sdptool not found — install bluez package")
        except Exception as e:
            logger.error("Service enumeration failed for %s: %s", mac, e)

        return services

    async def get_device_info(self, mac: str) -> BluetoothDevice:
        """Get detailed information about a Bluetooth device.

        Retrieves name, device class, and vendor information.

        Args:
            mac: Target device MAC address.
        """
        device = BluetoothDevice(
            mac=mac,
            first_seen=time.time(),
            last_seen=time.time(),
        )

        try:
            proc = await asyncio.create_subprocess_exec(
                "hcitool", "name", mac,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE,
            )
            stdout, _ = await asyncio.wait_for(proc.communicate(), timeout=10)
            name = stdout.decode("utf-8", errors="replace").strip()
            if name:
                device.name = name

        except (TimeoutError, FileNotFoundError, Exception) as e:
            logger.debug("Could not get name for %s: %s", mac, e)

        try:
            proc = await asyncio.create_subprocess_exec(
                "hcitool", "info", mac,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE,
            )
            stdout, _ = await asyncio.wait_for(proc.communicate(), timeout=10)
            info = stdout.decode("utf-8", errors="replace")

            class_match = re.search(r"Device Class:\s*(0x[0-9A-Fa-f]+)", info)
            if class_match:
                device.device_class = class_match.group(1)
                major_class = int(class_match.group(1), 16) & 0x1F00
                device.device_type = DEVICE_CLASS_MAP.get(major_class, "Unknown")

        except (TimeoutError, FileNotFoundError, Exception) as e:
            logger.debug("Could not get info for %s: %s", mac, e)

        device.vendor = self.lookup_vendor(mac)

        self._devices[mac] = device
        self._emit_device(device)

        return device

    def lookup_vendor(self, mac: str) -> str:
        """Look up vendor from MAC address OUI prefix.

        Args:
            mac: MAC address to look up.
        """
        mac_prefix = mac.upper()[:8]
        if mac_prefix in BT_VENDOR_OUIS:
            return BT_VENDOR_OUIS[mac_prefix]

        shorter = mac.upper()[:5]
        for prefix, vendor in BT_VENDOR_OUIS.items():
            if prefix.startswith(shorter):
                return vendor

        return "Unknown"

    def _parse_classic_scan(self, output: str) -> None:
        """Parse hcitool scan output into BluetoothDevice objects.

        Args:
            output: Raw stdout from hcitool scan.
        """
        now = time.time()
        for line in output.splitlines():
            line = line.strip()
            if not line or line.startswith(("Scanning", "Inquiry")):
                continue

            match = re.match(r"([0-9A-Fa-f:]{17})\s+(.+)", line)
            if match:
                mac = match.group(1)
                name = match.group(2).strip()

                if mac in self._devices:
                    self._devices[mac].last_seen = now
                    self._devices[mac].name = name
                else:
                    device = BluetoothDevice(
                        mac=mac,
                        name=name,
                        device_type="classic",
                        vendor=self.lookup_vendor(mac),
                        first_seen=now,
                        last_seen=now,
                    )
                    self._devices[mac] = device
                    self._emit_device(device)

    def get_all_devices(self) -> list[BluetoothDevice]:
        """Return all discovered devices."""
        return list(self._devices.values())

    def get_device_count(self) -> int:
        """Return total number of discovered devices."""
        return len(self._devices)

    def stop(self) -> None:
        """Stop any running scan."""
        self._running = False
        if self._scan_process and self._scan_process.returncode is None:
            self._scan_process.terminate()
        logger.info("Bluetooth scan stopped")

    async def stop_async(self) -> None:
        """Async stop any running scan."""
        self.stop()
        if self._scan_process and self._scan_process.returncode is None:
            try:
                await asyncio.wait_for(self._scan_process.wait(), timeout=5.0)
            except TimeoutError:
                self._scan_process.kill()

    @property
    def is_running(self) -> bool:
        """Check if scan is running."""
        return self._running

    async def scan_and_enumerate(
        self,
        duration: int = 30,
        interface: str = "hci0",
        scan_type: str = "classic",
        enumerate_services: bool = False,
    ) -> BluetoothScanResult:
        """Full reconnaissance: scan + optional service enumeration.

        Args:
            duration: Scan duration in seconds.
            interface: Bluetooth interface.
            scan_type: 'ble', 'classic', or 'both'.
            enumerate_services: Whether to enumerate services on found devices.
        """
        if scan_type in ("ble", "both"):
            await self.scan_ble(duration=duration, interface=interface)

        if scan_type in ("classic", "both"):
            await self.scan_classic(duration=duration, interface=interface)

        if enumerate_services:
            for mac, device in self._devices.items():
                services = await self.enumerate_services(mac)
                device.services = services

        now = time.time()
        return BluetoothScanResult(
            scan_type=scan_type,
            devices=list(self._devices.values()),
            interface=interface,
            started_at=now - duration,
            ended_at=now,
            success=True,
        )
