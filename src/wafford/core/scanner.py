"""Async network scanner using airodump-ng CSV output parsing."""

from __future__ import annotations

import asyncio
import csv
import io
import logging
import time
from dataclasses import dataclass, field
from pathlib import Path
from typing import TYPE_CHECKING, Any

if TYPE_CHECKING:
    from collections.abc import AsyncGenerator

from wafford.constants import (
    DEFAULT_CHANNELS,
    DEFAULT_SCAN_DURATION,
)

logger = logging.getLogger(__name__)

# ── OUI lookup (same subset as interface module for self-containedness) ──────
_OUI: dict[str, str] = {
    "00:1B:2F": "Netgear",
    "00:1E:58": "D-Link",
    "00:22:6B": "Cisco-Linksys",
    "00:24:01": "D-Link",
    "00:26:F2": "Netgear",
    "08:36:69": "Ubiquiti",
    "0C:80:63": "TP-Link",
    "10:DA:43": "Netgear",
    "14:91:82": "Belkin",
    "18:E8:29": "Ubiquiti",
    "24:05:0F": "Ubiquiti",
    "2C:B0:5D": "Netgear",
    "30:B5:C2": "TP-Link",
    "34:97:F6": "ASUSTek",
    "38:2C:4A": "ASUSTek",
    "3C:37:86": "Netgear",
    "44:94:FC": "Ubiquiti",
    "48:EE:0C": "D-Link",
    "4C:ED:FB": "ASUSTek",
    "50:6A:03": "Netgear",
    "54:04:A6": "ASUSTek",
    "58:EF:68": "Belkin",
    "5C:CF:7F": "Espressif",
    "60:45:CB": "Belkin",
    "60:A4:4C": "ASUSTek",
    "64:66:B3": "D-Link",
    "68:72:51": "Ubiquiti",
    "70:4D:7B": "ASUSTek",
    "74:AC:B9": "Ubiquiti",
    "78:8A:20": "Ubiquiti",
    "7C:8B:CA": "TP-Link",
    "80:2A:A8": "Ubiquiti",
    "84:1B:5E": "D-Link",
    "88:DC:96": "EnGenius",
    "8C:3B:AD": "Netgear",
    "94:10:3E": "Belkin",
    "98:DE:D0": "TP-Link",
    "9C:3D:CF": "Netgear",
    "A0:04:60": "Netgear",
    "A4:2B:B0": "TP-Link",
    "AC:22:0B": "TP-Link",
    "AC:84:C6": "TP-Link",
    "B0:4E:26": "TP-Link",
    "B0:BE:76": "TP-Link",
    "B4:FB:E4": "Ubiquiti",
    "B8:27:EB": "Raspberry-Pi",
    "B8:EE:65": "Netgear",
    "C0:25:E9": "TP-Link",
    "C4:6E:1F": "TP-Link",
    "C4:71:54": "TP-Link",
    "CC:40:D0": "Netgear",
    "D4:6E:5E": "TP-Link",
    "D8:07:B6": "TP-Link",
    "DC:9F:DB": "Ubiquiti",
    "DC:A6:32": "Raspberry-Pi",
    "E0:63:DA": "Ubiquiti",
    "E8:94:F6": "TP-Link",
    "EC:08:6B": "TP-Link",
    "F4:EC:38": "TP-Link",
    "F8:1A:67": "TP-Link",
    "FC:EC:DA": "Ubiquiti",
}


@dataclass
class ScanResult:
    """Single network discovered during a scan."""

    bssid: str = ""
    essid: str = ""
    channel: int = 0
    encryption: str = "Unknown"
    signal_dbm: int = -100
    wps: bool = False
    vendor: str = ""
    clients: list[dict[str, Any]] = field(default_factory=list)
    first_seen: str = ""
    last_seen: str = ""
    is_hidden: bool = False

    @property
    def signal_percent(self) -> int:
        return max(0, min(100, 2 * (self.signal_dbm + 100)))

    def to_dict(self) -> dict[str, Any]:
        return {
            "bssid": self.bssid,
            "essid": self.essid,
            "channel": self.channel,
            "encryption": self.encryption,
            "signal_dbm": self.signal_dbm,
            "signal_percent": self.signal_percent,
            "wps": self.wps,
            "vendor": self.vendor,
            "clients": self.clients,
            "first_seen": self.first_seen,
            "last_seen": self.last_seen,
            "is_hidden": self.is_hidden,
        }


class NetworkScanner:
    """Async scanner that wraps airodump-ng and parses its CSV output."""

    def __init__(self, interface: str, output_dir: Path | str = "/tmp") -> None:  # noqa: S108
        self._interface = interface
        self._output_dir = Path(output_dir)
        self._process: asyncio.subprocess.Process | None = None
        self._results: dict[str, ScanResult] = {}
        self._running = False
        self._scan_start: float = 0.0

    @property
    def results(self) -> list[ScanResult]:
        return sorted(self._results.values(), key=lambda r: r.signal_dbm, reverse=True)

    async def stop(self) -> None:
        """Stop an active scan and terminate its airodump process."""
        self._running = False
        await self._stop_process()

    # ── Scan ─────────────────────────────────────────────────────────────
    async def scan(
        self,
        channels: list[int] | None = None,
        duration: int = DEFAULT_SCAN_DURATION,
        passive: bool = False,
    ) -> AsyncGenerator[ScanResult, None]:
        """Run airodump-ng, yield results as they arrive."""
        if self._running:
            logger.warning("Scan already in progress")
            return

        channels = channels or DEFAULT_CHANNELS
        self._running = True
        self._results.clear()
        self._scan_start = time.monotonic()

        output_prefix = self._output_dir / f"wafford_scan_{int(time.time())}"

        cmd = self._build_airodump_cmd(channels, str(output_prefix), passive)
        logger.info("Starting scan: %s", " ".join(cmd))

        try:
            self._process = await asyncio.create_subprocess_exec(
                *cmd,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE,
            )
        except FileNotFoundError:
            logger.error("airodump-ng not found in PATH")
            self._running = False
            return

        csv_path = Path(f"{output_prefix}-01.csv")
        elapsed = 0.0
        poll_interval = 2.0

        try:
            while elapsed < duration and self._running:
                await asyncio.sleep(poll_interval)
                elapsed = time.monotonic() - self._scan_start

                if csv_path.exists():
                    new_results = self.parse_airodump_csv(csv_path)
                    for bssid, result in new_results.items():
                        if bssid not in self._results:
                            self._results[bssid] = result
                            yield result
                        else:
                            existing = self._results[bssid]
                            existing.last_seen = result.last_seen
                            existing.signal_dbm = max(existing.signal_dbm, result.signal_dbm)
                            existing.clients = result.clients or existing.clients
        except asyncio.CancelledError:
            logger.info("Scan cancelled")
        finally:
            await self._stop_process()
            self._running = False
            # Final parse
            if csv_path.exists():
                final = self.parse_airodump_csv(csv_path)
                for bssid, result in final.items():
                    if bssid not in self._results:
                        self._results[bssid] = result
                        yield result

    def _build_airodump_cmd(
        self, channels: list[int], output_prefix: str, _passive: bool,
    ) -> list[str]:
        cmd = ["airodump-ng", "--write", output_prefix, "--output-format", "csv"]

        if channels:
            ch_str = ",".join(str(c) for c in channels)
            cmd.extend(["--channel", ch_str])

        cmd.append(self._interface)
        return cmd

    async def _stop_process(self) -> None:
        if self._process and self._process.returncode is None:
            try:
                self._process.terminate()
                await asyncio.wait_for(self._process.wait(), timeout=5)
            except TimeoutError:
                self._process.kill()
                await self._process.wait()
            except ProcessLookupError:
                pass
        self._process = None

    # ── CSV parsing ──────────────────────────────────────────────────────
    def parse_airodump_csv(self, csv_path: Path) -> dict[str, ScanResult]:
        """Parse airodump-ng CSV output into ScanResult objects."""
        results: dict[str, ScanResult] = {}
        try:
            content = csv_path.read_text(encoding="utf-8", errors="replace")
        except OSError as exc:
            logger.error("Failed to read CSV: %s", exc)
            return results

        # airodump-ng CSV has two sections: APs and Clients separated by a blank line
        # Try the real airodump-ng separator first, then common fallbacks
        for sep in ("\r\n\r\n", "\r\r\n\r\r\n", "\n\n"):
            sections = content.split(sep)
            if len(sections) >= 2:
                break

        ap_section = sections[0] if sections else content
        client_section = sections[1] if len(sections) > 1 else ""

        # Parse APs
        ap_clients = self._parse_client_section(client_section)
        reader = csv.reader(io.StringIO(ap_section))
        try:
            header = next(reader)
        except StopIteration:
            return results

        col_map = {h.strip(): i for i, h in enumerate(header)}

        for row in reader:
            if len(row) < 2:
                continue
            bssid = self._col(row, col_map, "BSSID", "")
            if not bssid or bssid == "BSSID":
                continue
            if bssid == "(not associated)":
                continue

            essid = self._col(row, col_map, "ESSID", "")
            channel = self._safe_int(self._col(row, col_map, "Channel", "0"))
            enc_raw = self._col(row, col_map, "Privacy", "")
            cipher = self._col(row, col_map, "Cipher", "")
            auth = self._col(row, col_map, "Authentication", "")
            signal_dbm = self._safe_int(self._col(row, col_map, "Power", "-100"))
            first_seen = self._col(row, col_map, "First time seen", "")
            last_seen = self._col(row, col_map, "Last time seen", "")

            encryption = self._classify_encryption(enc_raw, cipher, auth)
            is_hidden = not essid.strip()
            wps = "WPS" in content.split(bssid)[1].split("\n")[0] if bssid in content else False

            # Try WPS detection from the row
            if not wps:
                for col_name in col_map:
                    if "wps" in col_name.lower():
                        wps_val = self._col(row, col_map, col_name, "")
                        if wps_val and wps_val != "0" and wps_val != "":
                            wps = True
                            break

            clients = ap_clients.get(bssid.upper(), [])
            vendor = self.lookup_vendor(bssid)

            result = ScanResult(
                bssid=bssid.upper(),
                essid=essid,
                channel=channel,
                encryption=encryption,
                signal_dbm=signal_dbm,
                wps=wps,
                vendor=vendor,
                clients=clients,
                first_seen=first_seen,
                last_seen=last_seen,
                is_hidden=is_hidden,
            )
            results[bssid.upper()] = result

        return results

    def _parse_client_section(self, section: str) -> dict[str, list[dict[str, Any]]]:
        clients: dict[str, list[dict[str, Any]]] = {}
        if not section.strip():
            return clients

        reader = csv.reader(io.StringIO(section))
        try:
            header = next(reader)
        except StopIteration:
            return clients

        col_map = {h.strip(): i for i, h in enumerate(header)}

        for row in reader:
            if len(row) < 2:
                continue
            station_mac = self._col(row, col_map, "Station MAC", "").strip()
            if not station_mac or station_mac == "Station MAC":
                continue
            bssid = self._col(row, col_map, "BSSID", "").strip()
            probe = self._col(row, col_map, "Probed ESSIDs", "")
            signal = self._safe_int(self._col(row, col_map, "Power", "-100"))

            client_info = {
                "mac": station_mac.upper(),
                "signal_dbm": signal,
                "probe_requests": probe,
            }

            key = bssid.upper() if bssid and bssid != "(not associated)" else ""
            if key:
                clients.setdefault(key, []).append(client_info)

        return clients

    @staticmethod
    def _col(row: list[str], col_map: dict[str, int], name: str, default: str = "") -> str:
        idx = col_map.get(name)
        if idx is None or idx >= len(row):
            return default
        return row[idx].strip()

    @staticmethod
    def _safe_int(val: str, default: int = 0) -> int:
        cleaned = val.replace("°", "").replace("dB", "").strip()
        try:
            return int(float(cleaned))
        except (ValueError, TypeError):
            return default

    @staticmethod
    def _classify_encryption(enc: str, _cipher: str, auth: str) -> str:
        enc_upper = enc.upper()
        auth_upper = auth.upper()
        if "OPN" in enc_upper or enc_upper == "":
            return "OPN"
        if "WEP" in enc_upper:
            return "WEP"
        if "WPA3" in enc_upper:
            return "WPA3"
        if "WPA2" in enc_upper:
            if "ENTERPRISE" in auth_upper or "802.1X" in auth_upper:
                return "WPA2-Enterprise"
            return "WPA2"
        if "WPA" in enc_upper:
            return "WPA"
        return "Unknown"

    # ── Hidden SSID detection ────────────────────────────────────────────
    def detect_hidden_ssids(self) -> list[ScanResult]:
        """Return networks with empty ESSIDs (hidden)."""
        return [r for r in self._results.values() if r.is_hidden or not r.essid.strip()]

    # ── Vendor lookup ────────────────────────────────────────────────────
    @staticmethod
    def lookup_vendor(bssid: str) -> str:
        prefix = bssid.upper()[:8]
        return _OUI.get(prefix, "Unknown")

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

    # ── Persist results ──────────────────────────────────────────────────
    def save_results(self, path: Path | str) -> Path:
        import json

        path = Path(path)
        path.parent.mkdir(parents=True, exist_ok=True)
        data = [r.to_dict() for r in self.results]
        path.write_text(json.dumps(data, indent=2, default=str), encoding="utf-8")
        logger.info("Scan results saved to %s (%d networks)", path, len(data))
        return path

    def load_results(self, path: Path | str) -> list[ScanResult]:
        import json

        path = Path(path)
        try:
            data = json.loads(path.read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError) as exc:
            logger.error("Failed to load scan results: %s", exc)
            return []

        results: list[ScanResult] = []
        for item in data:
            results.append(ScanResult(
                bssid=item.get("bssid", ""),
                essid=item.get("essid", ""),
                channel=item.get("channel", 0),
                encryption=item.get("encryption", "Unknown"),
                signal_dbm=item.get("signal_dbm", -100),
                wps=item.get("wps", False),
                vendor=item.get("vendor", ""),
                clients=item.get("clients", []),
                first_seen=item.get("first_seen", ""),
                last_seen=item.get("last_seen", ""),
                is_hidden=item.get("is_hidden", False),
            ))
        logger.info("Loaded %d scan results from %s", len(results), path)
        return results
