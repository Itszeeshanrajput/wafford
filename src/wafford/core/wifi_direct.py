"""WiFi Direct (P2P) attack modules for Wafford."""

from __future__ import annotations

import asyncio
import logging
import re
import time
from dataclasses import dataclass, field
from pathlib import Path
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from collections.abc import Callable

from wafford.scripts.shell import ShellRunner

logger = logging.getLogger("wafford.core.wifi_direct")


@dataclass
class WiFiDirectPeer:
    """A discovered WiFi Direct peer device."""
    mac: str
    device_name: str = ""
    device_type: str = ""
    interface: str = ""
    signal_level: int = 0
    first_seen: float = 0.0
    last_seen: float = 0.0


@dataclass
class WiFiDirectResult:
    """Result of a WiFi Direct operation."""
    operation: str = ""
    peers: list[WiFiDirectPeer] = field(default_factory=list)
    group_owner: bool = False
    group_ssid: str = ""
    group_freq: int = 0
    success: bool = False
    error: str = ""
    started_at: float = 0.0
    ended_at: float = 0.0


class WiFiDirectAttack:
    """WiFi Direct / P2P discovery and attack module.

    Implements WiFi Peer-to-Peer discovery, group owner negotiation,
    and P2P monitoring via wpa_supplicant P2P commands.
    """

    WPA_SUPPLICANT_CONF = "/tmp/wafford_wpa_supplicant.conf"  # noqa: S108

    def __init__(self, interface: str) -> None:
        self.interface = interface
        self.shell = ShellRunner()
        self._running = False
        self._wpa_process: asyncio.subprocess.Process | None = None
        self._peers: dict[str, WiFiDirectPeer] = {}
        self._group_owner = False
        self._group_ssid = ""
        self._group_freq = 0
        self._peer_callbacks: list[Callable[[WiFiDirectPeer], None]] = []

    def on_peer_found(self, callback: Callable[[WiFiDirectPeer], None]) -> None:
        """Register callback for discovered peers."""
        self._peer_callbacks.append(callback)

    def _emit_peer(self, peer: WiFiDirectPeer) -> None:
        """Notify callbacks of a discovered peer."""
        for cb in self._peer_callbacks:
            try:
                cb(peer)
            except Exception as e:
                logger.error("Peer callback error: %s", e)

    async def _start_wpa_supplicant_p2p(self) -> bool:
        """Start wpa_supplicant in P2P mode."""
        config = f"""ctrl_interface=/var/run/wpa_supplicant_p2p
ctrl_interface_group=0
device_name=Wafford-P2P
device_type=1-0050F204-1
driver_param=p2p_device_interface={self.interface}

p2p_no_group_iface=1
p2p_go_intent=7
"""
        try:
            with Path(self.WPA_SUPPLICANT_CONF).open("w") as f:
                f.write(config)
        except OSError as e:
            logger.error("Failed to write wpa_supplicant config: %s", e)
            return False

        try:
            proc = await asyncio.create_subprocess_exec(
                "wpa_supplicant", "-i", self.interface,
                "-c", self.WPA_SUPPLICANT_CONF,
                "-D", "nl80211",
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE,
            )
            self._wpa_process = proc

            await asyncio.sleep(3)

            if proc.returncode is not None:
                logger.error("wpa_supplicant failed to start")
                return False

            logger.info("wpa_supplicant P2P started on %s", self.interface)
            return True

        except FileNotFoundError:
            logger.error("wpa_supplicant not found")
            return False
        except Exception as e:
            logger.error("Failed to start wpa_supplicant: %s", e)
            return False

    async def _wpa_cli_command(self, command: str) -> str:
        """Execute a wpa_cli command and return the result.

        Args:
            command: The wpa_cli command string.
        """
        try:
            cmd_parts = (
                ["wpa_cli", "-p", "/var/run/wpa_supplicant_p2p", "-i", self.interface]
                + command.split()
            )
            proc = await asyncio.create_subprocess_exec(
                *cmd_parts,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE,
            )
            stdout, _ = await asyncio.wait_for(proc.communicate(), timeout=10)
            return stdout.decode("utf-8", errors="replace")
        except Exception as e:
            logger.debug("wpa_cli command failed: %s: %s", command, e)
            return ""

    async def discover_peers(self, duration: int = 30) -> WiFiDirectResult:
        """Discover WiFi Direct (P2P) peer devices.

        Scans for P2P-capable devices using P2P device discovery.

        Args:
            duration: Discovery duration in seconds.
        """
        self._running = True
        self._peers.clear()
        start_time = time.time()

        result = WiFiDirectResult(
            operation="discover_peers",
            started_at=start_time,
        )

        logger.info("Starting P2P peer discovery: iface=%s duration=%ds",
                     self.interface, duration)

        try:
            started = await self._start_wpa_supplicant_p2p()
            if not started:
                result.error = "Failed to start wpa_supplicant P2P mode"
                self._running = False
                return result

            await self._wpa_cli_command("p2p_find")

            scan_end = time.time() + duration
            while time.time() < scan_end and self._running:
                await asyncio.sleep(2)
                await self._check_p2p_events()

            await self._wpa_cli_command("p2p_stop_find")

            for peer in self._peers.values():
                result.peers.append(peer)

            result.success = True
            result.ended_at = time.time()
            logger.info("Discovered %d P2P peers", len(result.peers))

        except asyncio.CancelledError:
            logger.info("P2P discovery cancelled")
            result.error = "Cancelled by user"
        except Exception as e:
            logger.error("P2P discovery failed: %s", e)
            result.error = str(e)
        finally:
            self._running = False

        return result

    async def negotiate_group_owner(
        self,
        peer_mac: str,
        intent: int = 15,
    ) -> WiFiDirectResult:
        """Initiate P2P group owner negotiation with a peer.

        Attempts to form a P2P group with the specified peer,
        optionally forcing group owner status.

        Args:
            peer_mac: Target peer MAC address.
            intent: Group owner intent (0-15, 15 = force GO).
        """
        start_time = time.time()
        result = WiFiDirectResult(
            operation="negotiate_group_owner",
            started_at=start_time,
        )

        logger.info(
            "Starting GO negotiation: peer=%s intent=%d",
            peer_mac, intent,
        )

        try:
            started = await self._start_wpa_supplicant_p2p()
            if not started:
                result.error = "Failed to start wpa_supplicant P2P mode"
                return result

            await self._wpa_cli_command(f"p2p_connect {peer_mac} go_intent={intent}")
            await self._wpa_cli_command(f"p2p_connect {peer_mac}")

            await asyncio.sleep(5)

            group_info = await self._wpa_cli_command("p2p_group_add")
            if "OK" in group_info:
                status = await self._wpa_cli_command("status")
                self._parse_group_status(status)
                result.group_owner = self._group_owner
                result.group_ssid = self._group_ssid
                result.group_freq = self._group_freq

            peer = self._peers.get(peer_mac)
            if peer:
                result.peers.append(peer)

            result.success = True
            result.ended_at = time.time()
            logger.info(
                "GO negotiation complete: GO=%s SSID=%s",
                result.group_owner, result.group_ssid,
            )

        except Exception as e:
            logger.error("GO negotiation failed: %s", e)
            result.error = str(e)
        finally:
            self._running = False

        return result

    async def monitor_p2p_traffic(
        self,
        duration: int = 60,
    ) -> WiFiDirectResult:
        """Monitor P2P group traffic.

        Monitors traffic in a P2P group for analysis.

        Args:
            duration: Monitoring duration in seconds.
        """
        self._running = True
        start_time = time.time()

        result = WiFiDirectResult(
            operation="monitor_p2p_traffic",
            started_at=start_time,
        )

        logger.info("Starting P2P traffic monitor: duration=%ds", duration)

        try:
            output_dir = "/tmp/wafford_captures"  # noqa: S108
            self.shell.run(f"mkdir -p {output_dir}", timeout=5)

            cap_prefix = f"{output_dir}/p2p_{int(time.time())}"
            cmd = (
                f"airodump-ng {self.interface} "
                f"--write {cap_prefix} "
                f"--output-format pcap"
            )

            proc = await asyncio.create_subprocess_shell(  # noqa: S602 -- composed airodump command
                cmd,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE,
            )
            self._wpa_process = proc

            await asyncio.sleep(duration)

            if proc.returncode is None:
                proc.terminate()
                try:
                    await asyncio.wait_for(proc.wait(), timeout=5.0)
                except TimeoutError:
                    proc.kill()

            result.success = True
            result.ended_at = time.time()
            logger.info("P2P traffic capture completed")

        except asyncio.CancelledError:
            result.error = "Cancelled by user"
        except Exception as e:
            logger.error("P2P traffic monitoring failed: %s", e)
            result.error = str(e)
        finally:
            self._running = False

        return result

    async def _check_p2p_events(self) -> None:
        """Check for P2P events from wpa_supplicant."""
        try:
            status = await self._wpa_cli_command("p2p_peers")
            if not status or "FAIL" in status:
                return

            for line in status.splitlines():
                mac = line.strip()
                if re.match(r"^([0-9A-Fa-f]{2}:){5}[0-9A-Fa-f]{2}$", mac):
                    if mac not in self._peers:
                        name = ""
                        try:
                            name_out = await self._wpa_cli_command(
                                f"p2p_peer {mac}"
                            )
                            for name_line in name_out.splitlines():
                                if "device_name=" in name_line:
                                    name = name_line.split("=", 1)[1]
                                    break
                        except Exception:  # noqa: S110 -- non-fatal peer name lookup
                            pass

                        peer = WiFiDirectPeer(
                            mac=mac,
                            device_name=name,
                            interface=self.interface,
                            first_seen=time.time(),
                            last_seen=time.time(),
                        )
                        self._peers[mac] = peer
                        self._emit_peer(peer)
                        logger.info("P2P peer discovered: %s (%s)", mac, name)
                    else:
                        self._peers[mac].last_seen = time.time()

        except Exception as e:
            logger.debug("P2P event check error: %s", e)

    def _parse_group_status(self, status_output: str) -> None:
        """Parse wpa_supplicant status output for group info.

        Args:
            status_output: Raw output from 'wpa_cli status'.
        """
        for line in status_output.splitlines():
            line = line.strip()
            if "=" in line:
                key, _, value = line.partition("=")
                key = key.strip()
                value = value.strip()

                if key == "p2p_group_owner":
                    self._group_owner = value == "1"
                elif key == "ssid":
                    self._group_ssid = value
                elif key == "freq":
                    try:
                        self._group_freq = int(value)
                    except ValueError:
                        pass
                elif key == "wpa_state":
                    if value == "COMPLETED":
                        logger.info("P2P group established")

    def get_all_peers(self) -> list[WiFiDirectPeer]:
        """Return all discovered P2P peers."""
        return list(self._peers.values())

    def get_peer_count(self) -> int:
        """Return number of discovered peers."""
        return len(self._peers)

    async def stop(self) -> None:
        """Stop all P2P operations and cleanup."""
        logger.info("Stopping WiFi Direct operations")
        self._running = False

        try:
            await self._wpa_cli_command("p2p_stop_find")
        except Exception:  # noqa: S110 -- best-effort cleanup
            pass

        if self._wpa_process and self._wpa_process.returncode is None:
            self._wpa_process.terminate()
            try:
                await asyncio.wait_for(self._wpa_process.wait(), timeout=5.0)
            except TimeoutError:
                self._wpa_process.kill()

        self.shell.run("pkill -f wpa_supplicant_p2p", timeout=5, capture_output=True)

        Path(self.WPA_SUPPLICANT_CONF).unlink(missing_ok=True)

        logger.info("WiFi Direct operations stopped")

    @property
    def is_running(self) -> bool:
        """Check if P2P discovery is running."""
        return self._running
