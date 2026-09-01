"""Monitor mode management, channel hopping, and injection verification."""

from __future__ import annotations

import asyncio
import logging
import re
import shutil
import subprocess
from pathlib import Path
from typing import Any

logger = logging.getLogger(__name__)


class MonitorMode:
    """High-level interface for enabling / disabling monitor mode and channel hopping."""

    def __init__(self, interface: str) -> None:
        self._interface = interface
        self._original_mode: str = "managed"
        self._original_channel: int = 0
        self._hopping_task: asyncio.Task[None] | None = None
        self._hopping = False

    @property
    def interface(self) -> str:
        return self._interface

    @property
    def is_monitoring(self) -> bool:
        return self._get_current_mode() == "monitor"

    # ── Enable / Disable ─────────────────────────────────────────────────
    def enable(self, iface: str | None = None) -> str:
        """Switch the given interface (or the one passed at init) into monitor mode.

        Returns the name of the interface in monitor mode, which may differ
        from the input (e.g. wlan0 -> wlan0mon).
        """
        iface = iface or self._interface
        self._original_mode = self._get_current_mode(iface)
        self._original_channel = self._get_current_channel(iface)

        self._kill_conflicting()
        new_iface = self._start_monitor(iface)
        self._interface = new_iface

        if not self.verify_monitor(new_iface):
            from wafford.exceptions import InterfaceError
            raise InterfaceError(
                f"Monitor mode verification failed for {new_iface}",
                interface=new_iface,
            )

        logger.info("Monitor mode enabled on %s", new_iface)
        return new_iface

    def disable(self, iface: str | None = None) -> None:
        """Restore the interface to managed mode."""
        iface = iface or self._interface
        self._stop_monitor(iface)

        original = iface.rstrip("mon")
        if original != iface:
            restored_iface = original
        else:
            restored_iface = iface

        # Restore original channel if we saved one
        if self._original_channel > 0:
            try:
                self.set_channel(restored_iface, self._original_channel)
            except Exception:
                logger.debug("Failed to restore channel on %s", restored_iface, exc_info=True)

        logger.info("Managed mode restored on %s", restored_iface)

    # ── Channel hopping ──────────────────────────────────────────────────
    async def channel_hop(
        self,
        channels: list[int],
        interval: float = 0.5,
        callback: Any | None = None,
    ) -> None:
        """Continuously hop through the given channels.

        Stops when `stop_hopping()` is called or the task is cancelled.
        """
        if not channels:
            logger.warning("No channels provided for hopping")
            return

        self._hopping = True
        idx = 0
        logger.info("Channel hopping started: %s (interval %.2fs)", channels, interval)

        try:
            while self._hopping:
                ch = channels[idx % len(channels)]
                try:
                    self.set_channel(self._interface, ch)
                except Exception as exc:
                    logger.debug("Channel hop to %d failed: %s", ch, exc)

                if callback is not None:
                    try:
                        result = callback(ch)
                        if asyncio.iscoroutine(result):
                            await result
                    except Exception:
                        logger.exception("Channel hop callback error")

                idx += 1
                await asyncio.sleep(interval)
        except asyncio.CancelledError:
            logger.debug("Channel hopping cancelled")
        finally:
            self._hopping = False
            logger.info("Channel hopping stopped")

    async def start_hopping(
        self,
        channels: list[int],
        interval: float = 0.5,
        callback: Any | None = None,
    ) -> None:
        """Start channel hopping as a background task."""
        if self._hopping_task and not self._hopping_task.done():
            logger.warning("Channel hopping already running")
            return
        self._hopping_task = asyncio.create_task(
            self.channel_hop(channels, interval, callback)
        )

    async def stop_hopping(self) -> None:
        """Stop the background channel hopping task."""
        self._hopping = False
        if self._hopping_task and not self._hopping_task.done():
            self._hopping_task.cancel()
            try:
                await self._hopping_task
            except asyncio.CancelledError:
                pass
        self._hopping_task = None
        logger.info("Channel hopping stop requested")

    # ── Verify ───────────────────────────────────────────────────────────
    def verify_monitor(self, iface: str | None = None) -> bool:
        """Confirm the interface is in monitor mode."""
        iface = iface or self._interface
        mode = self._get_current_mode(iface)
        return mode == "monitor"

    # ── Injection test ───────────────────────────────────────────────────
    def inject_test(self, iface: str | None = None) -> bool:
        """Test packet injection capability using aireplay-ng --test."""
        iface = iface or self._interface
        aireplay = shutil.which("aireplay-ng")
        if not aireplay:
            logger.warning("aireplay-ng not found, cannot test injection")
            return False

        logger.info("Running injection test on %s", iface)
        try:
            proc = subprocess.run(
                [aireplay, "--test", iface],
                capture_output=True,
                text=True,
                timeout=30,
            )
            output = proc.stdout + proc.stderr
            success = (
                "100% injection" in output
                or "injection is working" in output.lower()
                or "injection works" in output.lower()
            )
            logger.info("Injection test %s", "PASSED" if success else "FAILED")
            return success
        except subprocess.TimeoutExpired:
            logger.warning("Injection test timed out on %s", iface)
            return False
        except FileNotFoundError:
            logger.error("aireplay-ng not found")
            return False

    # ── Internal helpers ─────────────────────────────────────────────────
    def _get_current_mode(self, iface: str | None = None) -> str:
        iface = iface or self._interface
        type_path = Path(f"/sys/class/net/{iface}/type")
        try:
            with type_path.open() as f:
                val = f.read().strip()
            if val == "803":
                return "monitor"
            return "managed"
        except (OSError, FileNotFoundError):
            pass

        iw = shutil.which("iw")
        if iw:
            try:
                proc = subprocess.run(
                    [iw, "dev", iface, "info"],
                    capture_output=True, text=True, timeout=5,
                )
                if "type monitor" in proc.stdout.lower():
                    return "monitor"
                return "managed"
            except (subprocess.SubprocessError, FileNotFoundError):
                pass
        return "unknown"

    def _get_current_channel(self, iface: str | None = None) -> int:
        iface = iface or self._interface
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

    def _kill_conflicting(self) -> None:
        conflicting = [
            "NetworkManager", "wpa_supplicant", "dhclient", "dhcpcd",
            "plymouth", "wpa_cli", "connman", "iwd", "dhcpcui",
            "wpa_actiond",
        ]
        for name in conflicting:
            try:
                subprocess.run(["killall", "-q", name], capture_output=True, timeout=5)
            except (subprocess.SubprocessError, FileNotFoundError):
                pass

    def _start_monitor(self, iface: str) -> str:
        """Use airmon-ng to enable monitor mode, return the monitor interface name."""
        airmon = shutil.which("airmon-ng")
        if not airmon:
            from wafford.exceptions import ToolNotFoundError
            raise ToolNotFoundError("airmon-ng not found", tool="airmon-ng")

        proc = subprocess.run(
            [airmon, "start", iface],
            capture_output=True, text=True, timeout=30,
        )
        if proc.returncode != 0:
            from wafford.exceptions import InterfaceError
            raise InterfaceError(
                f"airmon-ng start failed: {proc.stderr.strip()}",
                interface=iface,
            )

        return self._parse_monitor_iface(iface, proc.stdout)

    def _stop_monitor(self, iface: str) -> None:
        """Use airmon-ng to disable monitor mode."""
        airmon = shutil.which("airmon-ng")
        if not airmon:
            from wafford.exceptions import ToolNotFoundError
            raise ToolNotFoundError("airmon-ng not found", tool="airmon-ng")

        proc = subprocess.run(
            [airmon, "stop", iface],
            capture_output=True, text=True, timeout=30,
        )
        if proc.returncode != 0:
            from wafford.exceptions import InterfaceError
            raise InterfaceError(
                f"airmon-ng stop failed: {proc.stderr.strip()}",
                interface=iface,
            )

    @staticmethod
    def _parse_monitor_iface(original: str, output: str) -> str:
        """Extract the monitor interface name from airmon-ng output."""
        for line in output.splitlines():
            if "monitor mode" in line.lower():
                match = re.search(r"on\s+(\S+)", line)
                if match:
                    return match.group(1)

        # Fallback: common naming conventions
        for suffix in ("mon", "mon0", "sta"):
            candidate = original + suffix
            if Path(f"/sys/class/net/{candidate}").is_dir():
                return candidate

        return original

    def set_channel(self, iface: str, channel: int) -> None:
        """Set the radio channel for the given interface."""
        iw = shutil.which("iw")
        if not iw:
            from wafford.exceptions import ToolNotFoundError
            raise ToolNotFoundError("iw not found", tool="iw")

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
        logger.debug("Channel set to %d on %s", channel, iface)
