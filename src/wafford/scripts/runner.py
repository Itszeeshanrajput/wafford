"""ScriptRunner — orchestrates Wafford bash scripts."""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

from wafford.scripts.shell import ShellRunner

BASH_DIR = Path(__file__).resolve().parent / "bash"


def _script(name: str) -> str:
    path = BASH_DIR / name
    if not path.exists():
        raise FileNotFoundError(f"Script not found: {path}")
    return str(path)


def _parse_json(output: str) -> dict[str, Any]:
    """Best-effort JSON parse of the last JSON object/array in *output*."""
    text = output.strip()
    if not text:
        return {"error": "empty output"}
    # Find the last { or [ to handle log lines before JSON
    for idx in range(len(text) - 1, -1, -1):
        if text[idx] in ("{", "["):
            try:
                return json.loads(text[idx:])
            except json.JSONDecodeError:
                continue
    return {"raw": text}


def _parse_json_array(output: str) -> list[dict[str, Any]]:
    result = _parse_json(output)
    if isinstance(result, list):
        return result
    return [result]


class ScriptRunner:
    """High-level orchestrator that invokes Wafford bash scripts and
    returns structured data."""

    def __init__(self, shell: ShellRunner | None = None) -> None:
        self.shell = shell or ShellRunner()

    # ------------------------------------------------------------------
    # Monitor mode
    # ------------------------------------------------------------------

    def run_monitor_mode(
        self, interface: str, action: str = "on"
    ) -> dict[str, Any]:
        result = self.shell.sudo_run(
            f"{_script('monitor_mode.sh')} {interface} {action}", timeout=30
        )
        data = _parse_json(result.stdout)
        data["returncode"] = result.returncode
        data["duration"] = result.duration
        return data

    # ------------------------------------------------------------------
    # Scanning
    # ------------------------------------------------------------------

    def run_scan(
        self,
        interface: str,
        channels: str = "1-14",
        duration: int = 30,
        output_dir: str = "/tmp/wafford_scan",  # noqa: S108
    ) -> dict[str, Any]:
        Path(output_dir).mkdir(parents=True, exist_ok=True)
        result = self.shell.sudo_run(
            f"{_script('scan.sh')} {interface} {channels} {duration} {output_dir}",
            timeout=duration + 30,
        )
        data = _parse_json(result.stdout)
        data["returncode"] = result.returncode
        data["duration"] = result.duration
        return data

    # ------------------------------------------------------------------
    # Deauth
    # ------------------------------------------------------------------

    def run_deauth(
        self,
        interface: str,
        bssid: str,
        client: str = "FF:FF:FF:FF:FF:FF",
        count: int = 5,
        interval: float = 0.1,
    ) -> dict[str, Any]:
        result = self.shell.sudo_run(
            f"{_script('deauth.sh')} {interface} {bssid} {client} {count} {interval}",
            timeout=60,
        )
        data = _parse_json(result.stdout)
        data["returncode"] = result.returncode
        data["duration"] = result.duration
        return data

    # ------------------------------------------------------------------
    # WPA handshake
    # ------------------------------------------------------------------

    def run_handshake(
        self,
        interface: str,
        bssid: str,
        channel: int = 6,
        duration: int = 60,
        output_dir: str = "/tmp/wafford_handshake",  # noqa: S108
    ) -> dict[str, Any]:
        Path(output_dir).mkdir(parents=True, exist_ok=True)
        result = self.shell.sudo_run(
            f"{_script('handshake_capture.sh')} {interface} {bssid} "
            f"{channel} {duration} {output_dir}",
            timeout=duration + 60,
        )
        data = _parse_json(result.stdout)
        data["returncode"] = result.returncode
        data["duration"] = result.duration
        return data

    # ------------------------------------------------------------------
    # PMKID
    # ------------------------------------------------------------------

    def run_pmkid(
        self,
        interface: str,
        bssid: str = "",
        channel: int = 6,
        timeout: int = 120,
        output_dir: str = "/tmp/wafford_pmkid",  # noqa: S108
    ) -> dict[str, Any]:
        Path(output_dir).mkdir(parents=True, exist_ok=True)
        result = self.shell.sudo_run(
            f"{_script('pmkid_capture.sh')} {interface} {bssid} "
            f"{channel} {timeout} {output_dir}",
            timeout=timeout + 60,
        )
        data = _parse_json(result.stdout)
        data["returncode"] = result.returncode
        data["duration"] = result.duration
        return data

    # ------------------------------------------------------------------
    # Evil twin
    # ------------------------------------------------------------------

    def run_evil_twin(
        self,
        interface: str,
        ssid: str,
        channel: int = 6,
        dns_server: str = "8.8.8.8",
        gateway: str = "10.0.0.1",
    ) -> dict[str, Any]:
        result = self.shell.sudo_run(
            f"{_script('evil_twin.sh')} {interface} {ssid} {channel} {dns_server} {gateway}",
            timeout=30,
        )
        data = _parse_json(result.stdout)
        data["returncode"] = result.returncode
        data["duration"] = result.duration
        return data

    # ------------------------------------------------------------------
    # Captive portal
    # ------------------------------------------------------------------

    def run_captive_portal(
        self,
        interface: str,
        template: str = "default",
        port: int = 8080,
        output_dir: str = "/tmp/wafford_captive",  # noqa: S108
    ) -> dict[str, Any]:
        Path(output_dir).mkdir(parents=True, exist_ok=True)
        result = self.shell.sudo_run(
            f"{_script('captive_portal.sh')} {interface} {template} "
            f"{port} {output_dir}",
            timeout=15,
        )
        data = _parse_json(result.stdout)
        data["returncode"] = result.returncode
        data["duration"] = result.duration
        return data

    # ------------------------------------------------------------------
    # WEP
    # ------------------------------------------------------------------

    def run_wep_attack(
        self,
        interface: str,
        bssid: str,
        channel: int = 6,
        method: str = "ptw",
        duration: int = 120,
    ) -> dict[str, Any]:
        result = self.shell.sudo_run(
            f"{_script('wep_attack.sh')} {interface} {bssid} {channel} {method} {duration}",
            timeout=duration + 60,
        )
        data = _parse_json(result.stdout)
        data["returncode"] = result.returncode
        data["duration"] = result.duration
        return data

    # ------------------------------------------------------------------
    # WPA crack
    # ------------------------------------------------------------------

    def run_wpa_crack(
        self,
        capture: str,
        wordlist: str = "/usr/share/wordlists/rockyou.txt",
        engine: str = "hashcat",
        mode: str = "dictionary",
        rules: str = "",
        mask: str = "",
    ) -> dict[str, Any]:
        cmd = f"{_script('wpa_crack.sh')} {capture} {wordlist} {engine} {mode}"
        if rules:
            cmd += f" {rules}"
        if mask:
            cmd += f" {mask}"
        result = self.shell.sudo_run(cmd, timeout=3600)
        data = _parse_json(result.stdout)
        data["returncode"] = result.returncode
        data["duration"] = result.duration
        return data

    # ------------------------------------------------------------------
    # Karma
    # ------------------------------------------------------------------

    def run_karma(self, interface: str) -> dict[str, Any]:
        result = self.shell.sudo_run(
            f"{_script('karma_attack.sh')} {interface}", timeout=15
        )
        data = _parse_json(result.stdout)
        data["returncode"] = result.returncode
        data["duration"] = result.duration
        return data

    # ------------------------------------------------------------------
    # Enterprise
    # ------------------------------------------------------------------

    def run_enterprise(
        self, interface: str, ssid: str = "EnterpriseAP"
    ) -> dict[str, Any]:
        result = self.shell.sudo_run(
            f"{_script('enterprise_attack.sh')} {interface} {ssid}", timeout=15
        )
        data = _parse_json(result.stdout)
        data["returncode"] = result.returncode
        data["duration"] = result.duration
        return data

    # ------------------------------------------------------------------
    # WiFi Direct
    # ------------------------------------------------------------------

    def run_wifi_direct(
        self, interface: str, action: str = "discover", extra: str = ""
    ) -> dict[str, Any]:
        cmd = f"{_script('wifi_direct.sh')} {interface} {action}"
        if extra:
            cmd += f" {extra}"
        result = self.shell.sudo_run(cmd, timeout=30)
        data = _parse_json(result.stdout)
        data["returncode"] = result.returncode
        data["duration"] = result.duration
        return data

    # ------------------------------------------------------------------
    # DoS
    # ------------------------------------------------------------------

    def run_dos(
        self,
        interface: str,
        target: str,
        method: str = "deauth",
        duration: int = 30,
        rate: int = 64,
    ) -> dict[str, Any]:
        result = self.shell.sudo_run(
            f"{_script('dos_attack.sh')} {interface} {method} {target} {duration} {rate}",
            timeout=duration + 30,
        )
        data = _parse_json(result.stdout)
        data["returncode"] = result.returncode
        data["duration"] = result.duration
        return data

    # ------------------------------------------------------------------
    # Bluetooth
    # ------------------------------------------------------------------

    def run_bluetooth_scan(
        self, scan_type: str = "both", duration: int = 15
    ) -> dict[str, Any]:
        result = self.shell.sudo_run(
            f"{_script('bluetooth_scan.sh')} {scan_type} {duration}",
            timeout=duration + 30,
        )
        data = _parse_json_array(result.stdout)
        return {
            "devices": data,
            "returncode": result.returncode,
            "duration": result.duration,
        }

    # ------------------------------------------------------------------
    # Cleanup
    # ------------------------------------------------------------------

    def run_cleanup(self, interface: str = "") -> dict[str, Any]:
        result = self.shell.sudo_run(
            f"{_script('cleanup.sh')} {interface}", timeout=30
        )
        data = _parse_json(result.stdout)
        data["returncode"] = result.returncode
        data["duration"] = result.duration
        return data
