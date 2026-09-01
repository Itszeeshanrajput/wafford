"""Tool validation for the Wafford framework."""

from __future__ import annotations

import logging
import subprocess
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from packaging.version import InvalidVersion, Version

from wafford.tools.detector import OPTIONAL_TOOLS, REQUIRED_TOOLS, ToolDetector

logger = logging.getLogger(__name__)


@dataclass
class ValidationResult:
    """Result of a single tool validation check."""

    tool: str
    valid: bool
    version: str | None = None
    path: str | None = None
    errors: list[str] = field(default_factory=list)
    warnings: list[str] = field(default_factory=list)

    def to_dict(self) -> dict[str, Any]:
        return {
            "tool": self.tool,
            "valid": self.valid,
            "version": self.version,
            "path": self.path,
            "errors": self.errors,
            "warnings": self.warnings,
        }


class ToolValidator:
    """Validates tool installations and capabilities."""

    def __init__(self) -> None:
        self._detector = ToolDetector()

    def validate_tool(
        self, name: str, min_version: str | None = None
    ) -> ValidationResult:
        result = ValidationResult(tool=name, valid=False)

        status = self._detector.detect_tool(name)
        if not status.get("found"):
            result.errors.append(f"Tool '{name}' not found")
            return result

        result.path = status.get("path")
        result.version = status.get("version")

        if result.version is None:
            result.warnings.append(f"Could not determine version of '{name}'")

        if min_version and result.version:
            if not self._version_meets_minimum(result.version, min_version):
                result.errors.append(
                    f"Version {result.version} is below minimum {min_version}"
                )
                return result

        binary_path = Path(result.path)
        if not binary_path.exists():
            result.errors.append(f"Binary path does not exist: {result.path}")
            return result

        if not binary_path.is_file():
            result.errors.append(f"Path is not a file: {result.path}")
            return result

        result.valid = True
        return result

    def validate_all(self) -> dict[str, ValidationResult]:
        results: dict[str, ValidationResult] = {}
        for name in REQUIRED_TOOLS:
            results[name] = self.validate_tool(name)
        for name in OPTIONAL_TOOLS:
            results[name] = self.validate_tool(name)
        return results

    def validate_injection(self, interface: str) -> ValidationResult:
        result = ValidationResult(tool=f"injection:{interface}", valid=False)

        iw_result = self.validate_tool("iw")
        if not iw_result.valid:
            result.errors.append("iw is required for injection testing")
            return result

        status = self._detector.detect_tool("aireplay-ng")
        if not status.get("found"):
            result.errors.append("aireplay-ng is required for injection testing")
            return result

        try:
            proc = subprocess.run(
                ["aireplay-ng", "--test", interface],
                capture_output=True,
                text=True,
                timeout=30,
            )
            output = proc.stdout + proc.stderr
            if "Injection is working" in output:
                result.valid = True
                result.warnings.append("Packet injection verified")
            elif proc.returncode == 0:
                result.valid = True
            else:
                result.errors.append("Packet injection test failed")
                result.warnings.append(f"aireplay-ng output: {output[:500]}")
        except FileNotFoundError:
            result.errors.append("aireplay-ng binary not found at runtime")
        except subprocess.TimeoutExpired:
            result.errors.append("Injection test timed out")
        except OSError as exc:
            result.errors.append(f"OS error during injection test: {exc}")

        return result

    def validate_monitor(self, interface: str) -> ValidationResult:
        result = ValidationResult(tool=f"monitor:{interface}", valid=False)

        iw_result = self.validate_tool("iw")
        if not iw_result.valid:
            result.errors.append("iw is required for monitor mode validation")
            return result

        iface_info = self._detector.get_adapter_info(interface)
        supported_modes = iface_info.get("supported_modes", [])

        if "monitor" not in supported_modes:
            result.errors.append(
                f"Interface '{interface}' does not support monitor mode"
            )
            result.warnings.append(f"Supported modes: {', '.join(supported_modes)}")
            return result

        try:
            proc = subprocess.run(
                ["iw", "dev", interface, "info"],
                capture_output=True,
                text=True,
                timeout=5,
            )
            if proc.returncode != 0:
                result.errors.append(f"Failed to query interface: {proc.stderr.strip()}")
                return result

            current_mode = "unknown"
            for line in proc.stdout.splitlines():
                if line.strip().startswith("type "):
                    current_mode = line.strip().split(None, 1)[1]

            if current_mode == "monitor":
                result.valid = True
                result.warnings.append("Interface is already in monitor mode")
            elif current_mode == "managed":
                result.valid = True
                result.warnings.append(
                    "Interface is in managed mode but supports monitor mode"
                )
            else:
                result.warnings.append(f"Current mode: {current_mode}")
                result.valid = True

        except FileNotFoundError:
            result.errors.append("iw binary not found at runtime")
        except subprocess.TimeoutExpired:
            result.errors.append("Monitor mode check timed out")
        except OSError as exc:
            result.errors.append(f"Error checking monitor mode: {exc}")

        return result

    def validate_capabilities(self, interface: str) -> dict[str, Any]:
        report: dict[str, Any] = {
            "interface": interface,
            "monitor_mode": False,
            "packet_injection": False,
            "tools_available": False,
            "driver_info": {},
            "errors": [],
            "warnings": [],
        }

        tool_results = self.validate_all()
        required_met = all(
            r.valid
            for name, r in tool_results.items()
            if name in REQUIRED_TOOLS
        )
        report["tools_available"] = required_met

        if not required_met:
            missing = [
                name
                for name, r in tool_results.items()
                if name in REQUIRED_TOOLS and not r.valid
            ]
            report["errors"].append(f"Missing required tools: {', '.join(missing)}")

        adapter_info = self._detector.get_adapter_info(interface)
        report["driver_info"] = adapter_info

        if not adapter_info.get("driver"):
            report["warnings"].append("Could not determine driver information")

        monitor_result = self.validate_monitor(interface)
        report["monitor_mode"] = monitor_result.valid
        report["errors"].extend(monitor_result.errors)
        report["warnings"].extend(monitor_result.warnings)

        injection_result = self.validate_injection(interface)
        report["packet_injection"] = injection_result.valid
        report["errors"].extend(injection_result.errors)
        report["warnings"].extend(injection_result.warnings)

        report["overall_valid"] = (
            report["tools_available"]
            and report["monitor_mode"]
            and len(report["errors"]) == 0
        )

        return report

    def generate_report(self) -> dict[str, Any]:
        results = self.validate_all()

        report: dict[str, Any] = {
            "summary": {
                "total_tools": len(results),
                "valid_tools": sum(1 for r in results.values() if r.valid),
                "invalid_tools": sum(1 for r in results.values() if not r.valid),
                "required_tools": len(REQUIRED_TOOLS),
                "required_valid": sum(
                    1
                    for name, r in results.items()
                    if name in REQUIRED_TOOLS and r.valid
                ),
                "optional_tools": len(OPTIONAL_TOOLS),
                "optional_valid": sum(
                    1
                    for name, r in results.items()
                    if name in OPTIONAL_TOOLS and r.valid
                ),
            },
            "tools": {name: r.to_dict() for name, r in results.items()},
            "root_access": self._detector.check_root(),
            "wireless_interfaces": self._detector.check_wifi_adapter(),
        }

        report["overall_status"] = (
            report["summary"]["required_valid"] == report["summary"]["required_tools"]
        )

        return report

    @staticmethod
    def _version_meets_minimum(current: str, minimum: str) -> bool:
        try:
            current_ver = Version(current)
            minimum_ver = Version(minimum)
            return current_ver >= minimum_ver
        except InvalidVersion:
            try:
                cur_parts = [int(x) for x in current.split(".") if x.isdigit()]
                min_parts = [int(x) for x in minimum.split(".") if x.isdigit()]
                max_len = max(len(cur_parts), len(min_parts))
                cur_parts.extend([0] * (max_len - len(cur_parts)))
                min_parts.extend([0] * (max_len - len(min_parts)))
                return cur_parts >= min_parts
            except (ValueError, TypeError):
                return True
