"""Report generation for the Wafford framework."""

from __future__ import annotations

import json
import logging
import os
from dataclasses import asdict, dataclass, field
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

from jinja2 import Environment, FileSystemLoader, select_autoescape

from wafford.constants import REPORT_DIR

logger = logging.getLogger(__name__)

TEMPLATES_DIR = Path(__file__).parent / "templates"


@dataclass
class ReportData:
    """Structured data for report generation."""

    session: dict[str, Any] = field(default_factory=dict)
    networks: list[dict[str, Any]] = field(default_factory=list)
    attacks: list[dict[str, Any]] = field(default_factory=list)
    handshakes: list[dict[str, Any]] = field(default_factory=list)
    credentials: list[dict[str, Any]] = field(default_factory=list)
    duration: float = 0.0
    summary: str = ""

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


class ReportGenerator:
    """Generates audit reports in multiple formats."""

    def __init__(self, output_dir: Path | str | None = None) -> None:
        self._output_dir = Path(output_dir) if output_dir else REPORT_DIR
        self._output_dir.mkdir(parents=True, exist_ok=True)
        self._env = Environment(
            loader=FileSystemLoader(str(TEMPLATES_DIR)),
            autoescape=select_autoescape(["html"]),
            trim_blocks=True,
            lstrip_blocks=True,
        )

    def generate_session_report(self, session_id: str) -> ReportData:
        return ReportData(
            session={
                "id": session_id,
                "start_time": datetime.now(UTC).isoformat(),
                "hostname": self._get_hostname(),
                "user": os.environ.get("USER", "unknown"),
                "tool_version": self._get_version(),
            },
            networks=[],
            attacks=[],
            handshakes=[],
            credentials=[],
            duration=0.0,
            summary="Session report generated",
        )

    def generate_network_report(self, network_id: str) -> dict[str, Any]:
        return {
            "network_id": network_id,
            "generated_at": datetime.now(UTC).isoformat(),
            "bssid": "",
            "essid": "",
            "channel": 0,
            "encryption": "",
            "signal": 0,
            "clients": [],
            "attacks": [],
            "handshakes": [],
            "notes": "",
        }

    def generate_attack_report(self, attack_id: str) -> dict[str, Any]:
        return {
            "attack_id": attack_id,
            "generated_at": datetime.now(UTC).isoformat(),
            "type": "",
            "target": "",
            "start_time": "",
            "end_time": "",
            "duration": 0.0,
            "success": False,
            "packets_sent": 0,
            "output": "",
            "errors": [],
        }

    def get_statistics(self) -> dict[str, Any]:
        return {
            "total_scans": 0,
            "total_attacks": 0,
            "successful_attacks": 0,
            "failed_attacks": 0,
            "networks_discovered": 0,
            "handshakes_captured": 0,
            "credentials_found": 0,
            "total_duration": 0.0,
            "average_scan_duration": 0.0,
        }

    def build_html(self, report_data: ReportData, template: str = "html_report.html.j2") -> str:
        tmpl = self._env.get_template(template)
        stats = self._compute_statistics(report_data)
        return tmpl.render(
            data=report_data.to_dict(),
            stats=stats,
            generated_at=datetime.now(UTC).strftime("%Y-%m-%d %H:%M:%S UTC"),
            duration_human=self._format_duration(report_data.duration),
        )

    def build_json(self, report_data: ReportData) -> str:
        output = report_data.to_dict()
        output["generated_at"] = datetime.now(UTC).isoformat()
        output["statistics"] = self._compute_statistics(report_data)
        return json.dumps(output, indent=2, default=str)

    def build_markdown(self, report_data: ReportData) -> str:
        stats = self._compute_statistics(report_data)
        lines: list[str] = []

        lines.append("# Wafford Audit Report")
        lines.append("")
        lines.append(f"**Generated:** {datetime.now(UTC).strftime('%Y-%m-%d %H:%M:%S UTC')}")
        if report_data.session.get("id"):
            lines.append(f"**Session:** {report_data.session['id']}")
        lines.append(f"**Duration:** {self._format_duration(report_data.duration)}")
        lines.append("")

        lines.append("## Executive Summary")
        lines.append("")
        lines.append(f"- **Networks Discovered:** {stats['networks_discovered']}")
        lines.append(f"- **Attacks Performed:** {stats['total_attacks']}")
        lines.append(f"- **Successful Attacks:** {stats['successful_attacks']}")
        lines.append(f"- **Failed Attacks:** {stats['failed_attacks']}")
        lines.append(f"- **Handshakes Captured:** {stats['handshakes_captured']}")
        lines.append(f"- **Credentials Found:** {stats['credentials_found']}")
        lines.append("")

        if report_data.networks:
            lines.append("## Networks Found")
            lines.append("")
            lines.append("| # | ESSID | BSSID | Channel | Encryption | Signal |")
            lines.append("|---|-------|-------|---------|------------|--------|")
            for i, net in enumerate(report_data.networks, 1):
                lines.append(
                    f"| {i} | {net.get('essid', 'N/A')} | {net.get('bssid', 'N/A')} "
                    f"| {net.get('channel', '?')} | {net.get('encryption', '?')} "
                    f"| {net.get('signal', '?')} dBm |"
                )
            lines.append("")

        if report_data.attacks:
            lines.append("## Attacks Performed")
            lines.append("")
            lines.append("| # | Type | Target | Status | Duration |")
            lines.append("|---|------|--------|--------|----------|")
            for i, atk in enumerate(report_data.attacks, 1):
                status = "Success" if atk.get("success") else "Failed"
                lines.append(
                    f"| {i} | {atk.get('type', '?')} | {atk.get('target', '?')} "
                    f"| {status} | {self._format_duration(atk.get('duration', 0))} |"
                )
            lines.append("")

        if report_data.credentials:
            lines.append("## Credentials Captured")
            lines.append("")
            lines.append("| # | BSSID | ESSID | Password |")
            lines.append("|---|-------|-------|----------|")
            for i, cred in enumerate(report_data.credentials, 1):
                lines.append(
                    f"| {i} | {cred.get('bssid', '?')} | {cred.get('essid', '?')} "
                    f"| `{cred.get('password', '***')}` |"
                )
            lines.append("")

        if report_data.handshakes:
            lines.append("## Handshakes")
            lines.append("")
            for i, hs in enumerate(report_data.handshakes, 1):
                lines.append(
                    f"{i}. **{hs.get('essid', 'Unknown')}** — "
                    f"`{hs.get('path', 'N/A')}`"
                )
            lines.append("")

        if report_data.summary:
            lines.append("## Notes")
            lines.append("")
            lines.append(report_data.summary)
            lines.append("")

        lines.append("---")
        lines.append("*Generated by Wafford WiFi Auditing Framework*")

        return "\n".join(lines)

    def build_pdf(self, report_data: ReportData) -> bytes | str:
        html = self.build_html(report_data, template="pdf_report.html.j2")
        try:
            import weasyprint
            pdf_bytes: bytes = weasyprint.HTML(string=html).write_pdf()
            return pdf_bytes
        except ImportError:
            logger.warning("weasyprint not installed, falling back to HTML")
            return html
        except Exception as exc:
            logger.error("PDF generation failed: %s", exc)
            return html

    def _compute_statistics(self, report_data: ReportData) -> dict[str, Any]:
        successful = sum(
            1 for a in report_data.attacks if a.get("success")
        )
        failed = len(report_data.attacks) - successful

        return {
            "networks_discovered": len(report_data.networks),
            "total_attacks": len(report_data.attacks),
            "successful_attacks": successful,
            "failed_attacks": failed,
            "handshakes_captured": len(report_data.handshakes),
            "credentials_found": len(report_data.credentials),
            "success_rate": (
                f"{(successful / len(report_data.attacks) * 100):.1f}%"
                if report_data.attacks
                else "N/A"
            ),
        }

    @staticmethod
    def _format_duration(seconds: float) -> str:
        if seconds <= 0:
            return "0s"
        hours = int(seconds // 3600)
        minutes = int((seconds % 3600) // 60)
        secs = seconds % 60
        parts: list[str] = []
        if hours > 0:
            parts.append(f"{hours}h")
        if minutes > 0:
            parts.append(f"{minutes}m")
        if secs > 0 or not parts:
            parts.append(f"{secs:.1f}s")
        return " ".join(parts)

    @staticmethod
    def _get_hostname() -> str:
        import socket
        try:
            return socket.gethostname()
        except OSError:
            return "unknown"

    @staticmethod
    def _get_version() -> str:
        try:
            from wafford.version import VERSION
            return VERSION
        except ImportError:
            return "unknown"
