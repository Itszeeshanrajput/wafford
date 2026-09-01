"""Built-in plugin — Automatically generate and export audit reports."""

from __future__ import annotations

import csv
import io
import json
import logging
import threading
from dataclasses import dataclass
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

from wafford.plugins.api import (
    PluginBase,
    PluginContext,
    register_hook,
)

logger = logging.getLogger(__name__)


@dataclass
class ReportSection:
    title: str
    rows: list[dict[str, Any]] | None = None
    summary: str = ""


# ---------------------------------------------------------------------------
# Report builders / exporters
# ---------------------------------------------------------------------------

class ReportExporterBase:
    ext = ""
    mime = "application/octet-stream"

    def build(self, report: dict[str, Any]) -> bytes:
        raise NotImplementedError

    @staticmethod
    def render_markdown_body(report: dict[str, Any]) -> str:
        lines: list[str] = []
        lines.append(f"# {report.get('title', 'Wafford Audit Report')}")
        lines.append(f"**Generated:** {report.get('generated_at', '')}")
        lines.append("")
        lines.append("## Summary")
        lines.append(report.get("summary", ""))
        lines.append("")
        for section in report.get("sections", []):
            lines.append(f"## {section['title']}")
            lines.append("")
            if section.get("summary"):
                lines.append(f"{section['summary']}")
                lines.append("")
            for row in section.get("rows", []):
                rendered = ", ".join(f"{k}: {v}" for k, v in row.items())
                lines.append(f"- {rendered}")
            lines.append("")
        return "\n".join(lines)


class MarkdownExporter(ReportExporterBase):
    ext = ".md"
    mime = "text/markdown"

    def build(self, report: dict[str, Any]) -> bytes:
        return self.render_markdown_body(report).encode("utf-8")


class JSONExporter(ReportExporterBase):
    ext = ".json"
    mime = "application/json"

    def build(self, report: dict[str, Any]) -> bytes:
        return json.dumps(report, indent=2, default=str).encode("utf-8")


class CSVExporter(ReportExporterBase):
    ext = ".csv"
    mime = "text/csv"

    def build(self, report: dict[str, Any]) -> bytes:
        buf = io.StringIO()
        writer = csv.writer(buf)
        writer.writerow(["section", "field", "value"])
        for section in report.get("sections", []):
            for row in section.get("rows", []):
                for key, value in row.items():
                    writer.writerow([section["title"], key, value])
            if section.get("summary"):
                writer.writerow([section["title"], "summary", section["summary"]])
        return buf.getvalue().encode("utf-8")


class HTMLExporter(ReportExporterBase):
    ext = ".html"
    mime = "text/html"

    def build(self, report: dict[str, Any]) -> bytes:
        body_lines: list[str] = []
        for section in report.get("sections", []):
            body_lines.append(f"<h2>{section['title']}</h2>")
            if section.get("summary"):
                body_lines.append(f"<p>{section['summary']}</p>")
            rows = section.get("rows", [])
            if rows:
                keys = list(rows[0].keys())
                body_lines.append("<table><thead><tr>")
                body_lines.extend(f"<th>{k}</th>" for k in keys)
                body_lines.append("</tr></thead><tbody>")
                for row in rows:
                    body_lines.append("<tr>")
                    body_lines.extend(
                        f"<td>{row.get(k, '')}</td>" for k in keys
                    )
                    body_lines.append("</tr>")
                body_lines.append("</tbody></table>")
        html = f"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="utf-8">
<title>{report.get('title', 'Report')}</title>
<style>
body{{font-family:system-ui,sans-serif;margin:2rem;color:#222}}
h1{{border-bottom:2px solid #2c3e50;padding-bottom:.5rem}}
table{{border-collapse:collapse;width:100%;margin:.5rem 0}}
td,th{{border:1px solid #ccc;padding:.4rem;text-align:left}}
th{{background:#2c3e50;color:#fff}}
</style>
</head>
<body>
<h1>{report.get('title', 'Report')}</h1>
<p><em>Generated: {report.get('generated_at', '')}</em></p>
<p><strong>Summary:</strong> {report.get('summary', '')}</p>
{''.join(body_lines)}
</body>
</html>"""
        return html.encode("utf-8")


EXPORTERS: dict[str, ReportExporterBase] = {
    "md": MarkdownExporter(),
    "markdown": MarkdownExporter(),
    "json": JSONExporter(),
    "csv": CSVExporter(),
    "html": HTMLExporter(),
}


# ---------------------------------------------------------------------------
# Main plugin
# ---------------------------------------------------------------------------

class AutoReportPlugin(PluginBase):
    name = "auto_report"
    version = "1.0.0"
    author = "Wafford Core"
    description = "Automatically build and export structured audit reports"
    min_wafford_version = "0.1.0"

    def __init__(self) -> None:
        super().__init__()
        self._data_store: dict[str, list[dict[str, Any]]] = {}
        self._report_dir = ""
        self._watch_events = ["scan_result", "crack_result", "attack_result"]
        self._lock = threading.Lock()

    def on_load(self, context: PluginContext) -> None:
        super().on_load(context)
        self._report_dir = context.config.get(
            "auto_report_dir",
            str(Path.home() / ".wafford" / "reports"),
        )
        Path(self._report_dir).mkdir(parents=True, exist_ok=True)
        context.info("Auto Report loaded (dir=%s)", self._report_dir)

    def on_enable(self) -> None:
        super().on_enable()

    def on_disable(self) -> None:
        super().on_disable()

    # -- event hooks --------------------------------------------------------

    @register_hook("scan_result", priority=50)
    def _on_scan_result(self, result: dict[str, Any]) -> None:
        with self._lock:
            self._record("networks", result)

    @register_hook("crack_result", priority=50)
    def _on_crack_result(self, result: dict[str, Any]) -> None:
        with self._lock:
            self._record("cracked", result)
        self.generate()

    @register_hook("attack_result", priority=50)
    def _on_attack_result(self, result: dict[str, Any]) -> None:
        with self._lock:
            self._record("attacks", result)

    def _record(self, section: str, data: dict[str, Any]) -> None:
        self._data_store.setdefault(section, [])
        data = dict(data)
        data.setdefault("timestamp", datetime.now(UTC).isoformat())
        self._data_store[section].append(data)

    # -- report generation --------------------------------------------------

    def generate(self, **options: Any) -> dict[str, Any]:
        """Build the report data structure."""
        with self._lock:
            networks = list(self._data_store.get("networks", []))
            cracked = list(self._data_store.get("cracked", []))
            attacks = list(self._data_store.get("attacks", []))

        wpa_count = sum(
            1 for n in networks if "wpa" in n.get("encryption", "").lower()
        )
        wep_count = sum(1 for n in networks if "wep" in n.get("encryption", "").lower())
        open_count = sum(1 for n in networks if not n.get("encryption"))
        encrypted_count = len(networks) - open_count

        # Uniquify networks by BSSID
        seen: set = set()
        unique_networks: list[dict[str, Any]] = []
        for n in networks:
            bssid = n.get("bssid", "")
            if bssid and bssid not in seen:
                seen.add(bssid)
                unique_networks.append(n)

        return {
            "title": "Wafford WiFi Audit Report",
            "generated_at": datetime.now(UTC).isoformat(),
            "summary": (
                f"Scanned {len(unique_networks)} unique access points "
                f"({wpa_count} WPA, {wep_count} WEP, {open_count} open, "
                f"{encrypted_count} total encrypted). "
                f"Successfully cracked {len(cracked)} networks. "
                f"Executed {len(attacks)} attacks."
            ),
            "sections": [
                {
                    "title": "Networks Discovered",
                    "summary": f"{len(unique_networks)} unique networks found.",
                    "rows": unique_networks,
                },
                {
                    "title": "Cracked Networks",
                    "summary": (
                        f"{len(cracked)} network(s) cracked. "
                        "Review credentials responsibly and only on authorized targets."
                    ),
                    "rows": cracked,
                },
                {
                    "title": "Attack Log",
                    "summary": f"{len(attacks)} attacks performed.",
                    "rows": attacks,
                },
            ],
        }

    def export(
        self,
        fmt: str = "md",
        filename: str | None = None,
        report: dict[str, Any] | None = None,
    ) -> str:
        """Export the report and return the written file path."""
        report = report or self.generate()
        exporter = EXPORTERS.get(fmt.lower())
        if exporter is None:
            raise ValueError(
                f"Unsupported report format '{fmt}'. "
                f"Supported: {', '.join(sorted(EXPORTERS))}"
            )
        if filename is None:
            timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
            filename = f"wafford_report_{timestamp}{exporter.ext}"
        out_path = Path(self._report_dir) / filename
        out_path.write_bytes(exporter.build(report))
        logger.info("Exported report to %s", out_path)
        return str(out_path)

    def export_all(self, report: dict[str, Any] | None = None) -> dict[str, str]:
        """Export report in every supported format."""
        report = report or self.generate()
        results: dict[str, str] = {}
        for fmt in EXPORTERS:
            try:
                results[fmt] = self.export(fmt, report=report)
            except Exception as exc:
                logger.error("Failed to export %s report: %s", fmt, exc)
        return results

    def export_filename(self, fmt: str, report: dict[str, Any] | None = None) -> str:
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        exporter = EXPORTERS.get(fmt.lower())
        ext = exporter.ext if exporter else ".txt"
        return f"wafford_report_{timestamp}{ext}"
