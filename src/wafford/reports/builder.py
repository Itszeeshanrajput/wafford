"""Report generation for Wafford."""

from __future__ import annotations

import json
import logging
from datetime import datetime
from pathlib import Path
from typing import Any

from wafford.constants import REPORT_DIR
from wafford.exceptions import ReportError

logger = logging.getLogger(__name__)


class ReportBuilder:
    """Base class for report builders."""

    def __init__(self, output_dir: Path | str | None = None) -> None:
        """Initialize report builder.

        Args:
            output_dir: Directory for report output. Defaults to REPORT_DIR.
        """
        self.output_dir = Path(output_dir or REPORT_DIR)
        self.output_dir.mkdir(parents=True, exist_ok=True)
        self.data: dict[str, Any] = {}
        self.generated_at = datetime.now().isoformat()

    def add_data(self, key: str, value: Any) -> None:
        """Add data to report.

        Args:
            key: Data key.
            value: Data value.
        """
        self.data[key] = value

    def generate(self) -> Path:
        """Generate report (to be implemented by subclasses).

        Returns:
            Path to generated report.
        """
        raise NotImplementedError


class JSONReportBuilder(ReportBuilder):
    """JSON report builder."""

    def generate(self) -> Path:
        """Generate JSON report.

        Returns:
            Path to JSON report file.

        Raises:
            ReportError: If report generation fails.
        """
        try:
            report_data = {
                "generated_at": self.generated_at,
                "data": self.data,
            }
            timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
            report_path = self.output_dir / f"wafford_report_{timestamp}.json"
            report_path.write_text(json.dumps(report_data, indent=2))
            logger.info("Generated JSON report: %s", report_path)
            return report_path
        except Exception as exc:
            raise ReportError(f"JSON report generation failed: {exc}") from exc


class HTMLReportBuilder(ReportBuilder):
    """HTML report builder."""

    def generate(self) -> Path:
        """Generate HTML report.

        Returns:
            Path to HTML report file.

        Raises:
            ReportError: If report generation fails.
        """
        try:
            html_content = f"""
            <!DOCTYPE html>
            <html>
            <head>
                <title>Wafford Audit Report</title>
                <style>
                    body {{ font-family: Arial, sans-serif; margin: 20px; }}
                    h1 {{ color: #333; }}
                    .timestamp {{ color: #666; font-size: 0.9em; }}
                    .data {{ background: #f5f5f5; padding: 10px; border-radius: 5px; }}
                </style>
            </head>
            <body>
                <h1>Wafford WiFi Audit Report</h1>
                <div class="timestamp">Generated: {self.generated_at}</div>
                <div class="data">
                    <pre>{json.dumps(self.data, indent=2)}</pre>
                </div>
            </body>
            </html>
            """
            timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
            report_path = self.output_dir / f"wafford_report_{timestamp}.html"
            report_path.write_text(html_content)
            logger.info("Generated HTML report: %s", report_path)
            return report_path
        except Exception as exc:
            raise ReportError(f"HTML report generation failed: {exc}") from exc
