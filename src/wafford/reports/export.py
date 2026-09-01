"""Report export for the Wafford framework."""

from __future__ import annotations

import logging
import os
import platform
import shutil
import subprocess
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

from wafford.constants import REPORT_DIR
from wafford.reports.generator import ReportData, ReportGenerator

logger = logging.getLogger(__name__)


class ReportExporter:
    """Exports audit reports in various formats."""

    def __init__(self, output_dir: Path | str | None = None) -> None:
        self._output_dir = Path(output_dir) if output_dir else REPORT_DIR
        self._output_dir.mkdir(parents=True, exist_ok=True)
        self._generator = ReportGenerator(self._output_dir)

    @property
    def output_dir(self) -> Path:
        return self._output_dir

    def export_html(
        self,
        report_data: ReportData,
        output_path: Path | str | None = None,
    ) -> Path:
        html = self._generator.build_html(report_data)
        out = self._resolve_output(output_path, "html")
        out.write_text(html, encoding="utf-8")
        logger.info("HTML report exported to %s", out)
        return out

    def export_pdf(
        self,
        report_data: ReportData,
        output_path: Path | str | None = None,
    ) -> Path:
        try:
            import weasyprint

            html = self._generator.build_html(report_data, template="pdf_report.html.j2")
            out = self._resolve_output(output_path, "pdf")
            weasyprint.HTML(string=html).write_pdf(str(out))
            logger.info("PDF report exported to %s", out)
            return out
        except ImportError:
            logger.warning("weasyprint not installed, exporting as HTML instead")
            return self.export_html(report_data, output_path)
        except Exception as exc:
            logger.error("PDF export failed: %s, falling back to HTML", exc)
            return self.export_html(report_data, output_path)

    def export_json(
        self,
        report_data: ReportData,
        output_path: Path | str | None = None,
    ) -> Path:
        json_str = self._generator.build_json(report_data)
        out = self._resolve_output(output_path, "json")
        out.write_text(json_str, encoding="utf-8")
        logger.info("JSON report exported to %s", out)
        return out

    def export_markdown(
        self,
        report_data: ReportData,
        output_path: Path | str | None = None,
    ) -> Path:
        md = self._generator.build_markdown(report_data)
        out = self._resolve_output(output_path, "md")
        out.write_text(md, encoding="utf-8")
        logger.info("Markdown report exported to %s", out)
        return out

    def export(
        self,
        report_data: ReportData,
        fmt: str = "html",
        output_path: Path | str | None = None,
    ) -> Path:
        exporters: dict[str, Any] = {
            "html": self.export_html,
            "pdf": self.export_pdf,
            "json": self.export_json,
            "markdown": self.export_markdown,
            "md": self.export_markdown,
        }

        exporter = exporters.get(fmt.lower())
        if not exporter:
            raise ValueError(
                f"Unsupported format: '{fmt}'. Supported: {', '.join(exporters.keys())}"
            )

        return exporter(report_data, output_path)

    @staticmethod
    def open_report(path: Path | str) -> bool:
        p = Path(path)
        if not p.exists():
            logger.error("Report file not found: %s", p)
            return False

        system = platform.system()
        try:
            if system == "Linux":
                subprocess.Popen(
                    ["xdg-open", str(p)],
                    stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
                )
            elif system == "Darwin":
                subprocess.Popen(
                    ["open", str(p)],
                    stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
                )
            elif system == "Windows":
                os.startfile(str(p))  # noqa: S606
            else:
                logger.warning("Cannot auto-open reports on %s", system)
                return False
            logger.info("Opened report: %s", p)
            return True
        except OSError as exc:
            logger.error("Failed to open report: %s", exc)
            return False

    @staticmethod
    def share_report(path: Path | str, method: str = "file") -> bool:
        p = Path(path)
        if not p.exists():
            logger.error("Report file not found: %s", p)
            return False

        if method == "file":
            dest = Path.home() / "Desktop" / p.name
            try:
                shutil.copy2(p, dest)
                logger.info("Report copied to %s", dest)
                return True
            except OSError as exc:
                logger.error("Failed to copy report: %s", exc)
                return False

        elif method == "email":
            logger.info("Email sharing not configured. Report at: %s", p)
            return False

        else:
            logger.warning("Unknown share method: '%s'", method)
            return False

    def _resolve_output(self, path: Path | str | None, extension: str) -> Path:
        if path:
            p = Path(path)
            p.parent.mkdir(parents=True, exist_ok=True)
            return p

        timestamp = datetime.now(UTC).strftime("%Y%m%d_%H%M%S")
        return self._output_dir / f"report_{timestamp}.{extension}"

    def list_reports(self) -> list[dict[str, Any]]:
        reports: list[dict[str, Any]] = []
        if not self._output_dir.exists():
            return reports

        for path in sorted(self._output_dir.iterdir()):
            if path.is_file() and path.suffix in (".html", ".pdf", ".json", ".md", ".csv", ".txt"):
                stat = path.stat()
                reports.append({
                    "name": path.name,
                    "path": str(path),
                    "format": path.suffix.lstrip("."),
                    "size": stat.st_size,
                    "created": datetime.fromtimestamp(stat.st_ctime, UTC).isoformat(),
                })

        return reports

    def delete_report(self, path: Path | str) -> bool:
        p = Path(path)
        if not p.exists():
            return False
        try:
            p.unlink()
            logger.info("Deleted report: %s", p)
            return True
        except OSError as exc:
            logger.error("Failed to delete report: %s", exc)
            return False
