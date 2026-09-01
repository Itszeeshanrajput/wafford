# ruff: noqa: SLF001
from __future__ import annotations

from typing import TYPE_CHECKING, Any, cast

from textual import on, work
from textual.containers import Horizontal, Vertical
from textual.screen import Screen
from textual.widgets import Button, DataTable, Label, Select, Static

from wafford.reports.export import ReportExporter
from wafford.reports.generator import ReportData
from wafford.ui.widgets.progress import WaffordProgressBar

if TYPE_CHECKING:
    from textual.app import ComposeResult

    from wafford.ui.app import WaffordApp

FORMAT_LABEL = {"html": "HTML", "pdf": "PDF", "json": "JSON", "md": "Markdown"}


class ReportMenu(Screen[None]):
    CSS = """
    ReportMenu {
        background: $background;
    }
    #rp-layout {
        width: 100%;
        height: 100%;
        padding: 1 2;
    }
    #rp-header {
        width: 100%;
        height: 3;
        color: $primary;
        text-style: bold;
        text-align: center;
        margin-bottom: 1;
    }
    #rp-summary {
        width: 100%;
        height: auto;
        padding: 1 2;
        border: solid $accent;
        background: $surface;
        margin-bottom: 1;
    }
    .rp-sum-line {
        width: 100%;
        height: 1;
        color: $text;
    }
    #rp-config {
        width: 100%;
        height: auto;
        layout: horizontal;
        margin-bottom: 1;
    }
    .rp-cfg-field {
        margin-right: 2;
    }
    .rp-cfg-label {
        color: $muted;
        height: 1;
    }
    #rp-buttons {
        width: 100%;
        height: 3;
        layout: horizontal;
        margin-bottom: 1;
    }
    #rp-buttons Button {
        margin-right: 1;
        min-width: 14;
    }
    #rp-history {
        width: 100%;
        height: 1fr;
    }
    #rp-progress {
        width: 100%;
        height: 3;
    }
    """

    BINDINGS = [
        ("escape", "go_back", "Back"),
    ]

    @property
    def app(self) -> WaffordApp:  # type: ignore[override]
        return cast("WaffordApp", super().app)

    def __init__(self) -> None:
        super().__init__()
        self._exporter = ReportExporter()
        self._reports: list[dict[str, Any]] = []

    def compose(self) -> ComposeResult:
        with Vertical(id="rp-layout"):
            yield Static("📊  Report Generator", id="rp-header")
            with Vertical(id="rp-summary"):
                yield Static("  Session Summary:", classes="rp-sum-line")
                yield Static(
                    "  Select a format and generate a report from the current session.",
                    classes="rp-sum-line",
                )
            with Horizontal(id="rp-config"):
                with Vertical(classes="rp-cfg-field"):
                    yield Label("Format", classes="rp-cfg-label")
                    yield Select(
                        [("HTML", "html"), ("PDF", "pdf"), ("JSON", "json"), ("Markdown", "md")],
                        value="html",
                        id="rp-format",
                    )
                with Vertical(classes="rp-cfg-field"):
                    yield Label("Template", classes="rp-cfg-label")
                    yield Select(
                        [
                            ("Standard", "standard"),
                            ("Detailed", "detailed"),
                            ("Executive", "executive"),
                        ],
                        value="standard",
                        id="rp-template",
                    )
            with Horizontal(id="rp-buttons"):
                yield Button("📄  Generate Report", id="gen-btn", variant="success")
                yield Button("📂  Open Report", id="open-btn", variant="default")
                yield Button("←  Back", id="back-btn", variant="default")
            dt: DataTable[Any] = DataTable(id="rp-history")
            dt.add_columns("Date", "Format", "Path")
            yield dt
            yield WaffordProgressBar(label="Idle", id="rp-progress")

    def _refresh_reports(self) -> None:
        try:
            self._reports = self._exporter.list_reports()
        except Exception:
            self._reports = []
        table = self.query_one("#rp-history", DataTable)
        table.clear()
        for r in self._reports:
            table.add_row(r.get("created", "")[:19], r.get("format", ""), r.get("name", ""))

    def on_mount(self) -> None:
        self._refresh_reports()

    @on(Button.Pressed, "#gen-btn")
    def on_generate(self, _event: Button.Pressed) -> None:
        fmt = str(self.query_one("#rp-format", Select).value)
        self.query_one("#rp-progress", WaffordProgressBar).set_label("Generating report...")
        self.query_one("#rp-progress", WaffordProgressBar).reset()
        self.app._notify(f"Generating {FORMAT_LABEL.get(fmt, fmt)} report...", level="info")
        self._gen_worker(fmt)

    @work(thread=True)
    def _gen_worker(self, fmt: str) -> None:
        progress = self.query_one("#rp-progress", WaffordProgressBar)
        data = ReportData(session={"id": "current-session"})
        try:
            out = self._exporter.export(data, fmt=fmt)
        except Exception as exc:
            self.app.call_from_thread(
                progress.set_label, "Report generation failed"
            )
            self.app.call_from_thread(
                self.app._notify, f"Report generation failed: {exc}", "error"
            )
            return
        self.app.call_from_thread(progress.update_progress, 100, 100)
        self.app.call_from_thread(progress.set_label, "Report generated!")
        self.app.call_from_thread(
            self.app._notify, f"Report generated: {out.name}", "success"
        )
        self.app.call_from_thread(self._refresh_reports)

    @on(Button.Pressed, "#open-btn")
    def on_open(self, _event: Button.Pressed) -> None:
        if not self._reports:
            self.app._notify("No reports to open. Generate one first.", level="info")
            return
        latest = self._reports[-1]
        path = latest.get("path")
        if not path:
            self.app._notify("Report path missing", level="error")
            return
        try:
            ok = self._exporter.open_report(str(path))
        except Exception:
            ok = False
        self.app._notify(
            "Opened report in browser" if ok else "Failed to open report",
            level="success" if ok else "error",
        )

    @on(Button.Pressed, "#back-btn")
    def on_back(self, _event: Button.Pressed) -> None:
        self.action_go_back()

    def action_go_back(self) -> None:
        self.app.pop_screen()
