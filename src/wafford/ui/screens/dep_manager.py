# ruff: noqa: SLF001
from __future__ import annotations

from typing import TYPE_CHECKING, Any, cast

from textual import on, work
from textual.containers import Horizontal, Vertical
from textual.screen import Screen
from textual.widgets import Button, DataTable, Static

from wafford.tools.detector import ToolDetector
from wafford.tools.installer import DependencyInstaller
from wafford.ui.widgets.progress import WaffordProgressBar

if TYPE_CHECKING:
    from textual.app import ComposeResult

    from wafford.ui.app import WaffordApp


class DepManager(Screen[None]):
    CSS = """
    DepManager {
        background: $background;
    }
    #dm-layout {
        width: 100%;
        height: 100%;
        padding: 1 2;
    }
    #dm-header {
        width: 100%;
        height: 3;
        color: $primary;
        text-style: bold;
        text-align: center;
        margin-bottom: 1;
    }
    #dm-buttons {
        width: 100%;
        height: 3;
        layout: horizontal;
        margin-bottom: 1;
    }
    #dm-buttons Button {
        margin-right: 1;
        min-width: 14;
    }
    #dm-table {
        width: 100%;
        height: 1fr;
    }
    #dm-progress {
        width: 100%;
        height: 3;
        margin-top: 1;
    }
    #dm-status {
        width: 100%;
        height: 1;
        color: $muted;
        text-align: right;
    }
    """

    BINDINGS = [
        ("escape", "go_back", "Back"),
        ("r", "rescan", "Re-scan"),
    ]

    @property
    def app(self) -> WaffordApp:  # type: ignore[override]
        return cast("WaffordApp", super().app)

    def __init__(self) -> None:
        super().__init__()
        self._detector = ToolDetector()
        self._installer = DependencyInstaller(progress_callback=self._progress_callback)
        self._tools: list[dict[str, Any]] = []

    def compose(self) -> ComposeResult:
        with Vertical(id="dm-layout"):
            yield Static("📦  Dependency Manager", id="dm-header")
            with Horizontal(id="dm-buttons"):
                yield Button("🔧  Auto-Install Missing", id="install-btn", variant="success")
                yield Button("⟳  Re-scan", id="rescan-btn", variant="primary")
                yield Button("←  Back", id="back-btn", variant="default")
            dt: DataTable[Any] = DataTable(id="dm-table")
            dt.add_columns("Name", "Required", "Status", "Version", "Path")
            yield dt
            yield Static("Scanning...", id="dm-status")
            yield WaffordProgressBar(label="Idle", id="dm-progress")

    def on_mount(self) -> None:
        self._scan()

    def _scan(self) -> None:
        self._detect_worker()

    @work(thread=True)
    def _detect_worker(self) -> None:
        try:
            status = self._detector.detect_all()
        except Exception:
            status = {}
        entries: list[dict[str, Any]] = []
        for name, meta in status.items():
            entries.append({
                "name": name,
                "required": bool(meta.get("required")),
                "status": "Found" if meta.get("found") else "Missing",
                "version": meta.get("version") or "-",
                "path": meta.get("path") if meta.get("found") else "-",
            })
        if not entries:
            entries.append({
                "name": "(no tools detected)",
                "required": False,
                "status": "Unknown",
                "version": "-",
                "path": "-",
            })
        self.app.call_from_thread(self._set_tools, entries)

    def _set_tools(self, tools: list[dict[str, Any]]) -> None:
        self._tools = tools
        self._render_tools()

    def _render_tools(self) -> None:
        table = self.query_one("#dm-table", DataTable)
        table.clear()
        found = 0
        for t in self._tools:
            if t["status"] == "Found":
                found += 1
            table.add_row(
                t["name"],
                "Yes" if t["required"] else "No",
                t["status"],
                t["version"],
                t["path"],
                key=t["name"],
            )
        total = len(self._tools)
        self.query_one("#dm-status", Static).update(f"{found}/{total} tools found")

    @on(Button.Pressed, "#install-btn")
    def on_install(self, _event: Button.Pressed) -> None:
        self._install_worker()

    @work(thread=True)
    def _install_worker(self) -> None:
        progress = self.query_one("#dm-progress", WaffordProgressBar)
        self.app.call_from_thread(progress.set_label, "Installing missing tools...")
        self.app.call_from_thread(progress.reset)
        try:
            results = self._installer.install_all_missing()
        except Exception as exc:
            self.app.call_from_thread(
                progress.set_label, f"Install failed: {exc}"
            )
            self.app.call_from_thread(self.app._notify, f"Install failed: {exc}", "error")
            return
        self.app.call_from_thread(progress.update_progress, 100, 100)
        self.app.call_from_thread(progress.set_label, "Installation finished")
        if not results:
            self.app.call_from_thread(
                self.app._notify, "All dependencies are installed!", "success"
            )
        else:
            installed = sum(1 for ok in results.values() if ok)
            self.app.call_from_thread(
                self.app._notify,
                f"Installed {installed}/{len(results)} missing tools",
                "success" if installed else "warning",
            )
        self.app.call_from_thread(self._scan)

    def _progress_callback(self, _name: str, fraction: float, _message: str) -> None:
        progress = self.query_one("#dm-progress", WaffordProgressBar)
        self.app.call_from_thread(progress.update_progress, fraction * 100, 100)

    @on(Button.Pressed, "#rescan-btn")
    def on_rescan(self, _event: Button.Pressed) -> None:
        self.app._notify("Re-scanning dependencies...", level="info")
        self._scan()

    @on(Button.Pressed, "#back-btn")
    def on_back(self, _event: Button.Pressed) -> None:
        self.action_go_back()

    def action_go_back(self) -> None:
        self.app.pop_screen()

    def action_rescan(self) -> None:
        self.on_rescan(None)  # type: ignore[arg-type]
