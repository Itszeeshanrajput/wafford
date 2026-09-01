# ruff: noqa: SLF001
from __future__ import annotations

from typing import TYPE_CHECKING, Any, cast

from textual import on, work
from textual.containers import Horizontal, Vertical
from textual.screen import Screen
from textual.widgets import Button, DataTable, Static

from wafford.tools.updater import ToolUpdater
from wafford.ui.widgets.progress import WaffordProgressBar
from wafford.version import VERSION

if TYPE_CHECKING:
    from textual.app import ComposeResult

    from wafford.ui.app import WaffordApp


class UpdateMenu(Screen[None]):
    CSS = """
    UpdateMenu {
        background: $background;
    }
    #up-layout {
        width: 100%;
        height: 100%;
        padding: 1 2;
    }
    #up-header {
        width: 100%;
        height: 3;
        color: $primary;
        text-style: bold;
        text-align: center;
        margin-bottom: 1;
    }
    #up-current {
        width: 100%;
        height: auto;
        padding: 1 2;
        border: solid $accent;
        background: $surface;
        margin-bottom: 1;
    }
    .up-info {
        width: 100%;
        height: 1;
        color: $text;
    }
    #up-buttons {
        width: 100%;
        height: 3;
        layout: horizontal;
        margin-bottom: 1;
    }
    #up-buttons Button {
        margin-right: 1;
        min-width: 14;
    }
    #up-changelog {
        width: 100%;
        height: auto;
        min-height: 6;
        padding: 1 2;
        border: solid $muted;
        background: $surface;
        margin-bottom: 1;
        color: $text;
    }
    #up-history {
        width: 100%;
        height: 1fr;
    }
    #up-progress {
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
        self._updater = ToolUpdater()
        self._update_available = False
        self._latest: str | None = None

    def compose(self) -> ComposeResult:
        with Vertical(id="up-layout"):
            yield Static("🔄  Update Manager", id="up-header")
            with Vertical(id="up-current"):
                yield Static("", id="up-cur")
                yield Static("", id="up-latest")
                yield Static("", id="up-status")
            with Horizontal(id="up-buttons"):
                yield Button("🔍  Check for Updates", id="check-btn", variant="primary")
                yield Button("⬇  Update Now", id="update-btn", variant="success")
                yield Button("←  Back", id="back-btn", variant="default")
            with Vertical(id="up-changelog"):
                yield Static(
                    "  Changelog:\n  Run 'Check for Updates' to fetch release notes.",
                    id="up-changelog-text",
                )
            dt: DataTable[Any] = DataTable(id="up-history")
            dt.add_columns("Version", "Date", "Size", "Notes")
            yield dt
            yield WaffordProgressBar(label="Idle", id="up-progress")

    def on_mount(self) -> None:
        self.query_one("#up-cur", Static).update(f"  Current Version: {VERSION}")
        self.query_one("#up-latest", Static).update("  Latest Version: —")
        self.query_one("#up-status", Static).update("  Status: Unknown")

    @on(Button.Pressed, "#check-btn")
    def on_check(self, _event: Button.Pressed) -> None:
        self.app._notify("Checking for updates...", level="info")
        self.query_one("#up-progress", WaffordProgressBar).set_label("Checking...")
        self.query_one("#up-progress", WaffordProgressBar).set_indeterminate(True)
        self._check_worker()

    @work(thread=True)
    def _check_worker(self) -> None:
        progress = self.query_one("#up-progress", WaffordProgressBar)
        try:
            result = self._updater.check_wafford_update()
        except Exception as exc:
            self.app.call_from_thread(
                progress.set_label, "Check failed"
            )
            self.app.call_from_thread(
                self.app._notify, f"Update check failed: {exc}", "error"
            )
            self.app.call_from_thread(progress.set_indeterminate, False)
            return
        self._update_available = bool(result.get("update_available"))
        self._latest = result.get("latest")
        changelog = result.get("body", "")
        self.app.call_from_thread(progress.set_indeterminate, False)
        if self._latest is None:
            self.app.call_from_thread(
                progress.set_label, "Update check unavailable (offline?)"
            )
            self.app.call_from_thread(
                self.app._notify,
                "Could not reach the update server. Check network access.",
                "warning",
            )
            return
        self.app.call_from_thread(
            self.query_one("#up-latest", Static).update,
            f"  Latest Version: {self._latest}",
        )
        if self._update_available:
            self.app.call_from_thread(
                self.query_one("#up-status", Static).update,
                "  Status: Update Available",
            )
            self.app.call_from_thread(
                progress.set_label, f"Update v{self._latest} available!"
            )
            self.app.call_from_thread(
                self.app._notify, f"Update available: v{self._latest}", "success"
            )
            if changelog:
                self.app.call_from_thread(
                    self.query_one("#up-changelog-text", Static).update,
                    "  Changelog:\n" + self._indent(changelog),
                )
        else:
            self.app.call_from_thread(
                self.query_one("#up-status", Static).update,
                "  Status: Up to date",
            )
            self.app.call_from_thread(
                progress.set_label, "Wafford is up to date!"
            )
            self.app.call_from_thread(
                self.app._notify, "Wafford is up to date", "success"
            )

    @staticmethod
    def _indent(text: str) -> str:
        return "\n".join(f"  - {line}" for line in text.splitlines() if line.strip())

    @on(Button.Pressed, "#update-btn")
    def on_update(self, _event: Button.Pressed) -> None:
        if not self._update_available:
            self.app._notify("No update available to install", level="info")
            return
        self.app._notify("Updating wafford...", level="info")
        self.query_one("#up-progress", WaffordProgressBar).set_label("Updating...")
        self.query_one("#up-progress", WaffordProgressBar).set_indeterminate(True)
        self._update_worker()

    @work(thread=True)
    def _update_worker(self) -> None:
        progress = self.query_one("#up-progress", WaffordProgressBar)
        try:
            ok = self._updater.update_wafford()
        except Exception as exc:
            ok = False
            self.app.call_from_thread(
                self.app._notify, f"Update failed: {exc}", "error"
            )
        self.app.call_from_thread(progress.set_indeterminate, False)
        if ok:
            self.app.call_from_thread(
                progress.set_label, "Update installed!"
            )
            self.app.call_from_thread(
                self.app._notify, "Update complete! Restart required.", "success"
            )
        else:
            self.app.call_from_thread(
                progress.set_label, "Update failed"
            )
            self.app.call_from_thread(
                self.app._notify,
                "Update failed. Run with appropriate privileges and network.",
                "error",
            )

    @on(Button.Pressed, "#back-btn")
    def on_back(self, _event: Button.Pressed) -> None:
        self.action_go_back()

    def action_go_back(self) -> None:
        self.app.pop_screen()
