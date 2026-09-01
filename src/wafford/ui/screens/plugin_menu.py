# ruff: noqa: SLF001
from __future__ import annotations

from typing import TYPE_CHECKING, cast

from textual import on
from textual.containers import Horizontal, Vertical
from textual.screen import Screen
from textual.widgets import Button, DataTable, Static

if TYPE_CHECKING:
    from textual.app import ComposeResult

    from wafford.ui.app import WaffordApp
class PluginMenu(Screen):
    CSS = """
    PluginMenu {
        background: $background;
    }
    #pl-layout {
        width: 100%;
        height: 100%;
        padding: 1 2;
    }
    #pl-header {
        width: 100%;
        height: 3;
        color: $primary;
        text-style: bold;
        text-align: center;
        margin-bottom: 1;
    }
    #pl-buttons {
        width: 100%;
        height: 3;
        layout: horizontal;
        margin-bottom: 1;
    }
    #pl-buttons Button {
        margin-right: 1;
        min-width: 14;
    }
    #pl-table {
        width: 100%;
        height: 1fr;
    }
    #pl-details {
        width: 100%;
        height: auto;
        min-height: 5;
        padding: 1 2;
        border: solid $muted;
        background: $surface;
        margin-top: 1;
        color: $text;
    }
    """

    BINDINGS = [
        ("escape", "go_back", "Back"),
    ]

    @property
    def app(self) -> WaffordApp:  # type: ignore[override]
        return cast("WaffordApp", super().app)

    def __init__(self, **kwargs) -> None:
        super().__init__(**kwargs)
        self._plugins: list[dict] = [
            {"name": "wpa3-analyzer", "version": "1.2.0", "author": "wafford-dev", "status": "enabled", "desc": "Advanced WPA3 SAE handshake analysis"},
            {"name": "auto-recon", "version": "2.0.1", "author": "securitylabs", "status": "enabled", "desc": "Automated reconnaissance module"},
            {"name": "ble-tracker", "version": "0.9.3", "author": "iot-sec", "status": "disabled", "desc": "BLE device tracking and enumeration"},
            {"name": "report-pro", "version": "1.0.0", "author": "wafford-dev", "status": "enabled", "desc": "Professional report templates"},
            {"name": "hashcat-gpu", "version": "3.1.0", "author": "crack-team", "status": "enabled", "desc": "GPU-accelerated cracking support"},
        ]

    def compose(self) -> ComposeResult:
        with Vertical(id="pl-layout"):
            yield Static("🧩  Plugin Manager", id="pl-header")
            with Horizontal(id="pl-buttons"):
                yield Button("📁  Install from File", id="install-btn", variant="success")
                yield Button("⟳  Refresh", id="refresh-btn", variant="default")
                yield Button("←  Back", id="back-btn", variant="default")
            dt = DataTable(id="pl-table")
            dt.add_columns("Name", "Version", "Author", "Status", "Description")
            yield dt
            with Vertical(id="pl-details"):
                yield Static("  Select a plugin to view details", id="detail-text")

    def on_mount(self) -> None:
        self._render_plugins()

    def _render_plugins(self) -> None:
        table = self.query_one("#pl-table", DataTable)
        table.clear()
        for p in self._plugins:
            table.add_row(p["name"], p["version"], p["author"], p["status"], p["desc"], key=p["name"])

    @on(DataTable.RowSelected, "#pl-table")
    def on_plugin_select(self, event: DataTable.RowSelected) -> None:
        if event.row_key:
            name = str(event.row_key.value)
            plugin = next((p for p in self._plugins if p["name"] == name), None)
            if plugin:
                detail = (
                    f"  Name: {plugin['name']}\n"
                    f"  Version: {plugin['version']}\n"
                    f"  Author: {plugin['author']}\n"
                    f"  Status: {plugin['status']}\n"
                    f"  Description: {plugin['desc']}"
                )
                self.query_one("#detail-text", Static).update(detail)

    @on(Button.Pressed, "#install-btn")
    def on_install(self, event: Button.Pressed) -> None:
        self.app._notify("Select plugin file to install...", level="info")

    @on(Button.Pressed, "#refresh-btn")
    def on_refresh(self, event: Button.Pressed) -> None:
        self._render_plugins()
        self.app._notify("Plugins refreshed", level="info")

    @on(Button.Pressed, "#back-btn")
    def on_back(self, event: Button.Pressed) -> None:
        self.action_go_back()

    def action_go_back(self) -> None:
        self.app.pop_screen()
