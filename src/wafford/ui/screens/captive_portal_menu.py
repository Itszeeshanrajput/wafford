"""Captive Portal Screen for Wafford with Real Credential Harvesting Server."""

from __future__ import annotations

import asyncio
from typing import TYPE_CHECKING, Any

from textual.containers import Horizontal, Vertical
from textual.screen import Screen
from textual.widgets import Button, DataTable, Header, Input, Select, Static

from wafford.core.captive_portal import CaptivePortal, CapturedCredential
from wafford.ui.widgets.mode_guard import ModeGuard
from wafford.ui.widgets.status_bar import StatusBar
from wafford.ui.widgets.terminal_log import TerminalLog

if TYPE_CHECKING:
    from textual.app import ComposeResult


class CaptivePortalMenu(Screen[None]):
    """Real Captive Portal HTTP Server & Credential Sniffer Screen."""

    CSS = """
    CaptivePortalMenu {
        background: $background;
    }
    #cp-layout {
        width: 100%;
        height: 1fr;
        padding: 1 2;
    }
    #cp-config-card {
        height: auto;
        margin-bottom: 1;
        padding: 1;
        background: $surface;
        border: round $primary;
    }
    .cp-row {
        height: 3;
        margin-bottom: 1;
        layout: horizontal;
    }
    .cp-input {
        width: 1fr;
        margin-right: 1;
    }
    #cp-buttons {
        height: 3;
        layout: horizontal;
    }
    #cp-buttons Button {
        margin-right: 1;
    }
    #cp-split {
        height: 1fr;
        layout: horizontal;
    }
    #cp-left {
        width: 50%;
        height: 100%;
        margin-right: 1;
    }
    #cp-right {
        width: 50%;
        height: 100%;
    }
    #cp-cred-table {
        height: 1fr;
        background: $surface;
    }
    """

    BINDINGS = [
        ("escape", "go_back", "Back"),
    ]

    def __init__(self, **kwargs: Any) -> None:
        super().__init__(**kwargs)
        self._portal: CaptivePortal | None = None
        self._server_task: asyncio.Task[Any] | None = None
        self._credentials: list[CapturedCredential] = []

    def compose(self) -> ComposeResult:
        yield Header(show_clock=True)
        with Vertical(id="cp-layout"):
            with Vertical(id="cp-config-card"):
                Static("🎣 Captive Portal & Credential Harvester", classes="menu-title")
                yield ModeGuard(required="managed", id="cp-mode-guard")
                with Horizontal(classes="cp-row"):
                    yield Input(placeholder="SSID to clone", id="cp-ssid", value="Free-Airport-WiFi", classes="cp-input")
                    yield Input(placeholder="Listen IP", id="cp-ip", value="192.168.1.1", classes="cp-input")
                    yield Input(placeholder="Port", id="cp-port", value="80", classes="cp-input")
                    yield Select([("Default Login", "default"), ("Router Firmware Update", "firmware"), ("Social Login", "social")], value="default", id="cp-template-select")

                with Horizontal(id="cp-buttons"):
                    yield Button("▶ Start Portal Server", id="btn-cp-start", variant="success")
                    yield Button("⏹ Stop", id="btn-cp-stop", variant="error", disabled=True)
                    yield Button("← Back", id="btn-cp-back", variant="default")

            with Horizontal(id="cp-split"):
                with Vertical(id="cp-left"):
                    Static("📋 Captured Credentials", classes="panel-title")
                    yield DataTable(id="cp-cred-table", zebra_stripes=True)
                with Vertical(id="cp-right"):
                    yield TerminalLog(id="cp-terminal")

        yield StatusBar(id="status-bar")

    def on_mount(self) -> None:
        table = self.query_one("#cp-cred-table", DataTable)
        table.cursor_type = "row"
        table.add_columns("Time", "Client IP", "Username", "Password", "Template")

    async def on_button_pressed(self, event: Button.Pressed) -> None:
        bid = event.button.id
        if bid == "btn-cp-start":
            await self._start_portal()
        elif bid == "btn-cp-stop":
            await self._stop_portal()
        elif bid == "btn-cp-back":
            self.action_go_back()

    async def _start_portal(self) -> None:
        self.query_one("#cp-ssid", Input).value.strip() or "Free-WiFi"
        ip = self.query_one("#cp-ip", Input).value.strip() or "192.168.1.1"
        port_str = self.query_one("#cp-port", Input).value.strip() or "80"
        template = self.query_one("#cp-template-select", Select).value or "default"
        term = self.query_one("#cp-terminal", TerminalLog)

        try:
            port = int(port_str)
        except ValueError:
            port = 80

        iface = getattr(self.app, "selected_interface", "wlan0mon") or "wlan0mon"
        term.write_line(f"[bold cyan]Starting Captive Portal ({template}) on {ip}:{port}...[/]")

        self.query_one("#btn-cp-start", Button).disabled = True
        self.query_one("#btn-cp-stop", Button).disabled = False

        self._portal = CaptivePortal(interface=iface, template=template, listen_ip=ip, port=port)
        self._portal.on("captive_portal.captured", self._on_credential_captured)

        self._server_task = asyncio.create_task(self._portal.start(template=template, port=port, listen_ip=ip))
        term.write_line("[bold green]✓ Portal HTTP server is running and intercepting requests![/]")

    def _on_credential_captured(self, evt: Any) -> None:
        term = self.query_one("#cp-terminal", TerminalLog)
        creds = getattr(self._portal, "captured", [])
        if creds:
            latest = creds[-1]
            self._credentials.append(latest)
            term.write_line(f"[bold green]🎉 CREDENTIAL SNIFFED from {latest.client_ip}: '{latest.username}' / '{latest.password}'[/]")

            table = self.query_one("#cp-cred-table", DataTable)
            table.add_row(latest.timestamp[:19], latest.client_ip, latest.username, latest.password, latest.template)

            if hasattr(self.app, "db_manager") and self.app.db_manager:
                asyncio.create_task(self.app.db_manager.add_credential(
                    bssid=latest.client_ip,
                    essid="CaptivePortal",
                    username=latest.username,
                    password=latest.password,
                    source="captive_portal",
                ))

    async def _stop_portal(self) -> None:
        if self._portal:
            await self._portal.stop()
        if self._server_task and not self._server_task.done():
            self._server_task.cancel()
        self.query_one("#btn-cp-start", Button).disabled = False
        self.query_one("#btn-cp-stop", Button).disabled = True
        self.query_one("#cp-terminal", TerminalLog).write_line("[bold red]Captive Portal stopped.[/]")

    def action_go_back(self) -> None:
        self.app.pop_screen()
