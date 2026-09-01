"""Evil Twin Rogue AP Screen for Wafford with Real Core Engine."""

from __future__ import annotations

import asyncio
from typing import TYPE_CHECKING, Any

from textual.containers import Horizontal, Vertical
from textual.screen import Screen
from textual.widgets import Button, DataTable, Header, Input, Static

from wafford.core.evil_twin import EvilTwin
from wafford.ui.widgets.mode_guard import ModeGuard
from wafford.ui.widgets.status_bar import StatusBar
from wafford.ui.widgets.terminal_log import TerminalLog

if TYPE_CHECKING:
    from textual.app import ComposeResult


class EvilTwinMenu(Screen[None]):
    """Evil Twin Rogue AP Screen with DNS Spoofing & Client Tracker."""

    CSS = """
    EvilTwinMenu {
        background: $background;
    }
    #et-layout {
        width: 100%;
        height: 1fr;
        padding: 1 2;
    }
    #et-config-card {
        height: auto;
        margin-bottom: 1;
        padding: 1;
        background: $surface;
        border: round $primary;
    }
    .et-row {
        height: 3;
        margin-bottom: 1;
        layout: horizontal;
    }
    .et-input {
        width: 1fr;
        margin-right: 1;
    }
    #et-buttons {
        height: 3;
        layout: horizontal;
    }
    #et-buttons Button {
        margin-right: 1;
    }
    #et-split {
        height: 1fr;
        layout: horizontal;
    }
    #et-left {
        width: 50%;
        height: 100%;
        margin-right: 1;
    }
    #et-right {
        width: 50%;
        height: 100%;
    }
    #et-client-table {
        height: 1fr;
        background: $surface;
    }
    """

    BINDINGS = [
        ("escape", "go_back", "Back"),
    ]

    def __init__(self, **kwargs: Any) -> None:
        super().__init__(**kwargs)
        self._evil_twin: EvilTwin | None = None
        self._ap_task: asyncio.Task[Any] | None = None
        self._clients: dict[str, str] = {}

    def compose(self) -> ComposeResult:
        yield Header(show_clock=True)
        with Vertical(id="et-layout"):
            with Vertical(id="et-config-card"):
                Static("👥 Evil Twin Rogue Access Point", classes="menu-title")
                yield ModeGuard(required="monitor", id="evil_twin_menu-mode-guard")
                with Horizontal(classes="et-row"):
                    yield Input(placeholder="SSID to clone", id="et-ssid", value="Target-AP-Clone", classes="et-input")
                    yield Input(placeholder="Operating Channel", id="et-channel", value="6", classes="et-input")
                    yield Input(placeholder="Gateway IP", id="et-gateway", value="192.168.1.1", classes="et-input")

                with Horizontal(id="et-buttons"):
                    yield Button("▶ Start Rogue AP", id="btn-et-start", variant="success")
                    yield Button("⏹ Stop AP", id="btn-et-stop", variant="error", disabled=True)
                    yield Button("← Back", id="btn-et-back", variant="default")

            with Horizontal(id="et-split"):
                with Vertical(id="et-left"):
                    Static("📱 Associated Clients", classes="panel-title")
                    yield DataTable(id="et-client-table", zebra_stripes=True)
                with Vertical(id="et-right"):
                    yield TerminalLog(id="et-terminal")

        yield StatusBar(id="status-bar")

    def on_mount(self) -> None:
        table = self.query_one("#et-client-table", DataTable)
        table.cursor_type = "row"
        table.add_columns("Client MAC", "Assigned IP", "Status")
        if getattr(self.app, "selected_network", None):
            self.query_one("#et-ssid", Input).value = self.app.selected_network.get("essid", "Cloned-AP")
            self.query_one("#et-channel", Input).value = str(self.app.selected_network.get("channel", 6))

    async def on_button_pressed(self, event: Button.Pressed) -> None:
        bid = event.button.id
        if bid == "btn-et-start":
            await self._start_ap()
        elif bid == "btn-et-stop":
            await self._stop_ap()
        elif bid == "btn-et-back":
            self.action_go_back()

    async def _start_ap(self) -> None:
        ssid = self.query_one("#et-ssid", Input).value.strip() or "Cloned-WiFi"
        ch_str = self.query_one("#et-channel", Input).value.strip() or "6"
        gateway = self.query_one("#et-gateway", Input).value.strip() or "192.168.1.1"
        term = self.query_one("#et-terminal", TerminalLog)

        try:
            channel = int(ch_str)
        except ValueError:
            channel = 6

        iface = getattr(self.app, "selected_interface", "wlan0mon") or "wlan0mon"
        term.write_line(f"[bold cyan]Launching Evil Twin '{ssid}' on Channel {channel} using {iface}...[/]")

        self.query_one("#btn-et-start", Button).disabled = True
        self.query_one("#btn-et-stop", Button).disabled = False

        self._evil_twin = EvilTwin(interface=iface)
        self._evil_twin.on("evil_twin.client_joined", self._on_client_joined)

        self._ap_task = asyncio.create_task(
            self._evil_twin.start_ap(ssid=ssid, channel=channel, gateway_ip=gateway)
        )
        term.write_line("[bold green]✓ Hostapd and Dnsmasq spawned successfully! Monitoring client associations...[/]")

    def _on_client_joined(self, evt: Any) -> None:
        mac = evt.data.get("mac", "Unknown")
        ip = evt.data.get("ip", "DHCP Assigned")
        term = self.query_one("#et-terminal", TerminalLog)
        term.write_line(f"[bold green]📱 Client associated: {mac} -> {ip}[/]")
        table = self.query_one("#et-client-table", DataTable)
        table.add_row(mac, ip, "CONNECTED")

    async def _stop_ap(self) -> None:
        if self._evil_twin:
            await self._evil_twin.stop()
        if self._ap_task and not self._ap_task.done():
            self._ap_task.cancel()
        self.query_one("#btn-et-start", Button).disabled = False
        self.query_one("#btn-et-stop", Button).disabled = True
        self.query_one("#et-terminal", TerminalLog).write_line("[bold red]Evil Twin AP stopped and network cleaned up.[/]")

    def action_go_back(self) -> None:
        self.app.pop_screen()
