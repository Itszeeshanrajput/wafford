"""Karma / MANA Attack Screen for Wafford with Real Core Engine."""

from __future__ import annotations

import asyncio
from typing import TYPE_CHECKING, Any

from textual.containers import Horizontal, Vertical
from textual.screen import Screen
from textual.widgets import Button, DataTable, Header, Input, Static

from wafford.core.karma import KarmaAttack
from wafford.ui.widgets.mode_guard import ModeGuard
from wafford.ui.widgets.status_bar import StatusBar
from wafford.ui.widgets.terminal_log import TerminalLog

if TYPE_CHECKING:
    from textual.app import ComposeResult


class KarmaMenu(Screen[None]):
    """Karma / MANA Probe Sniffing & Dynamic Rogue AP Screen."""

    CSS = """
    KarmaMenu {
        background: $background;
    }
    #km-layout {
        width: 100%;
        height: 1fr;
        padding: 1 2;
    }
    #km-config-card {
        height: auto;
        margin-bottom: 1;
        padding: 1;
        background: $surface;
        border: round $primary;
    }
    .km-row {
        height: 3;
        margin-bottom: 1;
        layout: horizontal;
    }
    .km-input {
        width: 1fr;
        margin-right: 1;
    }
    #km-buttons {
        height: 3;
        layout: horizontal;
    }
    #km-buttons Button {
        margin-right: 1;
    }
    #km-split {
        height: 1fr;
        layout: horizontal;
    }
    #km-left {
        width: 50%;
        height: 100%;
        margin-right: 1;
    }
    #km-right {
        width: 50%;
        height: 100%;
    }
    #km-probe-table {
        height: 1fr;
        background: $surface;
    }
    """

    BINDINGS = [
        ("escape", "go_back", "Back"),
    ]

    def __init__(self, **kwargs: Any) -> None:
        super().__init__(**kwargs)
        self._karma: KarmaAttack | None = None
        self._attack_task: asyncio.Task[Any] | None = None

    def compose(self) -> ComposeResult:
        yield Header(show_clock=True)
        with Vertical(id="km-layout"):
            with Vertical(id="km-config-card"):
                Static("🌀 Karma / MANA Dynamic Rogue AP", classes="menu-title")
                yield ModeGuard(required="monitor", id="karma_menu-mode-guard")
                with Horizontal(classes="km-row"):
                    yield Input(placeholder="SSID Override (Blank to auto-respond to probes)", id="km-ssid", classes="km-input")
                    yield Input(placeholder="Channel", id="km-channel", value="1", classes="km-input")

                with Horizontal(id="km-buttons"):
                    yield Button("▶ Start Karma Sniffer & AP", id="btn-km-start", variant="success")
                    yield Button("⏹ Stop", id="btn-km-stop", variant="error", disabled=True)
                    yield Button("← Back", id="btn-km-back", variant="default")

            with Horizontal(id="km-split"):
                with Vertical(id="km-left"):
                    Static("📡 Intercepted Probe Requests", classes="panel-title")
                    yield DataTable(id="km-probe-table", zebra_stripes=True)
                with Vertical(id="km-right"):
                    yield TerminalLog(id="km-terminal")

        yield StatusBar(id="status-bar")

    def on_mount(self) -> None:
        table = self.query_one("#km-probe-table", DataTable)
        table.cursor_type = "row"
        table.add_columns("Client MAC", "Requested SSID", "Signal")

    async def on_button_pressed(self, event: Button.Pressed) -> None:
        bid = event.button.id
        if bid == "btn-km-start":
            await self._start_karma()
        elif bid == "btn-km-stop":
            await self._stop_karma()
        elif bid == "btn-km-back":
            self.action_go_back()

    async def _start_karma(self) -> None:
        ssid = self.query_one("#km-ssid", Input).value.strip()
        ch_str = self.query_one("#km-channel", Input).value.strip()
        term = self.query_one("#km-terminal", TerminalLog)

        try:
            channel = int(ch_str)
        except ValueError:
            channel = 1

        iface = getattr(self.app, "selected_interface", "wlan0mon") or "wlan0mon"
        term.write_line(f"[bold cyan]Starting Karma attack on {iface} (Channel {channel})...[/]")

        self.query_one("#btn-km-start", Button).disabled = True
        self.query_one("#btn-km-stop", Button).disabled = False

        self._karma = KarmaAttack(interface=iface)
        self._karma.on("karma.probe_seen", self._on_probe_seen)

        self._attack_task = asyncio.create_task(self._karma.start(ssid=ssid, channel=channel))
        term.write_line("[bold green]✓ Karma sniffer listening for probe requests...[/]")

    def _on_probe_seen(self, evt: Any) -> None:
        data = evt.data
        mac = data.get("client_mac", "")
        ssid = data.get("ssid", "")
        rssi = data.get("rssi", -50)
        table = self.query_one("#km-probe-table", DataTable)
        table.add_row(mac, ssid, f"{rssi} dBm")
        term = self.query_one("#km-terminal", TerminalLog)
        term.write_line(f"[bold yellow]Intercepted probe: {mac} searching for '{ssid}'[/]")

    async def _stop_karma(self) -> None:
        if self._karma:
            await self._karma.stop()
        if self._attack_task and not self._attack_task.done():
            self._attack_task.cancel()
        self.query_one("#btn-km-start", Button).disabled = False
        self.query_one("#btn-km-stop", Button).disabled = True
        self.query_one("#km-terminal", TerminalLog).write_line("[bold red]Karma attack stopped.[/]")

    def action_go_back(self) -> None:
        self.app.pop_screen()
