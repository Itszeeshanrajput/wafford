"""Wireless DoS Screen for Wafford with Real Core Engine."""

from __future__ import annotations

import asyncio
from typing import TYPE_CHECKING, Any

from textual.containers import Container, Horizontal, Vertical
from textual.screen import Screen
from textual.widgets import Button, Header, Input, Select, Static

from wafford.core.dos import DoSAttack
from wafford.ui.widgets.mode_guard import ModeGuard
from wafford.ui.widgets.status_bar import StatusBar
from wafford.ui.widgets.terminal_log import TerminalLog

if TYPE_CHECKING:
    from textual.app import ComposeResult


class DoSMenu(Screen[None]):
    """Wireless Denial of Service Flood Attack Screen."""

    CSS = """
    DoSMenu {
        background: $background;
    }
    #dos-layout {
        width: 100%;
        height: 1fr;
        padding: 1 2;
    }
    #dos-config-card {
        height: auto;
        margin-bottom: 1;
        padding: 1;
        background: $surface;
        border: round $primary;
    }
    .dos-row {
        height: 3;
        margin-bottom: 1;
        layout: horizontal;
    }
    .dos-input {
        width: 1fr;
        margin-right: 1;
    }
    #dos-buttons {
        height: 3;
        layout: horizontal;
    }
    #dos-buttons Button {
        margin-right: 1;
    }
    #dos-term-container {
        height: 1fr;
    }
    """

    BINDINGS = [
        ("escape", "go_back", "Back"),
    ]

    def __init__(self, **kwargs: Any) -> None:
        super().__init__(**kwargs)
        self._dos: DoSAttack | None = None
        self._dos_task: asyncio.Task[Any] | None = None

    def compose(self) -> ComposeResult:
        yield Header(show_clock=True)
        with Vertical(id="dos-layout"):
            with Vertical(id="dos-config-card"):
                Static("🌪️ Wireless Denial-of-Service (DoS) Flooding", classes="menu-title")
                yield ModeGuard(required="monitor", id="dos_menu-mode-guard")
                with Horizontal(classes="dos-row"):
                    yield Input(placeholder="Target BSSID (Optional)", id="dos-bssid", classes="dos-input")
                    yield Input(placeholder="Channel", id="dos-channel", value="1", classes="dos-input")
                    yield Select([("Beacon Frame Flood", "beacon"), ("Authentication Flood", "auth"), ("Deauth Flood", "deauth"), ("Association Flood", "assoc"), ("EAPOL Start Flood", "eapol"), ("Null Frame Flood", "null")], value="beacon", id="dos-type-select")

                with Horizontal(id="dos-buttons"):
                    yield Button("▶ Start DoS Flood", id="btn-dos-start", variant="success")
                    yield Button("⏹ Stop Flood", id="btn-dos-stop", variant="error", disabled=True)
                    yield Button("← Back", id="btn-dos-back", variant="default")

            with Container(id="dos-term-container"):
                yield TerminalLog(id="dos-terminal")

        yield StatusBar(id="status-bar")

    def on_mount(self) -> None:
        if getattr(self.app, "selected_network", None):
            self.query_one("#dos-bssid", Input).value = self.app.selected_network.get("bssid", "")
            self.query_one("#dos-channel", Input).value = str(self.app.selected_network.get("channel", 1))

    async def on_button_pressed(self, event: Button.Pressed) -> None:
        bid = event.button.id
        if bid == "btn-dos-start":
            await self._start_dos()
        elif bid == "btn-dos-stop":
            await self._stop_dos()
        elif bid == "btn-dos-back":
            self.action_go_back()

    async def _start_dos(self) -> None:
        bssid = self.query_one("#dos-bssid", Input).value.strip() or "FF:FF:FF:FF:FF:FF"
        ch_str = self.query_one("#dos-channel", Input).value.strip() or "1"
        dos_type = self.query_one("#dos-type-select", Select).value or "beacon"
        term = self.query_one("#dos-terminal", TerminalLog)

        try:
            channel = int(ch_str)
        except ValueError:
            channel = 1

        iface = getattr(self.app, "selected_interface", "wlan0mon") or "wlan0mon"
        term.write_line(f"[bold cyan]Launching {dos_type.upper()} flood on {iface} (Channel {channel})...[/]")

        self.query_one("#btn-dos-start", Button).disabled = True
        self.query_one("#btn-dos-stop", Button).disabled = False

        self._dos = DoSAttack(interface=iface)
        self._dos.on("dos.packet_sent", lambda evt: term.write_line(f"Flooding: {evt.data.get('packets_sent', 0)} frames dispatched"))

        attack_map = {
            "beacon": self._dos.beacon_flood,
            "auth": lambda: self._dos.auth_flood(bssid),
            "deauth": lambda: self._dos.deauth_flood(bssid),
            "assoc": lambda: self._dos.association_flood(bssid),
            "eapol": lambda: self._dos.eapol_flood(bssid),
            "null": lambda: self._dos.null_frame_flood(bssid),
        }
        func = attack_map.get(dos_type, self._dos.beacon_flood)
        self._dos_task = asyncio.create_task(func())
        term.write_line("[bold green]✓ DoS flood running...[/]")

    async def _stop_dos(self) -> None:
        if self._dos:
            self._dos.stop()
        if self._dos_task and not self._dos_task.done():
            self._dos_task.cancel()
        self.query_one("#btn-dos-start", Button).disabled = False
        self.query_one("#btn-dos-stop", Button).disabled = True
        self.query_one("#dos-terminal", TerminalLog).write_line("[bold red]DoS flood stopped.[/]")

    def action_go_back(self) -> None:
        self.app.pop_screen()
