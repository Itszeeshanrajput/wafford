"""Deauthentication & Jamming Screen for Wafford with Real Core Engine."""

from __future__ import annotations

import asyncio
from typing import TYPE_CHECKING, Any

from textual.containers import Container, Horizontal, Vertical
from textual.screen import Screen
from textual.widgets import Button, Header, Input, Select, Static

from wafford.core.deauth import DeauthAttack
from wafford.ui.widgets.mode_guard import ModeGuard
from wafford.ui.widgets.status_bar import StatusBar
from wafford.ui.widgets.terminal_log import TerminalLog

if TYPE_CHECKING:
    from textual.app import ComposeResult


class DeauthMenu(Screen[None]):
    """Wireless Deauthentication & Disassociation Jamming Screen."""

    CSS = """
    DeauthMenu {
        background: $background;
    }
    #da-layout {
        width: 100%;
        height: 1fr;
        padding: 1 2;
    }
    #da-config-card {
        height: auto;
        margin-bottom: 1;
        padding: 1;
        background: $surface;
        border: round $primary;
    }
    .da-row {
        height: 3;
        margin-bottom: 1;
        layout: horizontal;
    }
    .da-input {
        width: 1fr;
        margin-right: 1;
    }
    #da-buttons {
        height: 3;
        layout: horizontal;
    }
    #da-buttons Button {
        margin-right: 1;
    }
    #da-term-container {
        height: 1fr;
    }
    """

    BINDINGS = [
        ("escape", "go_back", "Back"),
        ("ctrl+d", "toggle_deauth", "Toggle"),
    ]

    def __init__(self, **kwargs: Any) -> None:
        super().__init__(**kwargs)
        self._deauth: DeauthAttack | None = None
        self._attack_task: asyncio.Task[Any] | None = None

    def compose(self) -> ComposeResult:
        yield Header(show_clock=True)
        with Vertical(id="da-layout"):
            with Vertical(id="da-config-card"):
                Static("🛑 Wireless Deauthentication & Jamming", classes="menu-title")
                yield ModeGuard(required="monitor", id="da-mode-guard")
                with Horizontal(classes="da-row"):
                    yield Input(placeholder="Target BSSID (e.g. AA:BB:CC:DD:EE:FF)", id="da-bssid", classes="da-input")
                    yield Input(placeholder="Client MAC (FF:FF:FF:FF:FF:FF for broadcast)", id="da-client", value="FF:FF:FF:FF:FF:FF", classes="da-input")
                    yield Input(placeholder="Packet Count (0 for continuous)", id="da-count", value="64", classes="da-input")
                with Horizontal(classes="da-row"):
                    yield Select([("Targeted / Broadcast Deauth", "targeted"), ("Selective Jamming", "selective"), ("Stealth Micro-bursts", "stealth")], value="targeted", id="da-mode-select")

                with Horizontal(id="da-buttons"):
                    yield Button("▶ Start Deauth", id="btn-da-start", variant="success")
                    yield Button("⏹ Stop", id="btn-da-stop", variant="error", disabled=True)
                    yield Button("← Back", id="btn-da-back", variant="default")

            with Container(id="da-term-container"):
                yield TerminalLog(id="da-terminal")

        yield StatusBar(id="status-bar")

    def on_mount(self) -> None:
        if getattr(self.app, "selected_network", None):
            self.query_one("#da-bssid", Input).value = self.app.selected_network.get("bssid", "")

    async def on_button_pressed(self, event: Button.Pressed) -> None:
        bid = event.button.id
        if bid == "btn-da-start":
            await self._start_deauth()
        elif bid == "btn-da-stop":
            await self._stop_deauth()
        elif bid == "btn-da-back":
            self.action_go_back()

    async def _start_deauth(self) -> None:
        bssid = self.query_one("#da-bssid", Input).value.strip()
        client = self.query_one("#da-client", Input).value.strip() or "FF:FF:FF:FF:FF:FF"
        count_str = self.query_one("#da-count", Input).value.strip()
        mode = self.query_one("#da-mode-select", Select).value or "targeted"
        term = self.query_one("#da-terminal", TerminalLog)

        if not bssid:
            term.write_line("[bold red]Please enter a valid target BSSID.[/]")
            return

        try:
            count = int(count_str)
        except ValueError:
            count = 64

        iface = getattr(self.app, "selected_interface", "wlan0mon") or "wlan0mon"
        term.write_line(f"[bold cyan]Launching {mode} deauth on {bssid} (Client: {client}) via {iface}...[/]")

        self.query_one("#btn-da-start", Button).disabled = True
        self.query_one("#btn-da-stop", Button).disabled = False

        self._deauth = DeauthAttack(interface=iface)
        self._deauth.on("deauth.sent", lambda evt: term.write_line(f"Sent {evt.data.get('packets_sent', 0)} frames to {evt.data.get('client', client)}"))

        if client.upper() == "FF:FF:FF:FF:FF:FF":
            self._attack_task = asyncio.create_task(self._deauth.broadcast_deauth(bssid, count=count))
        else:
            self._attack_task = asyncio.create_task(self._deauth.targeted_deauth(bssid, client, count=count))

        asyncio.create_task(self._monitor_deauth())

    async def _monitor_deauth(self) -> None:
        term = self.query_one("#da-terminal", TerminalLog)
        try:
            if self._attack_task:
                res = await self._attack_task
                term.write_line(f"[bold green]✓ Deauth completed: {res.message}[/]")
        except Exception as e:
            term.write_line(f"[bold red]Deauth error: {e}[/]")
        finally:
            self.query_one("#btn-da-start", Button).disabled = False
            self.query_one("#btn-da-stop", Button).disabled = True

    async def _stop_deauth(self) -> None:
        if self._deauth:
            await self._deauth.stop()
        if self._attack_task and not self._attack_task.done():
            self._attack_task.cancel()
        self.query_one("#btn-da-start", Button).disabled = False
        self.query_one("#btn-da-stop", Button).disabled = True
        self.query_one("#da-terminal", TerminalLog).write_line("[bold red]Deauth stopped by user.[/]")

    def action_go_back(self) -> None:
        self.app.pop_screen()
