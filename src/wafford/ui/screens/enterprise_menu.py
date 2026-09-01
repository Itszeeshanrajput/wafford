"""Enterprise 802.1X Attack Screen for Wafford with Real Core Engine."""

from __future__ import annotations

import asyncio
from typing import TYPE_CHECKING, Any

from textual.containers import Horizontal, Vertical
from textual.screen import Screen
from textual.widgets import Button, DataTable, Header, Input, Static

from wafford.core.enterprise import CapturedIdentity, EnterpriseAttack
from wafford.ui.widgets.mode_guard import ModeGuard
from wafford.ui.widgets.status_bar import StatusBar
from wafford.ui.widgets.terminal_log import TerminalLog

if TYPE_CHECKING:
    from textual.app import ComposeResult


class EnterpriseMenu(Screen[None]):
    """Enterprise 802.1X / RADIUS EAP Identity Harvesting Screen."""

    CSS = """
    EnterpriseMenu {
        background: $background;
    }
    #ent-layout {
        width: 100%;
        height: 1fr;
        padding: 1 2;
    }
    #ent-config-card {
        height: auto;
        margin-bottom: 1;
        padding: 1;
        background: $surface;
        border: round $primary;
    }
    .ent-row {
        height: 3;
        margin-bottom: 1;
        layout: horizontal;
    }
    .ent-input {
        width: 1fr;
        margin-right: 1;
    }
    #ent-buttons {
        height: 3;
        layout: horizontal;
    }
    #ent-buttons Button {
        margin-right: 1;
    }
    #ent-split {
        height: 1fr;
        layout: horizontal;
    }
    #ent-left {
        width: 50%;
        height: 100%;
        margin-right: 1;
    }
    #ent-right {
        width: 50%;
        height: 100%;
    }
    #ent-table {
        height: 1fr;
        background: $surface;
    }
    """

    BINDINGS = [
        ("escape", "go_back", "Back"),
    ]

    def __init__(self, **kwargs: Any) -> None:
        super().__init__(**kwargs)
        self._ent: EnterpriseAttack | None = None
        self._attack_task: asyncio.Task[Any] | None = None
        self._identities: list[CapturedIdentity] = []

    def compose(self) -> ComposeResult:
        yield Header(show_clock=True)
        with Vertical(id="ent-layout"):
            with Vertical(id="ent-config-card"):
                Static("🏢 Enterprise 802.1X / Evil RADIUS Harvester", classes="menu-title")
                yield ModeGuard(required="monitor", id="enterprise_menu-mode-guard")
                with Horizontal(classes="ent-row"):
                    yield Input(placeholder="SSID to clone", id="ent-ssid", value="Corp-WiFi-8021X", classes="ent-input")
                    yield Input(placeholder="Channel", id="ent-channel", value="6", classes="ent-input")

                with Horizontal(id="ent-buttons"):
                    yield Button("▶ Start Evil RADIUS", id="btn-ent-start", variant="success")
                    yield Button("⏹ Stop Server", id="btn-ent-stop", variant="error", disabled=True)
                    yield Button("← Back", id="btn-ent-back", variant="default")

            with Horizontal(id="ent-split"):
                with Vertical(id="ent-left"):
                    Static("👤 Captured EAP Identities", classes="panel-title")
                    yield DataTable(id="ent-table", zebra_stripes=True)
                with Vertical(id="ent-right"):
                    yield TerminalLog(id="ent-terminal")

        yield StatusBar(id="status-bar")

    def on_mount(self) -> None:
        table = self.query_one("#ent-table", DataTable)
        table.cursor_type = "row"
        table.add_columns("Client MAC", "EAP Identity", "Challenge / Hash")

    async def on_button_pressed(self, event: Button.Pressed) -> None:
        bid = event.button.id
        if bid == "btn-ent-start":
            await self._start_radius()
        elif bid == "btn-ent-stop":
            await self._stop_radius()
        elif bid == "btn-ent-back":
            self.action_go_back()

    async def _start_radius(self) -> None:
        ssid = self.query_one("#ent-ssid", Input).value.strip() or "Corp-WiFi"
        ch_str = self.query_one("#ent-channel", Input).value.strip() or "6"
        term = self.query_one("#ent-terminal", TerminalLog)

        try:
            channel = int(ch_str)
        except ValueError:
            channel = 6

        iface = getattr(self.app, "selected_interface", "wlan0mon") or "wlan0mon"
        term.write_line(f"[bold cyan]Launching Hostapd-WPE Evil RADIUS '{ssid}' on {iface}...[/]")

        self.query_one("#btn-ent-start", Button).disabled = True
        self.query_one("#btn-ent-stop", Button).disabled = False

        self._ent = EnterpriseAttack(interface=iface)
        self._ent.on_identity_captured(self._on_identity_captured)

        self._attack_task = asyncio.create_task(self._ent.start(ssid=ssid, channel=channel))
        term.write_line("[bold green]✓ Evil RADIUS AP active. Awaiting client authentications...[/]")

    def _on_identity_captured(self, ident: CapturedIdentity) -> None:
        self._identities.append(ident)
        table = self.query_one("#ent-table", DataTable)
        table.add_row(ident.mac, ident.identity, ident.challenge or ident.response or "EAP Response")
        term = self.query_one("#ent-terminal", TerminalLog)
        term.write_line(f"[bold green]🎉 EAP IDENTITY HARVESTED: User '{ident.identity}' from {ident.mac}[/]")

    async def _stop_radius(self) -> None:
        if self._ent:
            await self._ent.stop()
        if self._attack_task and not self._attack_task.done():
            self._attack_task.cancel()
        self.query_one("#btn-ent-start", Button).disabled = False
        self.query_one("#btn-ent-stop", Button).disabled = True
        self.query_one("#ent-terminal", TerminalLog).write_line("[bold red]Evil RADIUS stopped.[/]")

    def action_go_back(self) -> None:
        self.app.pop_screen()
