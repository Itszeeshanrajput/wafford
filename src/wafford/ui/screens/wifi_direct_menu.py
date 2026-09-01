"""WiFi Direct / P2P Attack Screen for Wafford with Real Core Engine."""

from __future__ import annotations

import asyncio
from typing import TYPE_CHECKING, Any

from textual.containers import Horizontal, Vertical
from textual.screen import Screen
from textual.widgets import Button, DataTable, Header, Input, Static

from wafford.core.wifi_direct import WiFiDirectAttack, WiFiDirectPeer
from wafford.ui.widgets.status_bar import StatusBar
from wafford.ui.widgets.terminal_log import TerminalLog

if TYPE_CHECKING:
    from textual.app import ComposeResult


class WiFiDirectMenu(Screen[None]):
    """WiFi Direct (P2P) Peer Discovery & Negotiation Screen."""

    CSS = """
    WiFiDirectMenu {
        background: $background;
    }
    #p2p-layout {
        width: 100%;
        height: 1fr;
        padding: 1 2;
    }
    #p2p-config-card {
        height: auto;
        margin-bottom: 1;
        padding: 1;
        background: $surface;
        border: round $primary;
    }
    .p2p-row {
        height: 3;
        margin-bottom: 1;
        layout: horizontal;
    }
    .p2p-input {
        width: 1fr;
        margin-right: 1;
    }
    #p2p-buttons {
        height: 3;
        layout: horizontal;
    }
    #p2p-buttons Button {
        margin-right: 1;
    }
    #p2p-split {
        height: 1fr;
        layout: horizontal;
    }
    #p2p-left {
        width: 50%;
        height: 100%;
        margin-right: 1;
    }
    #p2p-right {
        width: 50%;
        height: 100%;
    }
    #p2p-table {
        height: 1fr;
        background: $surface;
    }
    """

    BINDINGS = [
        ("escape", "go_back", "Back"),
    ]

    def __init__(self, **kwargs: Any) -> None:
        super().__init__(**kwargs)
        self._p2p: WiFiDirectAttack | None = None
        self._p2p_task: asyncio.Task[Any] | None = None
        self._peers: dict[str, WiFiDirectPeer] = {}

    def compose(self) -> ComposeResult:
        yield Header(show_clock=True)
        with Vertical(id="p2p-layout"):
            with Vertical(id="p2p-config-card"):
                Static("📶 WiFi Direct (P2P) Discovery & Group Negotiation", classes="menu-title")
                with Horizontal(classes="p2p-row"):
                    yield Input(placeholder="Scan Duration (sec)", id="p2p-dur", value="25", classes="p2p-input")

                with Horizontal(id="p2p-buttons"):
                    yield Button("▶ Discover P2P Peers", id="btn-p2p-start", variant="success")
                    yield Button("⏹ Stop", id="btn-p2p-stop", variant="error", disabled=True)
                    yield Button("← Back", id="btn-p2p-back", variant="default")

            with Horizontal(id="p2p-split"):
                with Vertical(id="p2p-left"):
                    Static("📱 Discovered P2P Devices", classes="panel-title")
                    yield DataTable(id="p2p-table", zebra_stripes=True)
                with Vertical(id="p2p-right"):
                    yield TerminalLog(id="p2p-terminal")

        yield StatusBar(id="status-bar")

    def on_mount(self) -> None:
        table = self.query_one("#p2p-table", DataTable)
        table.cursor_type = "row"
        table.add_columns("Device MAC", "Device Name", "Status")

    async def on_button_pressed(self, event: Button.Pressed) -> None:
        bid = event.button.id
        if bid == "btn-p2p-start":
            await self._start_p2p()
        elif bid == "btn-p2p-stop":
            await self._stop_p2p()
        elif bid == "btn-p2p-back":
            self.action_go_back()

    async def _start_p2p(self) -> None:
        dur_str = self.query_one("#p2p-dur", Input).value.strip() or "25"
        term = self.query_one("#p2p-terminal", TerminalLog)

        try:
            duration = int(dur_str)
        except ValueError:
            duration = 25

        iface = getattr(self.app, "selected_interface", "wlan0") or "wlan0"
        term.write_line(f"[bold cyan]Launching WiFi Direct discovery on {iface}...[/]")

        self.query_one("#btn-p2p-start", Button).disabled = True
        self.query_one("#btn-p2p-stop", Button).disabled = False

        table = self.query_one("#p2p-table", DataTable)
        table.clear()
        self._peers.clear()

        self._p2p = WiFiDirectAttack(interface=iface)
        self._p2p.on_peer_found(self._on_peer_found)

        self._p2p_task = asyncio.create_task(self._p2p.discover_peers(duration=duration))
        asyncio.create_task(self._monitor_p2p())

    def _on_peer_found(self, peer: WiFiDirectPeer) -> None:
        self._peers[peer.mac] = peer
        table = self.query_one("#p2p-table", DataTable)
        table.clear()
        for p in self._peers.values():
            table.add_row(p.mac, p.device_name or "Unknown P2P Peer", "DISCOVERED")
        term = self.query_one("#p2p-terminal", TerminalLog)
        term.write_line(f"[bold green]Discovered P2P Peer: {peer.mac} ({peer.device_name})[/]")

    async def _monitor_p2p(self) -> None:
        term = self.query_one("#p2p-terminal", TerminalLog)
        try:
            if self._p2p_task:
                res = await self._p2p_task
                term.write_line(f"[bold green]✓ P2P discovery complete: Found {len(res.peers)} peers.[/]")
        except Exception as e:
            term.write_line(f"[bold red]P2P error: {e}[/]")
        finally:
            self.query_one("#btn-p2p-start", Button).disabled = False
            self.query_one("#btn-p2p-stop", Button).disabled = True

    async def _stop_p2p(self) -> None:
        if self._p2p:
            await self._p2p.stop()
        if self._p2p_task and not self._p2p_task.done():
            self._p2p_task.cancel()
        self.query_one("#btn-p2p-start", Button).disabled = False
        self.query_one("#btn-p2p-stop", Button).disabled = True
        self.query_one("#p2p-terminal", TerminalLog).write_line("[bold red]WiFi Direct discovery stopped.[/]")

    def action_go_back(self) -> None:
        self.app.pop_screen()
