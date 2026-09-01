"""WEP Attack & Cracking Screen for Wafford with Real Core Engine."""

from __future__ import annotations

import asyncio
from typing import TYPE_CHECKING, Any

from textual.containers import Container, Horizontal, Vertical
from textual.screen import Screen
from textual.widgets import Button, Header, Input, ProgressBar, Select, Static

from wafford.core.wep import WEPAttack
from wafford.ui.widgets.mode_guard import ModeGuard
from wafford.ui.widgets.status_bar import StatusBar
from wafford.ui.widgets.terminal_log import TerminalLog

if TYPE_CHECKING:
    from textual.app import ComposeResult


class WEPMenu(Screen[None]):
    """WEP IV Harvesting & Statistical Key Recovery Screen."""

    CSS = """
    WEPMenu {
        background: $background;
    }
    #wep-layout {
        width: 100%;
        height: 1fr;
        padding: 1 2;
    }
    #wep-config-card {
        height: auto;
        margin-bottom: 1;
        padding: 1;
        background: $surface;
        border: round $primary;
    }
    .wep-row {
        height: 3;
        margin-bottom: 1;
        layout: horizontal;
    }
    .wep-input {
        width: 1fr;
        margin-right: 1;
    }
    #wep-buttons {
        height: 3;
        layout: horizontal;
    }
    #wep-buttons Button {
        margin-right: 1;
    }
    #wep-term-container {
        height: 1fr;
    }
    """

    BINDINGS = [
        ("escape", "go_back", "Back"),
    ]

    def __init__(self, **kwargs: Any) -> None:
        super().__init__(**kwargs)
        self._wep: WEPAttack | None = None
        self._attack_task: asyncio.Task[Any] | None = None

    def compose(self) -> ComposeResult:
        yield Header(show_clock=True)
        with Vertical(id="wep-layout"):
            with Vertical(id="wep-config-card"):
                Static("🔓 WEP Key Recovery & Packet Replay", classes="menu-title")
                yield ModeGuard(required="monitor", id="wep_menu-mode-guard")
                with Horizontal(classes="wep-row"):
                    yield Input(placeholder="Target BSSID", id="wep-bssid", classes="wep-input")
                    yield Input(placeholder="Channel", id="wep-channel", value="1", classes="wep-input")
                    yield Select([("PTW Attack (Fast)", "ptw"), ("ARP Replay", "arp_replay"), ("ChopChop Injection", "chopchop"), ("Fragmentation", "fragment")], value="ptw", id="wep-mode-select")

                with Horizontal(id="wep-buttons"):
                    yield Button("▶ Start WEP Attack", id="btn-wep-start", variant="success")
                    yield Button("⏹ Stop", id="btn-wep-stop", variant="error", disabled=True)
                    yield Button("← Back", id="btn-wep-back", variant="default")

            yield ProgressBar(id="wep-progress-bar", total=100, show_eta=False)
            with Container(id="wep-term-container"):
                yield TerminalLog(id="wep-terminal")

        yield StatusBar(id="status-bar")

    def on_mount(self) -> None:
        if getattr(self.app, "selected_network", None):
            self.query_one("#wep-bssid", Input).value = self.app.selected_network.get("bssid", "")
            self.query_one("#wep-channel", Input).value = str(self.app.selected_network.get("channel", 1))

    async def on_button_pressed(self, event: Button.Pressed) -> None:
        bid = event.button.id
        if bid == "btn-wep-start":
            await self._start_wep()
        elif bid == "btn-wep-stop":
            await self._stop_wep()
        elif bid == "btn-wep-back":
            self.action_go_back()

    async def _start_wep(self) -> None:
        bssid = self.query_one("#wep-bssid", Input).value.strip()
        ch_str = self.query_one("#wep-channel", Input).value.strip()
        mode = self.query_one("#wep-mode-select", Select).value or "ptw"
        term = self.query_one("#wep-terminal", TerminalLog)

        if not bssid:
            term.write_line("[bold red]Please enter a valid target BSSID.[/]")
            return

        try:
            channel = int(ch_str)
        except ValueError:
            channel = 1

        iface = getattr(self.app, "selected_interface", "wlan0mon") or "wlan0mon"
        term.write_line(f"[bold cyan]Starting {mode.upper()} WEP attack on {bssid} (Ch {channel}) via {iface}...[/]")

        self.query_one("#btn-wep-start", Button).disabled = True
        self.query_one("#btn-wep-stop", Button).disabled = False

        self._wep = WEPAttack(interface=iface)
        self._attack_task = asyncio.create_task(
            self._wep.start(target_bssid=bssid, channel=channel, attack_mode=mode)
        )
        asyncio.create_task(self._monitor_wep(bssid))

    async def _monitor_wep(self, bssid: str) -> None:
        term = self.query_one("#wep-terminal", TerminalLog)
        try:
            if self._attack_task:
                res = await self._attack_task
                if res.success and res.password:
                    term.write_line(f"[bold green]🎉 WEP KEY RECOVERED: {res.password}[/]")
                    if hasattr(self.app, "db_manager") and self.app.db_manager:
                        await self.app.db_manager.add_credential(
                            bssid=bssid,
                            essid="WEP Network",
                            password=res.password,
                            source="wep",
                        )
                else:
                    term.write_line(f"[bold yellow]WEP attack finished: {res.message}[/]")
        except Exception as e:
            term.write_line(f"[bold red]WEP attack error: {e}[/]")
        finally:
            self.query_one("#btn-wep-start", Button).disabled = False
            self.query_one("#btn-wep-stop", Button).disabled = True

    async def _stop_wep(self) -> None:
        if self._wep:
            await self._wep.stop()
        if self._attack_task and not self._attack_task.done():
            self._attack_task.cancel()
        self.query_one("#btn-wep-start", Button).disabled = False
        self.query_one("#btn-wep-stop", Button).disabled = True
        self.query_one("#wep-terminal", TerminalLog).write_line("[bold red]WEP attack stopped.[/]")

    def action_go_back(self) -> None:
        self.app.pop_screen()
