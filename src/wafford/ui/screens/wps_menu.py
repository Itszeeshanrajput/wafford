"""WPS Pixie Dust & PIN Brute-force Screen for Wafford."""

from __future__ import annotations

import asyncio
from typing import TYPE_CHECKING

from textual.containers import Container, Horizontal, Vertical
from textual.screen import Screen
from textual.widgets import Button, Header, Input, ProgressBar, Select, Static

from wafford.core.wps import WPSAttack
from wafford.ui.widgets.mode_guard import ModeGuard
from wafford.ui.widgets.status_bar import StatusBar
from wafford.ui.widgets.terminal_log import TerminalLog

if TYPE_CHECKING:
    from textual.app import ComposeResult


class WPSMenu(Screen[None]):
    """WPS Pixie Dust attack and PIN brute-forcing screen."""

    CSS = """
    WPSMenu {
        background: $background;
    }
    #wps-container {
        width: 100%;
        height: 1fr;
        padding: 1 2;
    }
    #wps-controls {
        height: auto;
        margin-bottom: 1;
        padding: 1;
        background: $surface;
        border: round $primary;
    }
    .wps-row {
        height: 3;
        margin-bottom: 1;
        layout: horizontal;
    }
    .wps-input {
        width: 1fr;
        margin-right: 1;
    }
    #wps-buttons {
        height: 3;
        layout: horizontal;
    }
    #wps-buttons Button {
        margin-right: 1;
    }
    #wps-progress-bar {
        width: 100%;
        margin-bottom: 1;
    }
    #wps-term-box {
        height: 1fr;
    }
    """

    def compose(self) -> ComposeResult:
        yield Header(show_clock=True)
        with Vertical(id="wps-container"):
            with Vertical(id="wps-controls"):
                Static("⚡ WPS Pixie Dust & PIN Recovery", classes="menu-title")
                yield ModeGuard(required="monitor", id="wps_menu-mode-guard")
                with Horizontal(classes="wps-row"):
                    yield Input(placeholder="Target BSSID (e.g. AA:BB:CC:DD:EE:FF)", id="wps-bssid", classes="wps-input")
                    yield Input(placeholder="Channel (1-14)", id="wps-channel", value="1", classes="wps-input")
                    yield Select(
                        [("Pixie Dust (Offline DH)", "pixie_dust"), ("PIN Brute-force (Online)", "pin_brute")],
                        value="pixie_dust",
                        id="wps-type-select",
                    )
                with Horizontal(id="wps-buttons"):
                    yield Button("Launch Attack", id="btn-wps-start", variant="success")
                    yield Button("Stop Attack", id="btn-wps-stop", variant="error", disabled=True)
                    yield Button("Back to Attacks", id="btn-wps-back", variant="default")

            yield ProgressBar(id="wps-progress-bar", total=100, show_eta=False)
            with Container(id="wps-term-box"):
                yield TerminalLog(id="wps-terminal")

        yield StatusBar(id="status-bar")

    def on_mount(self) -> None:
        if getattr(self.app, "selected_network", None):
            net = self.app.selected_network
            self.query_one("#wps-bssid", Input).value = net.get("bssid", "")
            self.query_one("#wps-channel", Input).value = str(net.get("channel", 1))

    async def on_button_pressed(self, event: Button.Pressed) -> None:
        bid = event.button.id
        if bid == "btn-wps-start":
            await self._start_wps_attack()
        elif bid == "btn-wps-stop":
            await self._stop_wps_attack()
        elif bid == "btn-wps-back":
            self.app.push_screen("AttackMenu")

    async def _start_wps_attack(self) -> None:
        bssid = self.query_one("#wps-bssid", Input).value.strip()
        ch_str = self.query_one("#wps-channel", Input).value.strip()
        attack_type = self.query_one("#wps-type-select", Select).value or "pixie_dust"
        term = self.query_one("#wps-terminal", TerminalLog)

        if not bssid:
            term.write_line("[bold red]Please enter a valid target BSSID.[/]")
            return

        try:
            channel = int(ch_str)
        except ValueError:
            channel = 1

        iface = getattr(self.app, "selected_interface", "wlan0mon") or "wlan0mon"
        term.write_line(f"[bold cyan]Launching WPS Attack ({attack_type}) on {bssid} (Ch {channel})...[/]")

        self.query_one("#btn-wps-start", Button).disabled = True
        self.query_one("#btn-wps-stop", Button).disabled = False

        self._attack_instance = WPSAttack(iface, bssid, channel)
        self._attack_instance.on("wps.output", lambda evt: term.write_line(evt.data.get("line", "")))

        asyncio.create_task(self._run_attack_task(attack_type))

    async def _run_attack_task(self, attack_type: str) -> None:
        term = self.query_one("#wps-terminal", TerminalLog)
        try:
            res = await self._attack_instance.start(attack_type=attack_type)
            if res.success:
                term.write_line(f"[bold green]🎉 SUCCESS: {res.message}[/]")
                if hasattr(self.app, "db_manager") and self.app.db_manager:
                    await self.app.db_manager.add_credential(
                        bssid=self._attack_instance.target_bssid,
                        essid=self._attack_instance.essid or "Unknown",
                        password=res.password,
                        source="wps",
                    )
            else:
                term.write_line(f"[bold yellow]Attack finished: {res.message}[/]")
        except Exception as e:
            term.write_line(f"[bold red]WPS attack error: {e}[/]")
        finally:
            self.query_one("#btn-wps-start", Button).disabled = False
            self.query_one("#btn-wps-stop", Button).disabled = True

    async def _stop_wps_attack(self) -> None:
        if hasattr(self, "_attack_instance") and self._attack_instance:
            await self._attack_instance.stop()
            self.query_one("#wps-terminal", TerminalLog).write_line("[bold red]WPS attack stopped by user.[/]")
        self.query_one("#btn-wps-start", Button).disabled = False
        self.query_one("#btn-wps-stop", Button).disabled = True
