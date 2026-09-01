"""PMKID Clientless Attack Screen for Wafford with Real Core Engine."""

from __future__ import annotations

import asyncio
from typing import TYPE_CHECKING, Any

from textual.containers import Container, Horizontal, Vertical
from textual.screen import Screen
from textual.widgets import Button, Header, Input, Static

from wafford.core.pmkid import PMKIDAttack
from wafford.ui.widgets.mode_guard import ModeGuard
from wafford.ui.widgets.status_bar import StatusBar
from wafford.ui.widgets.terminal_log import TerminalLog

if TYPE_CHECKING:
    from textual.app import ComposeResult


class PMKIDMenu(Screen[None]):
    """Clientless PMKID Capture Screen using hcxdumptool."""

    CSS = """
    PMKIDMenu {
        background: $background;
    }
    #pm-layout {
        width: 100%;
        height: 1fr;
        padding: 1 2;
    }
    #pm-config-card {
        height: auto;
        margin-bottom: 1;
        padding: 1;
        background: $surface;
        border: round $primary;
    }
    .pm-row {
        height: 3;
        margin-bottom: 1;
        layout: horizontal;
    }
    .pm-input {
        width: 1fr;
        margin-right: 1;
    }
    #pm-buttons {
        height: 3;
        layout: horizontal;
    }
    #pm-buttons Button {
        margin-right: 1;
    }
    #pm-term-container {
        height: 1fr;
    }
    """

    BINDINGS = [
        ("escape", "go_back", "Back"),
    ]

    def __init__(self, **kwargs: Any) -> None:
        super().__init__(**kwargs)
        self._pmkid: PMKIDAttack | None = None
        self._attack_task: asyncio.Task[Any] | None = None

    def compose(self) -> ComposeResult:
        yield Header(show_clock=True)
        with Vertical(id="pm-layout"):
            with Vertical(id="pm-config-card"):
                Static("🔑 Clientless PMKID Capture (hcxdumptool)", classes="menu-title")
                yield ModeGuard(required="monitor", id="pmkid_menu-mode-guard")
                with Horizontal(classes="pm-row"):
                    yield Input(placeholder="Target BSSID (Optional for broadcast)", id="pm-bssid", classes="pm-input")
                    yield Input(placeholder="Timeout in seconds", id="pm-timeout", value="30", classes="pm-input")

                with Horizontal(id="pm-buttons"):
                    yield Button("▶ Start PMKID Capture", id="btn-pm-start", variant="success")
                    yield Button("⏹ Stop", id="btn-pm-stop", variant="error", disabled=True)
                    yield Button("💥 Crack PMKID", id="btn-pm-crack", variant="warning", disabled=True)
                    yield Button("← Back", id="btn-pm-back", variant="default")

            with Container(id="pm-term-container"):
                yield TerminalLog(id="pm-terminal")

        yield StatusBar(id="status-bar")

    def on_mount(self) -> None:
        if getattr(self.app, "selected_network", None):
            self.query_one("#pm-bssid", Input).value = self.app.selected_network.get("bssid", "")

    async def on_button_pressed(self, event: Button.Pressed) -> None:
        bid = event.button.id
        if bid == "btn-pm-start":
            await self._start_pmkid()
        elif bid == "btn-pm-stop":
            await self._stop_pmkid()
        elif bid == "btn-pm-crack":
            self.app.push_screen("PasswordCrack")
        elif bid == "btn-pm-back":
            self.action_go_back()

    async def _start_pmkid(self) -> None:
        bssid = self.query_one("#pm-bssid", Input).value.strip() or None
        dur_str = self.query_one("#pm-timeout", Input).value.strip()
        term = self.query_one("#pm-terminal", TerminalLog)

        try:
            timeout = int(dur_str)
        except ValueError:
            timeout = 30

        iface = getattr(self.app, "selected_interface", "wlan0mon") or "wlan0mon"
        term.write_line(f"[bold cyan]Starting PMKID capture on {bssid or 'all nearby APs'} via {iface}...[/]")

        self.query_one("#btn-pm-start", Button).disabled = True
        self.query_one("#btn-pm-stop", Button).disabled = False

        self._pmkid = PMKIDAttack(interface=iface)
        self._attack_task = asyncio.create_task(
            self._pmkid.capture_pmkid(target_bssid=bssid, timeout_seconds=timeout)
        )
        asyncio.create_task(self._monitor_pmkid())

    async def _monitor_pmkid(self) -> None:
        term = self.query_one("#pm-terminal", TerminalLog)
        try:
            if self._attack_task:
                res = await self._attack_task
                if res.success:
                    term.write_line(f"[bold green]🎉 PMKID CAPTURED: {res.message}[/]")
                    self.query_one("#btn-pm-crack", Button).disabled = False
                else:
                    term.write_line(f"[bold yellow]PMKID capture finished: {res.message}[/]")
        except Exception as e:
            term.write_line(f"[bold red]PMKID error: {e}[/]")
        finally:
            self.query_one("#btn-pm-start", Button).disabled = False
            self.query_one("#btn-pm-stop", Button).disabled = True

    async def _stop_pmkid(self) -> None:
        if self._pmkid:
            await self._pmkid.stop()
        if self._attack_task and not self._attack_task.done():
            self._attack_task.cancel()
        self.query_one("#btn-pm-start", Button).disabled = False
        self.query_one("#btn-pm-stop", Button).disabled = True
        self.query_one("#pm-terminal", TerminalLog).write_line("[bold red]PMKID capture stopped by user.[/]")

    def action_go_back(self) -> None:
        self.app.pop_screen()
