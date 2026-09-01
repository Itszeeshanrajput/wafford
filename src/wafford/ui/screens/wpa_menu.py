"""WPA/WPA2/WPA3 Handshake Capture Screen for Wafford with Real Core Engine."""

from __future__ import annotations

import asyncio
from typing import TYPE_CHECKING, Any

from textual.containers import Container, Horizontal, Vertical
from textual.screen import Screen
from textual.widgets import Button, Header, Input, ProgressBar, Select, Static

from wafford.core.handshake import HandshakeCapture
from wafford.ui.widgets.mode_guard import ModeGuard
from wafford.ui.widgets.status_bar import StatusBar
from wafford.ui.widgets.terminal_log import TerminalLog

if TYPE_CHECKING:
    from textual.app import ComposeResult


class WPAMenu(Screen[None]):
    """WPA/WPA2 4-Way Handshake Capture Screen."""

    CSS = """
    WPAMenu {
        background: $background;
    }
    #wpa-layout {
        width: 100%;
        height: 1fr;
        padding: 1 2;
    }
    #wpa-target-card {
        height: auto;
        margin-bottom: 1;
        padding: 1;
        background: $surface;
        border: round $primary;
    }
    .wpa-row {
        height: 3;
        margin-bottom: 1;
        layout: horizontal;
    }
    .wpa-input {
        width: 1fr;
        margin-right: 1;
    }
    #wpa-buttons {
        height: 3;
        layout: horizontal;
    }
    #wpa-buttons Button {
        margin-right: 1;
    }
    #wpa-term-container {
        height: 1fr;
    }
    """

    BINDINGS = [
        ("escape", "go_back", "Back"),
        ("ctrl+s", "start_handshake", "Capture"),
        ("ctrl+p", "start_pmkid", "PMKID"),
    ]

    def __init__(self, **kwargs: Any) -> None:
        super().__init__(**kwargs)
        self._capture_instance: HandshakeCapture | None = None
        self._capture_task: asyncio.Task[Any] | None = None
        self._captured_cap_file: str = ""

    def compose(self) -> ComposeResult:
        yield Header(show_clock=True)
        with Vertical(id="wpa-layout"):
            with Vertical(id="wpa-target-card"):
                Static("🔐 WPA / WPA2 4-Way Handshake Capture", classes="menu-title")
                yield ModeGuard(required="monitor", id="wpa-mode-guard")
                with Horizontal(classes="wpa-row"):
                    yield Input(placeholder="Target BSSID (e.g. AA:BB:CC:DD:EE:FF)", id="wpa-bssid", classes="wpa-input")
                    yield Input(placeholder="Channel (1-14)", id="wpa-channel", value="1", classes="wpa-input")
                    yield Input(placeholder="Target Client MAC (Optional)", id="wpa-client", classes="wpa-input")
                    yield Select([("5 packets", "5"), ("10 packets", "10"), ("25 packets", "25")], value="5", id="wpa-deauth-select")

                with Horizontal(id="wpa-buttons"):
                    yield Button("📸 Capture Handshake", id="btn-hs-start", variant="success")
                    yield Button("⏹ Stop", id="btn-hs-stop", variant="error", disabled=True)
                    yield Button("🔑 PMKID Attack", id="btn-hs-pmkid", variant="primary")
                    yield Button("💥 Crack Handshake", id="btn-hs-crack", variant="warning", disabled=True)
                    yield Button("← Back", id="btn-hs-back", variant="default")

            yield ProgressBar(id="wpa-progress-bar", total=100, show_eta=False)
            with Container(id="wpa-term-container"):
                yield TerminalLog(id="wpa-terminal")

        yield StatusBar(id="status-bar")

    def on_mount(self) -> None:
        if getattr(self.app, "selected_network", None):
            net = self.app.selected_network
            self.query_one("#wpa-bssid", Input).value = net.get("bssid", "")
            self.query_one("#wpa-channel", Input).value = str(net.get("channel", 1))

    async def on_button_pressed(self, event: Button.Pressed) -> None:
        bid = event.button.id
        if bid == "btn-hs-start":
            await self._start_capture()
        elif bid == "btn-hs-stop":
            await self._stop_capture()
        elif bid == "btn-hs-pmkid":
            self.app.push_screen("PMKIDAttack")
        elif bid == "btn-hs-crack":
            self.app.push_screen("PasswordCrack")
        elif bid == "btn-hs-back":
            self.action_go_back()

    async def _start_capture(self) -> None:
        bssid = self.query_one("#wpa-bssid", Input).value.strip()
        ch_str = self.query_one("#wpa-channel", Input).value.strip()
        client = self.query_one("#wpa-client", Input).value.strip() or None
        deauth_count = int(self.query_one("#wpa-deauth-select", Select).value or "5")
        term = self.query_one("#wpa-terminal", TerminalLog)

        if not bssid:
            term.write_line("[bold red]Please enter a valid target BSSID.[/]")
            return

        try:
            channel = int(ch_str)
        except ValueError:
            channel = 1

        iface = getattr(self.app, "selected_interface", "wlan0mon") or "wlan0mon"
        term.write_line(f"[bold cyan]Starting handshake capture on {bssid} (Channel {channel}) using {iface}...[/]")

        self.query_one("#btn-hs-start", Button).disabled = True
        self.query_one("#btn-hs-stop", Button).disabled = False

        self._capture_instance = HandshakeCapture(interface=iface)
        self._capture_instance.on("handshake.captured", self._on_handshake_event)

        self._capture_task = asyncio.create_task(
            self._capture_instance.capture(
                bssid=bssid,
                channel=channel,
                timeout=60,
                deauth_count=deauth_count,
                client=client,
            )
        )
        asyncio.create_task(self._monitor_capture_result())

    def _on_handshake_event(self, evt: Any) -> None:
        term = self.query_one("#wpa-terminal", TerminalLog)
        cap_file = evt.data.get("cap_file", "")
        self._captured_cap_file = cap_file
        term.write_line(f"[bold green]🎉 4-WAY HANDSHAKE CAPTURED: {cap_file}[/]")
        self.query_one("#btn-hs-crack", Button).disabled = False

    async def _monitor_capture_result(self) -> None:
        term = self.query_one("#wpa-terminal", TerminalLog)
        try:
            if self._capture_task:
                res = await self._capture_task
                if res.success:
                    term.write_line(f"[bold green]✓ {res.message}[/]")
                    if hasattr(self.app, "db_manager") and self.app.db_manager:
                        await self.app.db_manager.add_handshake(
                            bssid=self.query_one("#wpa-bssid", Input).value.strip(),
                            essid="Captured",
                            path=res.extra.get("cap_file", ""),
                        )
                else:
                    term.write_line(f"[bold yellow]Capture finished: {res.message}[/]")
        except Exception as e:
            term.write_line(f"[bold red]Capture error: {e}[/]")
        finally:
            self.query_one("#btn-hs-start", Button).disabled = False
            self.query_one("#btn-hs-stop", Button).disabled = True

    async def _stop_capture(self) -> None:
        if self._capture_instance:
            await self._capture_instance.stop()
        if self._capture_task and not self._capture_task.done():
            self._capture_task.cancel()
        self.query_one("#btn-hs-start", Button).disabled = False
        self.query_one("#btn-hs-stop", Button).disabled = True
        self.query_one("#wpa-terminal", TerminalLog).write_line("[bold red]Handshake capture stopped by user.[/]")

    def action_go_back(self) -> None:
        self.app.pop_screen()
