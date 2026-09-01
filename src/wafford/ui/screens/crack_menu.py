"""Password Cracker Screen for Wafford with Real Hashcat and Aircrack Backend."""

from __future__ import annotations

import asyncio
from typing import TYPE_CHECKING, Any

from textual.containers import Container, Horizontal, Vertical
from textual.screen import Screen
from textual.widgets import Button, Header, Input, ProgressBar, Select, Static

from wafford.core.wpa_crack import WPACracker
from wafford.ui.widgets.status_bar import StatusBar
from wafford.ui.widgets.terminal_log import TerminalLog

if TYPE_CHECKING:
    from textual.app import ComposeResult


class CrackMenu(Screen[None]):
    """WPA/WPA2 Hashcat & Aircrack-ng Password Cracking Screen."""

    CSS = """
    CrackMenu {
        background: $background;
    }
    #cr-layout {
        width: 100%;
        height: 1fr;
        padding: 1 2;
    }
    #cr-config-card {
        height: auto;
        margin-bottom: 1;
        padding: 1;
        background: $surface;
        border: round $primary;
    }
    .cr-row {
        height: 3;
        margin-bottom: 1;
        layout: horizontal;
    }
    .cr-input {
        width: 1fr;
        margin-right: 1;
    }
    #cr-buttons {
        height: 3;
        layout: horizontal;
    }
    #cr-buttons Button {
        margin-right: 1;
    }
    #cr-term-container {
        height: 1fr;
    }
    """

    BINDINGS = [
        ("escape", "go_back", "Back"),
        ("ctrl+s", "start_crack", "Crack"),
    ]

    def __init__(self, **kwargs: Any) -> None:
        super().__init__(**kwargs)
        self._cracker: WPACracker | None = None
        self._crack_task: asyncio.Task[Any] | None = None

    def compose(self) -> ComposeResult:
        yield Header(show_clock=True)
        with Vertical(id="cr-layout"):
            with Vertical(id="cr-config-card"):
                Static("💥 WPA / WPA2 Password Cracker", classes="menu-title")
                with Horizontal(classes="cr-row"):
                    yield Input(placeholder="Handshake / PMKID file path (.cap / .hc22000)", id="cr-cap-path", classes="cr-input")
                    yield Input(placeholder="Wordlist path", id="cr-wordlist-path", value="/usr/share/wordlists/rockyou.txt", classes="cr-input")
                    yield Input(placeholder="Target BSSID (Optional)", id="cr-bssid", classes="cr-input")
                with Horizontal(classes="cr-row"):
                    yield Select([("Hashcat (GPU/CPU Optimized)", "hashcat"), ("Aircrack-ng (CPU Standard)", "aircrack-ng")], value="hashcat", id="cr-engine-select")
                    yield Select([("Dictionary Attack (Mode 0)", "dictionary"), ("Brute-force / Mask (Mode 3)", "mask")], value="dictionary", id="cr-mode-select")

                with Horizontal(id="cr-buttons"):
                    yield Button("▶ Start Cracking", id="btn-cr-start", variant="success")
                    yield Button("⏹ Stop", id="btn-cr-stop", variant="error", disabled=True)
                    yield Button("← Back", id="btn-cr-back", variant="default")

            yield ProgressBar(id="cr-progress-bar", total=100, show_eta=False)
            with Container(id="cr-term-container"):
                yield TerminalLog(id="cr-terminal")

        yield StatusBar(id="status-bar")

    def on_mount(self) -> None:
        if getattr(self.app, "selected_network", None):
            self.query_one("#cr-bssid", Input).value = self.app.selected_network.get("bssid", "")

    async def on_button_pressed(self, event: Button.Pressed) -> None:
        bid = event.button.id
        if bid == "btn-cr-start":
            await self._start_cracking()
        elif bid == "btn-cr-stop":
            await self._stop_cracking()
        elif bid == "btn-cr-back":
            self.action_go_back()

    async def _start_cracking(self) -> None:
        cap_file = self.query_one("#cr-cap-path", Input).value.strip()
        wl_file = self.query_one("#cr-wordlist-path", Input).value.strip()
        bssid = self.query_one("#cr-bssid", Input).value.strip() or None
        backend = self.query_one("#cr-engine-select", Select).value or "hashcat"
        term = self.query_one("#cr-terminal", TerminalLog)

        if not cap_file:
            term.write_line("[bold red]Please specify a valid handshake/PMKID file path.[/]")
            return

        term.write_line(f"[bold cyan]Launching {backend} cracking on {cap_file} using {wl_file}...[/]")

        self.query_one("#btn-cr-start", Button).disabled = True
        self.query_one("#btn-cr-stop", Button).disabled = False

        iface = getattr(self.app, "selected_interface", "wlan0") or "wlan0"
        self._cracker = WPACracker(interface=iface, wordlist_path=wl_file)
        self._cracker.on("crack.progress", lambda evt: self._on_crack_progress(evt.data))
        self._cracker.on("crack.finished", lambda evt: self._on_crack_finished(evt.data))

        self._crack_task = asyncio.create_task(
            self._cracker.start_crack(
                handshake_path=cap_file,
                bssid=bssid,
                backend=backend,
            )
        )
        asyncio.create_task(self._monitor_result(bssid))

    def _on_crack_progress(self, data: dict[str, Any]) -> None:
        speed = data.get("speed_hs", 0)
        prog = data.get("progress_pct", 0.0)
        cand = data.get("current_word", "")
        self.query_one("#cr-progress-bar", ProgressBar).update(progress=int(prog))
        if cand:
            self.query_one("#cr-terminal", TerminalLog).write_line(f"Speed: {speed:,.0f} H/s | Candidate: {cand} | Progress: {prog:.1f}%")

    def _on_crack_finished(self, data: dict[str, Any]) -> None:
        cracked = data.get("cracked", False)
        term = self.query_one("#cr-terminal", TerminalLog)
        if cracked:
            term.write_line("[bold green]🎉 PASSWORD CRACKED![/]")
        else:
            term.write_line("[bold yellow]Cracking finished without finding password.[/]")

    async def _monitor_result(self, bssid: str | None) -> None:
        term = self.query_one("#cr-terminal", TerminalLog)
        try:
            if self._crack_task:
                res = await self._crack_task
                if res.success and res.password:
                    term.write_line(f"[bold green]🎉 KEY RECOVERED: {res.password}[/]")
                    if hasattr(self.app, "db_manager") and self.app.db_manager:
                        await self.app.db_manager.add_credential(
                            bssid=bssid or "Unknown",
                            essid="Cracked Handshake",
                            password=res.password,
                            source="wpa_crack",
                        )
                else:
                    term.write_line(f"[bold yellow]Finished: {res.message}[/]")
        except Exception as e:
            term.write_line(f"[bold red]Cracking error: {e}[/]")
        finally:
            self.query_one("#btn-cr-start", Button).disabled = False
            self.query_one("#btn-cr-stop", Button).disabled = True

    async def _stop_cracking(self) -> None:
        if self._cracker:
            await self._cracker.stop()
        if self._crack_task and not self._crack_task.done():
            self._crack_task.cancel()
        self.query_one("#btn-cr-start", Button).disabled = False
        self.query_one("#btn-cr-stop", Button).disabled = True
        self.query_one("#cr-terminal", TerminalLog).write_line("[bold red]Cracking stopped by user.[/]")

    def action_go_back(self) -> None:
        self.app.pop_screen()
