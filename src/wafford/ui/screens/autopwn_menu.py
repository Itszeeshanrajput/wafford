"""Auto-PWN Automated Auditing Screen for Wafford."""

from __future__ import annotations

import asyncio
from typing import TYPE_CHECKING, Any

from rich.text import Text
from textual.containers import Horizontal, Vertical
from textual.screen import Screen
from textual.widgets import Button, DataTable, Header, ProgressBar, Static

from wafford.core.autopwn import AutoPWNEngine, AutoPWNTarget
from wafford.ui.widgets.mode_guard import ModeGuard
from wafford.ui.widgets.status_bar import StatusBar
from wafford.ui.widgets.terminal_log import TerminalLog

if TYPE_CHECKING:
    from textual.app import ComposeResult


class AutoPWNMenu(Screen[None]):
    """One-click autonomous auditing pipeline screen."""

    CSS = """
    AutoPWNMenu {
        background: $background;
    }
    #autopwn-container {
        width: 100%;
        height: 1fr;
        padding: 1 2;
    }
    #autopwn-header-box {
        height: auto;
        margin-bottom: 1;
        padding: 1;
        background: $surface;
        border: round $primary;
    }
    #autopwn-controls {
        height: 3;
        layout: horizontal;
    }
    #autopwn-controls Button {
        margin-right: 1;
    }
    #autopwn-grid {
        height: 1fr;
        layout: horizontal;
    }
    #autopwn-left-pane {
        width: 55%;
        height: 100%;
        margin-right: 1;
    }
    #autopwn-right-pane {
        width: 45%;
        height: 100%;
    }
    #targets-table {
        height: 1fr;
        background: $surface;
    }
    """

    def compose(self) -> ComposeResult:
        yield Header(show_clock=True)
        with Vertical(id="autopwn-container"):
            with Vertical(id="autopwn-header-box"):
                Static("🤖 Auto-PWN Autonomous Audit Pipeline", classes="menu-title")
                with Horizontal(id="autopwn-controls"):
                    yield Button("Start Auto-PWN", id="btn-autopwn-start", variant="success")
                    yield Button("Stop", id="btn-autopwn-stop", variant="error", disabled=True)
                    yield Button("Back to Main Menu", id="btn-autopwn-back", variant="default")

            yield ProgressBar(id="autopwn-progress", total=100, show_eta=False)

            with Horizontal(id="autopwn-grid"):
                with Vertical(id="autopwn-left-pane"):
                    yield DataTable(id="targets-table", zebra_stripes=True)
                with Vertical(id="autopwn-right-pane"):
                    yield TerminalLog(id="autopwn-terminal")

        yield StatusBar(id="status-bar")

    def on_mount(self) -> None:
        table = self.query_one("#targets-table", DataTable)
        table.add_columns("ESSID", "BSSID", "Ch", "Enc", "Status", "Password")
        table.cursor_type = "row"

    async def on_button_pressed(self, event: Button.Pressed) -> None:
        bid = event.button.id
        if bid == "btn-autopwn-start":
            await self._start_autopwn()
        elif bid == "btn-autopwn-stop":
            await self._stop_autopwn()
        elif bid == "btn-autopwn-back":
            self.app.push_screen("MainMenu")

    async def _start_autopwn(self) -> None:
        iface = getattr(self.app, "selected_interface", "wlan0mon") or "wlan0mon"
        term = self.query_one("#autopwn-terminal", TerminalLog)
        term.write_line(f"[bold cyan]Starting autonomous auditing pipeline on {iface}...[/]")

        self.query_one("#btn-autopwn-start", Button).disabled = True
        self.query_one("#btn-autopwn-stop", Button).disabled = False

        self._engine = AutoPWNEngine(interface=iface)
        self._engine.bus.on("autopwn.phase", self._on_phase_update)
        self._engine.bus.on("autopwn.target_update", self._on_target_update)
        self._engine.bus.on("autopwn.credential", self._on_credential_found)

        asyncio.create_task(self._run_engine_task())

    def _on_phase_update(self, evt: Any) -> None:
        phase = evt.data.get("phase", "")
        prog = evt.data.get("progress", 0.0)
        self.query_one("#autopwn-progress", ProgressBar).update(progress=int(prog * 100))
        self.query_one("#autopwn-terminal", TerminalLog).write_line(f"[bold magenta]► Phase: {phase}[/]")

    def _on_target_update(self, evt: Any) -> None:
        target: AutoPWNTarget = evt.data.get("target")
        if not target:
            return
        table = self.query_one("#targets-table", DataTable)

        # Refresh table rows
        table.clear()
        for t in self._engine.targets:
            s_style = "bold green" if t.status == "cracked" else ("bold yellow" if t.status in ("attacking", "captured") else "dim")
            table.add_row(t.essid, t.bssid, str(t.channel), t.encryption, Text(t.status.upper(), style=s_style), t.password or "—")

    def _on_credential_found(self, evt: Any) -> None:
        cred = evt.data
        term = self.query_one("#autopwn-terminal", TerminalLog)
        term.write_line(f"[bold green]🎉 KEY RECOVERED for {cred.get('essid')}: {cred.get('password')} (Type: {cred.get('type')})[/]")
        if hasattr(self.app, "db_manager") and self.app.db_manager:
            asyncio.create_task(self.app.db_manager.add_credential(
                bssid=cred.get("bssid", ""),
                essid=cred.get("essid", ""),
                password=cred.get("password", ""),
                source="autopwn",
            ))

    async def _run_engine_task(self) -> None:
        term = self.query_one("#autopwn-terminal", TerminalLog)
        try:
            res = await self._engine.start()
            term.write_line(f"[bold green]🏁 {res.message}[/]")
        except Exception as e:
            term.write_line(f"[bold red]Auto-PWN error: {e}[/]")
        finally:
            self.query_one("#btn-autopwn-start", Button).disabled = False
            self.query_one("#btn-autopwn-stop", Button).disabled = True

    async def _stop_autopwn(self) -> None:
        if hasattr(self, "_engine") and self._engine:
            await self._engine.stop()
            self.query_one("#autopwn-terminal", TerminalLog).write_line("[bold red]Auto-PWN stopped by user.[/]")
        self.query_one("#btn-autopwn-start", Button).disabled = False
        self.query_one("#btn-autopwn-stop", Button).disabled = True
