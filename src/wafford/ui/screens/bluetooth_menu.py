"""Bluetooth Reconnaissance Screen for Wafford with Real Core Engine."""

from __future__ import annotations

import asyncio
from typing import TYPE_CHECKING, Any

from textual.containers import Horizontal, Vertical
from textual.screen import Screen
from textual.widgets import Button, DataTable, Header, Input, Select, Static

from wafford.core.bluetooth import BluetoothDevice, BluetoothRecon
from wafford.ui.widgets.status_bar import StatusBar
from wafford.ui.widgets.terminal_log import TerminalLog

if TYPE_CHECKING:
    from textual.app import ComposeResult


class BluetoothMenu(Screen[None]):
    """Bluetooth Reconnaissance & BLE / Classic Device Discovery Screen."""

    CSS = """
    BluetoothMenu {
        background: $background;
    }
    #bt-layout {
        width: 100%;
        height: 1fr;
        padding: 1 2;
    }
    #bt-config-card {
        height: auto;
        margin-bottom: 1;
        padding: 1;
        background: $surface;
        border: round $primary;
    }
    .bt-row {
        height: 3;
        margin-bottom: 1;
        layout: horizontal;
    }
    .bt-input {
        width: 1fr;
        margin-right: 1;
    }
    #bt-buttons {
        height: 3;
        layout: horizontal;
    }
    #bt-buttons Button {
        margin-right: 1;
    }
    #bt-split {
        height: 1fr;
        layout: horizontal;
    }
    #bt-left {
        width: 60%;
        height: 100%;
        margin-right: 1;
    }
    #bt-right {
        width: 40%;
        height: 100%;
    }
    #bt-device-table {
        height: 1fr;
        background: $surface;
    }
    """

    BINDINGS = [
        ("escape", "go_back", "Back"),
    ]

    def __init__(self, **kwargs: Any) -> None:
        super().__init__(**kwargs)
        self._bt: BluetoothRecon | None = None
        self._scan_task: asyncio.Task[Any] | None = None
        self._devices: dict[str, BluetoothDevice] = {}

    def compose(self) -> ComposeResult:
        yield Header(show_clock=True)
        with Vertical(id="bt-layout"):
            with Vertical(id="bt-config-card"):
                Static("📱 Bluetooth Reconnaissance & BLE Discovery", classes="menu-title")
                with Horizontal(classes="bt-row"):
                    yield Input(placeholder="Interface", id="bt-iface", value="hci0", classes="bt-input")
                    yield Input(placeholder="Duration (sec)", id="bt-dur", value="20", classes="bt-input")
                    yield Select([("BLE + Classic (Both)", "both"), ("BLE Low Energy Only", "ble"), ("Classic Bluetooth Only", "classic")], value="both", id="bt-type-select")

                with Horizontal(id="bt-buttons"):
                    yield Button("▶ Start BT Scan", id="btn-bt-start", variant="success")
                    yield Button("⏹ Stop Scan", id="btn-bt-stop", variant="error", disabled=True)
                    yield Button("← Back", id="btn-bt-back", variant="default")

            with Horizontal(id="bt-split"):
                with Vertical(id="bt-left"):
                    Static("📡 Discovered Devices", classes="panel-title")
                    yield DataTable(id="bt-device-table", zebra_stripes=True)
                with Vertical(id="bt-right"):
                    yield TerminalLog(id="bt-terminal")

        yield StatusBar(id="status-bar")

    def on_mount(self) -> None:
        table = self.query_one("#bt-device-table", DataTable)
        table.cursor_type = "row"
        table.add_columns("MAC Address", "Name", "Type", "Vendor", "Class")

    async def on_button_pressed(self, event: Button.Pressed) -> None:
        bid = event.button.id
        if bid == "btn-bt-start":
            await self._start_scan()
        elif bid == "btn-bt-stop":
            await self._stop_scan()
        elif bid == "btn-bt-back":
            self.action_go_back()

    async def _start_scan(self) -> None:
        iface = self.query_one("#bt-iface", Input).value.strip() or "hci0"
        dur_str = self.query_one("#bt-dur", Input).value.strip() or "20"
        scan_type = self.query_one("#bt-type-select", Select).value or "both"
        term = self.query_one("#bt-terminal", TerminalLog)

        try:
            duration = int(dur_str)
        except ValueError:
            duration = 20

        term.write_line(f"[bold cyan]Starting Bluetooth reconnaissance ({scan_type}) on {iface}...[/]")

        self.query_one("#btn-bt-start", Button).disabled = True
        self.query_one("#btn-bt-stop", Button).disabled = False

        table = self.query_one("#bt-device-table", DataTable)
        table.clear()
        self._devices.clear()

        self._bt = BluetoothRecon()
        self._bt.on_device_found(self._on_device_found)

        self._scan_task = asyncio.create_task(
            self._bt.scan_and_enumerate(duration=duration, interface=iface, scan_type=scan_type, enumerate_services=True)
        )
        asyncio.create_task(self._monitor_scan())

    def _on_device_found(self, dev: BluetoothDevice) -> None:
        self._devices[dev.mac] = dev
        table = self.query_one("#bt-device-table", DataTable)
        table.clear()
        for d in self._devices.values():
            table.add_row(d.mac, d.name, d.device_type, d.vendor, d.device_class or "—")
        term = self.query_one("#bt-terminal", TerminalLog)
        term.write_line(f"[bold green]Discovered: {d.mac} ({d.name}) [{d.device_type}][/]")

    async def _monitor_scan(self) -> None:
        term = self.query_one("#bt-terminal", TerminalLog)
        try:
            if self._scan_task:
                res = await self._scan_task
                term.write_line(f"[bold green]✓ Scan complete: Found {len(res.devices)} Bluetooth devices.[/]")
        except Exception as e:
            term.write_line(f"[bold red]Scan error: {e}[/]")
        finally:
            self.query_one("#btn-bt-start", Button).disabled = False
            self.query_one("#btn-bt-stop", Button).disabled = True

    async def _stop_scan(self) -> None:
        if self._bt:
            self._bt.stop()
        if self._scan_task and not self._scan_task.done():
            self._scan_task.cancel()
        self.query_one("#btn-bt-start", Button).disabled = False
        self.query_one("#btn-bt-stop", Button).disabled = True
        self.query_one("#bt-terminal", TerminalLog).write_line("[bold red]Bluetooth scan stopped.[/]")

    def action_go_back(self) -> None:
        self.app.pop_screen()
