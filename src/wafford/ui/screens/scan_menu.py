"""Network Scanner Screen for Wafford with Live Streaming and Channel Spectrum."""

from __future__ import annotations

import asyncio
import csv
from datetime import UTC, datetime
from pathlib import Path
from typing import TYPE_CHECKING, Any, cast

from rich.text import Text
from textual.containers import Container, Horizontal, Vertical
from textual.screen import Screen
from textual.widgets import Button, DataTable, Header, Input, ProgressBar, Select, Static

from wafford.core.scanner import NetworkScanner, ScanResult
from wafford.tools.detector import ToolDetector
from wafford.ui.app import WaffordApp
from wafford.ui.widgets.spectrum_graph import SpectrumGraph
from wafford.ui.widgets.status_bar import StatusBar

if TYPE_CHECKING:
    from textual.app import ComposeResult


class ScanMenu(Screen[None]):
    """Live WiFi network scanner screen with real hardware integration."""

    CSS = """
    ScanMenu {
        background: $background;
    }
    #scan-container {
        width: 100%;
        height: 1fr;
        padding: 1 2;
    }
    #scan-config-card {
        height: auto;
        margin-bottom: 1;
        padding: 1;
        background: $surface;
        border: round $primary;
    }
    .config-row {
        height: 3;
        margin-bottom: 1;
        layout: horizontal;
    }
    .config-item {
        width: 1fr;
        margin-right: 1;
    }
    #scan-buttons-row {
        height: 3;
        layout: horizontal;
    }
    #scan-buttons-row Button {
        margin-right: 1;
    }
    #scan-middle-row {
        height: auto;
        margin-bottom: 1;
    }
    #scan-table-box {
        height: 1fr;
    }
    #scan-results-table {
        height: 1fr;
        background: $surface;
    }
    """

    BINDINGS = [
        ("escape", "go_back", "Back"),
        ("f5", "start_scan", "Scan"),
        ("space", "select_target", "Select Target"),
    ]

    def __init__(self, **kwargs: Any) -> None:
        super().__init__(**kwargs)
        self._scanner: NetworkScanner | None = None
        self._networks: dict[str, dict[str, Any]] = {}
        self._scan_task: asyncio.Task[Any] | None = None

    def compose(self) -> ComposeResult:
        yield Header(show_clock=True)
        with Vertical(id="scan-container"):
            with Vertical(id="scan-config-card"):
                Static("📡 Wireless Network Scanner", classes="menu-title")
                with Horizontal(classes="config-row"):
                    yield Input(placeholder="Interface (e.g. wlan0mon)", id="scan-iface", value="wlan0mon", classes="config-item")
                    yield Input(placeholder="Duration (sec)", id="scan-duration", value="30", classes="config-item")
                    yield Select([("All Bands", "all"), ("2.4 GHz", "2.4GHz"), ("5 GHz", "5GHz")], value="all", id="scan-band-select", classes="config-item")

                with Horizontal(id="scan-buttons-row"):
                    yield Button("▶ Start Scan", id="btn-scan-start", variant="success")
                    yield Button("⏹ Stop", id="btn-scan-stop", variant="error", disabled=True)
                    yield Button("🎯 Target Attack", id="btn-scan-attack", variant="primary", disabled=True)
                    yield Button("💾 Save to DB", id="btn-scan-save", variant="default")
                    yield Button("📄 Export CSV", id="btn-scan-export", variant="default")
                    yield Button("← Back", id="btn-scan-back", variant="default")

            yield ProgressBar(id="scan-progress-bar", total=100, show_eta=False)
            with Vertical(id="scan-middle-row"):
                yield SpectrumGraph(id="spectrum-graph")

            with Container(id="scan-table-box"):
                yield DataTable(id="scan-results-table", zebra_stripes=True)

        yield StatusBar(id="status-bar")

    def on_mount(self) -> None:
        table = self.query_one("#scan-results-table", DataTable)
        table.cursor_type = "row"
        table.add_columns("#", "BSSID", "ESSID", "Ch", "Enc", "Signal", "WPS", "Vendor", "Clients")

        # Auto-fill available interfaces
        try:
            adapters = ToolDetector.check_wifi_adapter()
            if adapters:
                self.query_one("#scan-iface", Input).value = adapters[0]
        except Exception:
            pass

    async def on_button_pressed(self, event: Button.Pressed) -> None:
        bid = event.button.id
        if bid == "btn-scan-start":
            await self._start_scan()
        elif bid == "btn-scan-stop":
            await self._stop_scan()
        elif bid == "btn-scan-attack":
            self.action_select_target()
        elif bid == "btn-scan-save":
            await self._save_to_db()
        elif bid == "btn-scan-export":
            self._export_csv()
        elif bid == "btn-scan-back":
            self.action_go_back()

    async def _start_scan(self) -> None:
        iface = self.query_one("#scan-iface", Input).value.strip() or "wlan0mon"
        dur_str = self.query_one("#scan-duration", Input).value.strip()
        try:
            duration = int(dur_str)
        except ValueError:
            duration = 30

        self.query_one("#btn-scan-start", Button).disabled = True
        self.query_one("#btn-scan-stop", Button).disabled = False
        self.query_one("#btn-scan-attack", Button).disabled = True

        table = self.query_one("#scan-results-table", DataTable)
        table.clear()
        self._networks.clear()

        self._scanner = NetworkScanner(interface=iface)

        self._scan_task = asyncio.create_task(self._run_scan_task(duration))

    def _on_network_discovered(self, net: ScanResult) -> None:
        data = {
            "bssid": net.bssid,
            "essid": net.essid or "<Hidden>",
            "channel": net.channel,
            "encryption": net.encryption,
            "signal": net.signal_dbm,
            "wps": net.wps,
            "vendor": net.vendor,
            "clients": len(net.clients),
        }
        self._networks[net.bssid] = data
        self._update_table_and_graph()

    def _update_table_and_graph(self) -> None:
        table = self.query_one("#scan-results-table", DataTable)
        table.clear()
        for idx, net in enumerate(self._networks.values(), 1):
            sig = net["signal"]
            sig_style = "bold green" if sig > -60 else ("bold yellow" if sig > -75 else "bold red")
            sig_bar = "▂▄▆█" if sig > -50 else ("▂▄▆░" if sig > -65 else ("▂▄░░" if sig > -80 else "▂░░░"))

            table.add_row(
                str(idx),
                net["bssid"],
                net["essid"],
                str(net["channel"]),
                net["encryption"],
                Text(f"{sig_bar} {sig}dBm", style=sig_style),
                "YES" if net["wps"] else "NO",
                net["vendor"],
                str(net["clients"]),
                key=net["bssid"],
            )

        # Update Spectrum Graph
        try:
            spectrum = self.query_one("#spectrum-graph", SpectrumGraph)
            spectrum.update_networks(list(self._networks.values()))
        except Exception:
            pass

    async def _run_scan_task(self, duration: int) -> None:
        try:
            if self._scanner:
                async for net in self._scanner.scan(duration=duration):
                    self._on_network_discovered(net)
        except Exception as e:
            if hasattr(self.app, "notify"):
                self.app.notify(f"Scan error: {e}", severity="error")
        finally:
            self.query_one("#btn-scan-start", Button).disabled = False
            self.query_one("#btn-scan-stop", Button).disabled = True
            if self._networks:
                self.query_one("#btn-scan-attack", Button).disabled = False

    async def _stop_scan(self) -> None:
        if self._scanner:
            await self._scanner.stop()
        if self._scan_task and not self._scan_task.done():
            self._scan_task.cancel()
        self.query_one("#btn-scan-start", Button).disabled = False
        self.query_one("#btn-scan-stop", Button).disabled = True

    def on_data_table_row_selected(self, event: DataTable.RowSelected) -> None:
        if event.row_key and event.row_key.value in self._networks:
            net = self._networks[event.row_key.value]
            cast("WaffordApp", self.app).selected_network = net
            self.query_one("#btn-scan-attack", Button).disabled = False

    def action_select_target(self) -> None:
        table = self.query_one("#scan-results-table", DataTable)
        if table.cursor_row is not None and self._networks:
            row_keys = list(self._networks.keys())
            if 0 <= table.cursor_row < len(row_keys):
                bssid = row_keys[table.cursor_row]
                cast("WaffordApp", self.app).selected_network = self._networks[bssid]
                self.app.push_screen("AttackMenu")

    async def _save_to_db(self) -> None:
        if hasattr(self.app, "db_manager") and self.app.db_manager:
            for net in self._networks.values():
                await self.app.db_manager.add_network(
                    bssid=net["bssid"],
                    essid=net["essid"],
                    channel=net["channel"],
                    encryption=net["encryption"],
                    signal=net["signal"],
                )
            if hasattr(self.app, "notify"):
                self.app.notify(f"Saved {len(self._networks)} networks to database", severity="information")

    def _export_csv(self) -> None:
        out_dir = Path.home() / ".wafford" / "reports"
        out_dir.mkdir(parents=True, exist_ok=True)
        ts = datetime.now(UTC).strftime("%Y%m%d_%H%M%S")
        out_file = out_dir / f"scan_export_{ts}.csv"

        with open(out_file, "w", newline="", encoding="utf-8") as fh:
            writer = csv.DictWriter(fh, fieldnames=["bssid", "essid", "channel", "encryption", "signal", "wps", "vendor", "clients"])
            writer.writeheader()
            for net in self._networks.values():
                writer.writerow(net)

        if hasattr(self.app, "notify"):
            self.app.notify(f"Exported to {out_file}", severity="information")

    def action_go_back(self) -> None:
        self.app.pop_screen()
