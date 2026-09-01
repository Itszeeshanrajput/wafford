from __future__ import annotations

from typing import TYPE_CHECKING, Any

from textual import on
from textual.containers import Horizontal
from textual.widget import Widget
from textual.widgets import Input, Select, Static

from wafford.ui.widgets.table import StyledDataTable

if TYPE_CHECKING:
    from collections.abc import Callable

    from textual.app import ComposeResult


class ScanResults(Widget):
    CSS = """
    ScanResults {
        width: 100%;
        height: 1fr;
    }
    #filter-row {
        width: 100%;
        height: 3;
        layout: horizontal;
        margin-bottom: 1;
    }
    #search-input {
        width: 1fr;
    }
    #enc-filter {
        width: 15;
    }
    #signal-filter {
        width: 15;
    }
    #results-table {
        width: 100%;
        height: 1fr;
    }
    #result-count {
        width: 100%;
        height: 1;
        color: $muted;
        text-align: right;
    }
    """

    def __init__(
        self,
        on_select: Callable[[str], None] | None = None,
        **kwargs,
    ) -> None:
        super().__init__(**kwargs)
        self._on_select = on_select
        self._all_rows: list[list[Any]] = []

    def compose(self) -> ComposeResult:
        with Horizontal(id="filter-row"):
            yield Input(placeholder="Search networks...", id="search-input")
            enc_options = [
                ("All", "all"),
                ("WPA3", "WPA3"),
                ("WPA2", "WPA2"),
                ("WPA", "WPA"),
                ("WEP", "WEP"),
                ("Open", "OPN"),
            ]
            yield Select(enc_options, value="all", id="enc-filter", prompt="Encryption")
            yield Select(
                [("All", "all"), (">70%", "70"), (">50%", "50"), (">30%", "30")],
                value="all",
                id="signal-filter",
                prompt="Signal",
            )
        table = StyledDataTable(id="results-table")
        table.add_columns("#", "BSSID", "ESSID", "Ch", "Enc", "Signal", "WPS", "Vendor", "Clients")
        yield table
        yield Static("0 networks found", id="result-count")

    def set_results(self, networks: list[dict]) -> None:
        self._all_rows = []
        table = self.query_one("#results-table", StyledDataTable)
        table.clear()
        for i, net in enumerate(networks, 1):
            row = [
                str(i),
                net.get("bssid", "??"),
                net.get("essid", "<Hidden>"),
                str(net.get("channel", "?")),
                net.get("encryption", "?"),
                str(net.get("signal", 0)),
                "Yes" if net.get("wps") else "No",
                net.get("vendor", ""),
                str(net.get("clients", 0)),
            ]
            self._all_rows.append(row)
            key = net.get("bssid", str(i))
            table.add_row(*row, key=key)
        self.query_one("#result-count", Static).update(f"{len(networks)} networks found")

    def add_network(self, network: dict) -> None:
        table = self.query_one("#results-table", StyledDataTable)
        idx = len(self._all_rows) + 1
        row = [
            str(idx),
            network.get("bssid", "??"),
            network.get("essid", "<Hidden>"),
            str(network.get("channel", "?")),
            network.get("encryption", "?"),
            str(network.get("signal", 0)),
            "Yes" if network.get("wps") else "No",
            network.get("vendor", ""),
            str(network.get("clients", 0)),
        ]
        self._all_rows.append(row)
        key = network.get("bssid", str(idx))
        table.add_row(*row, key=key)
        count = len(self._all_rows)
        self.query_one("#result-count", Static).update(f"{count} networks found")

    def clear_results(self) -> None:
        self._all_rows.clear()
        table = self.query_one("#results-table", StyledDataTable)
        table.clear()
        self.query_one("#result-count", Static).update("0 networks found")

    def _apply_filters(self) -> None:
        search = self.query_one("#search-input", Input).value.lower()
        enc_filter = self.query_one("#enc-filter", Select).value
        sig_filter = self.query_one("#signal-filter", Select).value

        table = self.query_one("#results-table", StyledDataTable)
        table.clear()
        shown = 0
        for row in self._all_rows:
            if search and not any(search in cell.lower() for cell in row):
                continue
            if enc_filter and enc_filter != "all" and row[4] != enc_filter:
                continue
            if sig_filter and sig_filter != "all":
                try:
                    sig = int(row[5])
                    threshold = int(sig_filter)
                    if sig < threshold:
                        continue
                except (ValueError, IndexError):
                    pass
            shown += 1
            key = row[1]
            table.add_row(*row, key=key)
        self.query_one("#result-count", Static).update(f"{shown} networks shown")

    @on(Input.Changed, "#search-input")
    def on_search(self, event: Input.Changed) -> None:
        del event
        self._apply_filters()

    @on(Select.Changed, "#enc-filter")
    def on_enc_filter(self, event: Select.Changed) -> None:
        del event
        self._apply_filters()

    @on(Select.Changed, "#signal-filter")
    def on_sig_filter(self, event: Select.Changed) -> None:
        del event
        self._apply_filters()

    def set_row_callback(self, callback: Callable[[str], None]) -> None:
        table = self.query_one("#results-table", StyledDataTable)
        table.set_row_callback(callback)

    def get_selected(self) -> str | None:
        table = self.query_one("#results-table", StyledDataTable)
        return table.get_selected_row()
