from __future__ import annotations

from typing import TYPE_CHECKING, Any

from rich.text import Text
from textual import on
from textual.widgets import DataTable

if TYPE_CHECKING:
    from collections.abc import Callable, Sequence


class StyledDataTable(DataTable):
    CSS = """
    StyledDataTable {
        background: $surface;
        color: $text;
        height: 1fr;
        width: 100%;
    }
    """

    SORT_ASC = "▲"
    SORT_DESC = "▼"

    def __init__(
        self,
        columns: Sequence[str] | None = None,
        *,
        sort_by: str | None = None,
        sortable: bool = True,
        zebra_stripes: bool = True,
        **kwargs,
    ) -> None:
        super().__init__(zebra_stripes=zebra_stripes, **kwargs)
        self.sortable = sortable
        self._sort_column: str | None = sort_by
        self._sort_reverse: bool = False
        self._row_callback: Callable[[str], None] | None = None
        self._columns_def = columns or []
        self._data_rows: list[list[Any]] = []

    def on_mount(self) -> None:
        for col in self._columns_def:
            self.add_columns(col)

    def set_columns(self, columns: Sequence[str]) -> None:
        self._columns_def = list(columns)
        for col in columns:
            self.add_columns(col)

    def populate(self, rows: Sequence[Sequence[Any]]) -> None:
        self.clear()
        self._data_rows = [list(r) for r in rows]
        for row in self._data_rows:
            self.add_row(*[str(c) for c in row])

    def add_row_data(self, row: Sequence[Any], key: str | None = None) -> None:
        self._data_rows.append(list(row))
        self.add_row(*[str(c) for c in row], key=key)

    def sort_by_column(self, column: str, reverse: bool = False) -> None:
        self._sort_column = column
        self._sort_reverse = reverse

    def format_signal_bar(self, strength: int) -> Text:
        if strength >= 80:
            bars = "▂▄▆█"
            color = "#00ff9f"
        elif strength >= 60:
            bars = "▂▄▆░"
            color = "#88c0d0"
        elif strength >= 40:
            bars = "▂▄░░"
            color = "#ffcc00"
        elif strength >= 20:
            bars = "▂░░░"
            color = "#ff8800"
        else:
            bars = "░░░░"
            color = "#ff3333"
        return Text(f"{bars} {strength}%", style=color)

    def format_encryption_badge(self, enc_type: str) -> Text:
        colors = {
            "WPA3": "#00ff9f",
            "WPA2": "#88c0d0",
            "WPA": "#ffcc00",
            "WEP": "#ff8800",
            "OPN": "#ff3333",
            "Open": "#ff3333",
        }
        color = colors.get(enc_type, "#888888")
        return Text(enc_type, style=f"bold {color}")

    def format_status_badge(self, status: str) -> Text:
        styles = {
            "active": "bold #00ff9f",
            "running": "bold #00ff9f",
            "found": "bold #00ff9f",
            "missing": "bold #ff3333",
            "error": "bold #ff3333",
            "warning": "bold #ffcc00",
            "disabled": "bold #555555",
            "inactive": "bold #555555",
            "idle": "bold #888888",
        }
        style = styles.get(status.lower(), "bold #888888")
        return Text(status, style=style)

    def set_row_callback(self, callback: Callable[[str], None]) -> None:
        self._row_callback = callback

    @on(DataTable.RowSelected)
    def on_row_selected(self, event: DataTable.RowSelected) -> None:
        if self._row_callback and event.row_key:
            self._row_callback(str(event.row_key.value))

    def get_selected_row(self) -> str | None:
        if self.cursor_row is not None:
            keys = list(self.rows.keys())
            if self.cursor_row < len(keys):
                return str(keys[self.cursor_row].value)
        return None

    def filter_rows(self, filter_fn: Callable[[list[Any]], bool]) -> None:
        filtered = [r for r in self._data_rows if filter_fn(r)]
        self.populate(filtered)
