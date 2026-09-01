from __future__ import annotations

from pathlib import Path
from typing import TYPE_CHECKING, Optional

from textual import on
from textual.containers import Horizontal, Vertical
from textual.screen import ModalScreen
from textual.widgets import Button, DataTable, Input, Static

if TYPE_CHECKING:
    from textual.app import ComposeResult


class FilePicker(ModalScreen[Optional[Path]]):
    CSS = """
    FilePicker {
        align: center middle;
    }
    #picker-box {
        width: 80;
        height: 40;
        max-width: 95%;
        max-height: 90%;
        border: thick $primary;
        background: $surface;
        padding: 1 2;
    }
    #current-path {
        width: 100%;
        color: $secondary;
        height: 1;
        margin-bottom: 1;
    }
    #filter-input {
        width: 100%;
        margin-bottom: 1;
    }
    #file-table {
        width: 100%;
        height: 1fr;
        margin-bottom: 1;
    }
    #buttons {
        width: 100%;
        align: right middle;
    }
    Button {
        margin-left: 1;
        min-width: 10;
    }
    """

    BINDINGS = [
        ("escape", "cancel", "Cancel"),
        ("enter", "select", "Select"),
        ("backspace", "go_up", "Up"),
    ]

    def __init__(
        self,
        start_path: str = ".",
        filter_extensions: list[str] | None = None,
        title: str = "Select File",
    ) -> None:
        super().__init__()
        self.current_dir = Path(start_path).resolve()
        self.filter_exts = [e.lower() if e.startswith(".") else f".{e.lower()}" for e in (filter_extensions or [])]
        self.title_text = title
        self.selected_file: Path | None = None

    def compose(self) -> ComposeResult:
        with Vertical(id="picker-box"):
            yield Static(f"📂 {self.title_text}", id="title", classes="bold")
            yield Static(str(self.current_dir), id="current-path")
            yield Input(placeholder="Filter by extension...", id="filter-input")
            dt = DataTable(id="file-table")
            dt.add_columns("Name", "Size", "Modified")
            yield dt
            with Horizontal(id="buttons"):
                yield Button("Open", variant="primary", id="open")
                yield Button("Select", variant="success", id="select")
                yield Button("Cancel", variant="default", id="cancel")

    def on_mount(self) -> None:
        self._load_directory()

    def _load_directory(self) -> None:
        table = self.query_one("#file-table", DataTable)
        table.clear()
        self.query_one("#current-path", Static).update(str(self.current_dir))

        entries: list[tuple[str, str, str, bool]] = []
        try:
            for entry in sorted(self.current_dir.iterdir(), key=lambda e: (not e.is_dir(), e.name.lower())):
                name = entry.name
                if entry.is_dir():
                    entries.append((f"📁 {name}/", "-", "-", True))
                else:
                    ext = entry.suffix.lower()
                    if self.filter_exts and ext not in self.filter_exts:
                        continue
                    size = self._format_size(entry.stat().st_size)
                    mtime = self._format_time(entry.stat().st_mtime)
                    entries.append((f"📄 {name}", size, mtime, False))
        except PermissionError:
            pass

        for name, size, mtime, _is_dir in entries:
            table.add_row(name, size, mtime, key=name)

    @staticmethod
    def _format_size(size: int) -> str:
        for unit in ("B", "KB", "MB", "GB"):
            if size < 1024:
                return f"{size:.1f} {unit}"
            size /= 1024
        return f"{size:.1f} TB"

    @staticmethod
    def _format_time(ts: float) -> str:
        import datetime
        return datetime.datetime.fromtimestamp(ts).strftime("%Y-%m-%d %H:%M")

    @on(DataTable.RowSelected, "#file-table")
    def on_row_selected(self, event: DataTable.RowSelected) -> None:
        if event.row_key and event.row_key.value:
            name = str(event.row_key.value)
            clean = name.lstrip("📁📄 ").rstrip("/")
            if name.startswith("📁"):
                self.current_dir = self.current_dir / clean
                self._load_directory()
            else:
                self.selected_file = self.current_dir / clean

    def on_button_pressed(self, event: Button.Pressed) -> None:
        if event.button.id == "open":
            table = self.query_one("#file-table", DataTable)
            if table.cursor_row is not None:
                rows = list(table.rows.keys())
                if rows and table.cursor_row < len(rows):
                    name = str(rows[table.cursor_row])
                    clean = name.lstrip("📁📄 ").rstrip("/")
                    if name.startswith("📁"):
                        self.current_dir = self.current_dir / clean
                        self._load_directory()
                        return
                    self.selected_file = self.current_dir / clean
                    self.dismiss(self.selected_file)
        elif event.button.id == "select":
            if self.selected_file:
                self.dismiss(self.selected_file)
            else:
                table = self.query_one("#file-table", DataTable)
                rows = list(table.rows.keys())
                if rows and table.cursor_row is not None and table.cursor_row < len(rows):
                    name = str(rows[table.cursor_row])
                    clean = name.lstrip("📁📄 ").rstrip("/")
                    if not name.startswith("📁"):
                        self.dismiss(self.current_dir / clean)
        elif event.button.id == "cancel":
            self.dismiss(None)

    def action_select(self) -> None:
        if self.selected_file:
            self.dismiss(self.selected_file)

    def action_go_up(self) -> None:
        parent = self.current_dir.parent
        if parent != self.current_dir:
            self.current_dir = parent
            self._load_directory()

    def action_cancel(self) -> None:
        self.dismiss(None)

    @on(Input.Changed, "#filter-input")
    def on_filter_changed(self, event: Input.Changed) -> None:
        ext = event.value.strip().lower()
        if ext and not ext.startswith("."):
            ext = f".{ext}"
        self.filter_exts = [ext] if ext else []
        self._load_directory()
