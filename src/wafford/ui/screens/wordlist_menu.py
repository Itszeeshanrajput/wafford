# ruff: noqa: SLF001
from __future__ import annotations

from typing import TYPE_CHECKING, Any, cast

from textual import on, work
from textual.containers import Horizontal, Vertical
from textual.screen import Screen
from textual.widgets import Button, DataTable, Static

from wafford.ui.widgets.progress import WaffordProgressBar
from wafford.wordlists.downloader import AVAILABLE_WORDLISTS, WordlistDownloader
from wafford.wordlists.manager import WordlistManager

if TYPE_CHECKING:
    from textual.app import ComposeResult

    from wafford.ui.app import WaffordApp

DOWNLOAD_ALIASES = {
    "rockyou.txt": "rockyou",
    "SecLists": "seclists_100k",
}


class WordlistMenu(Screen[None]):
    CSS = """
    WordlistMenu {
        background: $background;
    }
    #wl-layout {
        width: 100%;
        height: 100%;
        padding: 1 2;
    }
    #wl-header {
        width: 100%;
        height: 3;
        color: $primary;
        text-style: bold;
        text-align: center;
        margin-bottom: 1;
    }
    #wl-buttons {
        width: 100%;
        height: 3;
        layout: horizontal;
        margin-bottom: 1;
    }
    #wl-buttons Button {
        margin-right: 1;
        min-width: 12;
    }
    #wl-table {
        width: 100%;
        height: 8;
        margin-bottom: 1;
    }
    #wl-section-title {
        width: 100%;
        height: 1;
        color: $accent;
        text-style: bold;
        margin-bottom: 1;
    }
    #wl-preview {
        width: 100%;
        height: 1fr;
        border: solid $muted;
        background: $surface;
        padding: 1;
        color: $text;
        overflow-y: auto;
    }
    #wl-progress {
        width: 100%;
        height: 3;
        margin-bottom: 1;
    }
    """

    BINDINGS = [
        ("escape", "go_back", "Back"),
    ]

    @property
    def app(self) -> WaffordApp:  # type: ignore[override]
        return cast("WaffordApp", super().app)

    def __init__(self) -> None:
        super().__init__()
        self._wordlists: list[dict[str, Any]] = []
        self._manager = WordlistManager()

    def compose(self) -> ComposeResult:
        with Vertical(id="wl-layout"):
            yield Static("📝  Wordlist Manager", id="wl-header")
            with Horizontal(id="wl-buttons"):
                yield Button("⬇  Download rockyou", id="dl-rockyou", variant="primary")
                yield Button("⬇  Download SecLists", id="dl-seclists", variant="primary")
                yield Button("🔧  Generate", id="gen-btn", variant="success")
                yield Button("🔀  Merge", id="merge-btn", variant="default")
                yield Button("🗑  Deduplicate", id="dedup-btn", variant="default")
                yield Button("↕  Sort", id="sort-btn", variant="default")
                yield Button("←  Back", id="back-btn", variant="default")
            dt: DataTable[Any] = DataTable(id="wl-table")
            dt.add_columns("Name", "Path", "Size", "Words", "Avg Len", "Entropy")
            yield dt
            yield Static("Wordlist Preview (first 50 lines)", id="wl-section-title")
            yield Vertical(
                Static("Select a wordlist to preview...", id="preview-content"),
                id="wl-preview",
            )
            yield WaffordProgressBar(label="Idle", id="wl-progress")

    def _refresh_wordlists(self) -> None:
        try:
            infos = self._manager.list_wordlists()
        except Exception:
            infos = []
        self._wordlists = [i.to_dict() for i in infos]
        table = self.query_one("#wl-table", DataTable)
        table.clear()
        for wl in self._wordlists:
            table.add_row(
                wl["name"], wl["path"], wl["size_human"],
                f'{wl["word_count"]:,}', f'{wl["avg_length"]:.1f}', f'{wl["entropy"]:.1f}',
                key=wl["name"],
            )

    def on_mount(self) -> None:
        self._refresh_wordlists()

    @on(Button.Pressed, "#dl-rockyou")
    def on_dl_rockyou(self, _event: Button.Pressed) -> None:
        self.app._notify("Downloading rockyou.txt...", level="info")
        self._start_download("rockyou.txt")

    @on(Button.Pressed, "#dl-seclists")
    def on_dl_seclists(self, _event: Button.Pressed) -> None:
        self.app._notify("Downloading SecLists...", level="info")
        self._start_download("SecLists")

    def _start_download(self, label: str) -> None:
        key = DOWNLOAD_ALIASES.get(label, label)
        if key not in AVAILABLE_WORDLISTS:
            self.app._notify(f"Wordlist '{label}' is not available for download", level="error")
            self.query_one("#wl-progress", WaffordProgressBar).set_label("Not available")
            return
        self.query_one("#wl-progress", WaffordProgressBar).set_label(f"Downloading {label}...")
        self.query_one("#wl-progress", WaffordProgressBar).reset()
        self._download_worker(key, label)

    @work(thread=True)
    def _download_worker(self, key: str, label: str) -> None:
        progress = self.query_one("#wl-progress", WaffordProgressBar)
        try:
            downloader = WordlistDownloader(
                progress_callback=self._progress_callback,
            )
            result = downloader.download(key)
        except Exception as exc:
            self.app.call_from_thread(
                progress.set_label, f"Download failed: {exc}"
            )
            self.app.call_from_thread(
                self.app._notify, f"Download failed: {exc}", "error"
            )
            return
        if result is None:
            self.app.call_from_thread(
                progress.set_label, "Download unavailable (no network/tool)"
            )
            self.app.call_from_thread(
                self.app._notify,
                f"Download of {label} unavailable. Check network access.",
                "error",
            )
            return
        self.app.call_from_thread(
            progress.set_label, "Download complete"
        )
        self.app.call_from_thread(self.app._notify, f"{label} downloaded!", "success")
        self.app.call_from_thread(self._refresh_wordlists)

    def _progress_callback(self, _name: str, fraction: float, _message: str) -> None:
        progress = self.query_one("#wl-progress", WaffordProgressBar)
        self.app.call_from_thread(progress.update_progress, fraction * 100, 100)

    @on(Button.Pressed, "#gen-btn")
    def on_generate(self, _event: Button.Pressed) -> None:
        self.app._notify("Wordlist generator — enter base words and rules", level="info")

    @on(Button.Pressed, "#merge-btn")
    def on_merge(self, _event: Button.Pressed) -> None:
        self.app._notify("Select wordlists to merge", level="info")

    @on(Button.Pressed, "#dedup-btn")
    def on_dedup(self, _event: Button.Pressed) -> None:
        self.app._notify("Deduplicating wordlist...", level="info")

    @on(Button.Pressed, "#sort-btn")
    def on_sort(self, _event: Button.Pressed) -> None:
        self.app._notify("Wordlist sorted", level="success")

    @on(Button.Pressed, "#back-btn")
    def on_back(self, _event: Button.Pressed) -> None:
        self.action_go_back()

    def action_go_back(self) -> None:
        self.app.pop_screen()
