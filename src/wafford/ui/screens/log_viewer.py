# ruff: noqa: SLF001
from __future__ import annotations

import datetime
from typing import TYPE_CHECKING, cast

from textual import on
from textual.containers import Horizontal, Vertical
from textual.screen import Screen
from textual.widgets import Button, Input, Select, Static

if TYPE_CHECKING:
    from textual.app import ComposeResult

    from wafford.ui.app import WaffordApp


class LogViewer(Screen):
    CSS = """
    LogViewer {
        background: $background;
    }
    #lv-layout {
        width: 100%;
        height: 100%;
        padding: 1 2;
    }
    #lv-header {
        width: 100%;
        height: 3;
        color: $primary;
        text-style: bold;
        text-align: center;
        margin-bottom: 1;
    }
    #lv-toolbar {
        width: 100%;
        height: 3;
        layout: horizontal;
        margin-bottom: 1;
    }
    #lv-toolbar Button {
        margin-right: 1;
        min-width: 12;
    }
    #lv-search {
        width: 1fr;
    }
    #lv-level {
        width: 15;
    }
    #lv-log-area {
        width: 100%;
        height: 1fr;
        border: solid $muted;
        background: $surface;
        padding: 1;
        overflow-y: auto;
    }
    #lv-status {
        width: 100%;
        height: 1;
        color: $muted;
        text-align: right;
        margin-top: 1;
    }
    .log-entry {
        width: 100%;
        height: auto;
    }
    .log-timestamp {
        color: $muted;
    }
    .log-debug {
        color: $muted;
    }
    .log-info {
        color: $secondary;
    }
    .log-warning {
        color: $warning;
    }
    .log-error {
        color: $error;
    }
    """

    BINDINGS = [
        ("escape", "go_back", "Back"),
        ("ctrl+e", "export_logs", "Export"),
        ("ctrl+x", "clear_logs", "Clear"),
    ]

    @property
    def app(self) -> WaffordApp:  # type: ignore[override]
        return cast("WaffordApp", super().app)

    def __init__(self, **kwargs) -> None:
        super().__init__(**kwargs)
        now = datetime.datetime.now(datetime.UTC)
        base = now - datetime.timedelta(hours=2)
        raw = [
            (0, "INFO", "Wafford initialized successfully"),
            (2, "INFO", "Loading configuration from ~/.config/wafford/config.json"),
            (5, "DEBUG", "Checking root permissions... OK"),
            (7, "INFO", "Detected interfaces: wlan0, wlan1, eth0"),
            (10, "WARNING", "wlan1 has weak signal — may cause issues"),
            (15, "INFO", "Tools found: aircrack-ng, hashcat, reaver, mdk4, bettercap"),
            (18, "DEBUG", "Loading plugins... wpa3-analyzer, auto-recon"),
            (22, "INFO", "Database initialized: 847 networks in history"),
            (30, "ERROR", "Failed to connect to update server — retrying..."),
            (35, "INFO", "Update server reachable — version 1.0.0 is latest"),
            (40, "WARNING", "Monitor mode requires kernel 5.10+ for full feature support"),
            (45, "DEBUG", "UI theme loaded: DARK"),
            (50, "INFO", "TUI ready — main menu mounted"),
        ]
        self._entries: list[dict] = [
            {
                "time": (base + datetime.timedelta(seconds=sec)).strftime("%H:%M:%S"),
                "level": lvl,
                "msg": msg,
            }
            for sec, lvl, msg in raw
        ]
        self._filter_level = "ALL"
        self._search_term = ""

    def compose(self) -> ComposeResult:
        with Vertical(id="lv-layout"):
            yield Static("📋  Log Viewer", id="lv-header")
            with Horizontal(id="lv-toolbar"):
                yield Input(placeholder="Search logs...", id="lv-search")
                yield Select(
                    [
                        ("All", "ALL"),
                        ("DEBUG", "DEBUG"),
                        ("INFO", "INFO"),
                        ("WARNING", "WARNING"),
                        ("ERROR", "ERROR"),
                    ],
                    value="ALL",
                    id="lv-level",
                )
                yield Button("📄  Export", id="export-btn", variant="default")
                yield Button("🗑  Clear", id="clear-btn", variant="error")
                yield Button("←  Back", id="back-btn", variant="default")
            yield Vertical(id="lv-log-area")
            yield Static(f"{len(self._entries)} entries", id="lv-status")

    def on_mount(self) -> None:
        self._render_logs()

    def _render_logs(self) -> None:
        area = self.query_one("#lv-log-area")
        area.remove_children()
        entries = self._get_filtered()
        for entry in entries:
            lvl = entry["level"].lower()
            ts = entry["time"]
            msg = entry["msg"]
            line = Static(f"[{ts}] [{entry['level']:>7}] {msg}", classes=f"log-entry log-{lvl}")
            area.mount(line)
        self.query_one("#lv-status", Static).update(
            f"{len(entries)} entries shown ({len(self._total())} total)"
        )

    def _total(self) -> list[dict]:
        return self._entries

    def _get_filtered(self) -> list[dict]:
        result = self._entries
        if self._filter_level != "ALL":
            result = [e for e in result if e["level"] == self._filter_level]
        if self._search_term:
            term = self._search_term.lower()
            result = [e for e in result if term in e["msg"].lower() or term in e["level"].lower()]
        return result

    @on(Input.Changed, "#lv-search")
    def on_search(self, event: Input.Changed) -> None:
        self._search_term = event.value
        self._render_logs()

    @on(Select.Changed, "#lv-level")
    def on_level_filter(self, event: Select.Changed) -> None:
        self._filter_level = str(event.value or "ALL")
        self._render_logs()

    @on(Button.Pressed, "#export-btn")
    def on_export(self, _event: Button.Pressed) -> None:
        self.app._notify(f"Exported {len(self._entries)} log entries", level="success")

    @on(Button.Pressed, "#clear-btn")
    def on_clear(self, _event: Button.Pressed) -> None:
        self._entries.clear()
        self._render_logs()
        self.app._notify("Logs cleared", level="warning")

    @on(Button.Pressed, "#back-btn")
    def on_back(self, _event: Button.Pressed) -> None:
        self.action_go_back()

    def action_go_back(self) -> None:
        self.app.pop_screen()

    def action_export_logs(self) -> None:
        self.on_export(None)  # type: ignore[arg-type]

    def action_clear_logs(self) -> None:
        self.on_clear(None)  # type: ignore[arg-type]
