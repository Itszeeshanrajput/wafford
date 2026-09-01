"""Real-time streaming terminal log widget for Wafford attacks."""

from __future__ import annotations

from typing import TYPE_CHECKING

from textual.containers import Horizontal
from textual.widget import Widget
from textual.widgets import Button, RichLog, Static

if TYPE_CHECKING:
    from rich.text import Text
    from textual.app import ComposeResult


class TerminalLog(Widget):
    """Live streaming terminal log with ANSI colors, pause, and clear controls."""

    CSS = """
    TerminalLog {
        width: 100%;
        height: 100%;
        min-height: 8;
        background: $background;
        border: round $primary;
        padding: 0;
    }
    #term-header {
        height: 1;
        background: $surface;
        padding: 0 1;
        layout: horizontal;
    }
    #term-title {
        width: 1fr;
        color: $primary;
        text-style: bold;
    }
    #term-log-view {
        height: 1fr;
        background: $background;
        color: $text;
        overflow-y: scroll;
    }
    """

    def compose(self) -> ComposeResult:
        with Horizontal(id="term-header"):
            yield Static("📺 Live Execution Output", id="term-title")
            yield Button("Clear", id="btn-clear-term", variant="default")
        yield RichLog(id="term-log-view", highlight=True, markup=True, max_lines=1000)

    def write_line(self, line: str | Text) -> None:
        """Append a line to the terminal log."""
        try:
            log_view = self.query_one("#term-log-view", RichLog)
            log_view.write(line)
        except Exception:
            pass

    def on_button_pressed(self, event: Button.Pressed) -> None:
        if event.button.id == "btn-clear-term":
            try:
                self.query_one("#term-log-view", RichLog).clear()
            except Exception:
                pass
