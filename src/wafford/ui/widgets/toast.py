from __future__ import annotations

import time
from typing import TYPE_CHECKING

from rich.text import Text
from textual.containers import Vertical
from textual.reactive import reactive
from textual.widget import Widget
from textual.widgets import Static

if TYPE_CHECKING:
    from textual.app import ComposeResult

TOAST_COLORS = {
    "success": ("#00ff9f", "#0a0e14"),
    "error": ("#ff3333", "#ffffff"),
    "warning": ("#ffcc00", "#0a0e14"),
    "info": ("#00b8ff", "#0a0e14"),
}

TOAST_ICONS = {
    "success": "✓",
    "error": "✗",
    "warning": "⚠",
    "info": "ℹ",
}


class ToastWidget(Widget):
    CSS = """
    ToastWidget {
        width: 100%;
        height: auto;
        max-height: 3;
        layer: toast;
        dock: top;
        offset-y: 0;
    }
    .toast-container {
        width: 50;
        height: auto;
        margin: 0 0 0 auto;
        padding: 0 1;
        layer: toast;
    }
    .toast-item {
        width: 100%;
        height: auto;
        padding: 0 1;
        margin: 0 0 1 0;
        layer: toast;
    }
    .toast-msg {
        width: 100%;
        height: 1;
        color: $text;
    }
    """

    _toasts: reactive[list[dict]] = reactive(list)

    def __init__(self, **kwargs) -> None:
        super().__init__(**kwargs)
        self._toast_data: list[dict] = []
        self._toast_id: int = 0
        self.max_toasts: int = 5
        self.default_duration: float = 3.0

    def compose(self) -> ComposeResult:
        with Vertical(classes="toast-container", id="toast-container"):
            yield Static("", id="toast-display")

    def show(
        self,
        message: str,
        level: str = "info",
        duration: float | None = None,
        title: str | None = None,
    ) -> None:
        dur = duration if duration is not None else self.default_duration
        self._toast_id += 1
        toast = {
            "id": self._toast_id,
            "message": message,
            "level": level,
            "title": title,
            "time": time.time(),
            "duration": dur,
        }
        self._toast_data.append(toast)
        if len(self._toast_data) > self.max_toasts:
            self._toast_data = self._toast_data[-self.max_toasts :]
        self._render_toasts()

    def success(self, message: str, **kwargs) -> None:
        self.show(message, level="success", **kwargs)

    def error(self, message: str, **kwargs) -> None:
        self.show(message, level="error", **kwargs)

    def warning(self, message: str, **kwargs) -> None:
        self.show(message, level="warning", **kwargs)

    def info(self, message: str, **kwargs) -> None:
        self.show(message, level="info", **kwargs)

    def _render_toasts(self) -> None:
        try:
            display = self.query_one("#toast-display", Static)
        except Exception:
            return
        now = time.time()
        active = [t for t in self._toast_data if (now - t["time"]) < t["duration"]]
        self._toast_data = active
        lines: list[Text] = []
        for t in active:
            icon = TOAST_ICONS.get(t["level"], "ℹ")
            fg, bg = TOAST_COLORS.get(t["level"], ("#ffffff", "#000000"))
            prefix = f"[{t['title']}] " if t["title"] else ""
            line = Text()
            line.append(f" {icon} {prefix}{t['message']} ", style=f"bold {fg} on {bg}")
            lines.append(line)
        if lines:
            combined = Text("\n")
            combined = lines[0]
            for line in lines[1:]:
                combined.append_text(Text("\n"))
                combined.append_text(line)
            display.update(combined)
        else:
            display.update("")

    def dismiss_all(self) -> None:
        self._toast_data.clear()
        self._render_toasts()

    def on_timer(self) -> None:
        self._render_toasts()


class ToastBridge:
    def __init__(self, widget: ToastWidget | None = None) -> None:
        self._widget = widget

    def attach(self, widget: ToastWidget) -> None:
        self._widget = widget

    def show(self, message: str, level: str = "info", **kwargs) -> None:
        if self._widget:
            self._widget.show(message, level=level, **kwargs)

    def success(self, message: str, **kwargs) -> None:
        self.show(message, level="success", **kwargs)

    def error(self, message: str, **kwargs) -> None:
        self.show(message, level="error", **kwargs)

    def warning(self, message: str, **kwargs) -> None:
        self.show(message, level="warning", **kwargs)

    def info(self, message: str, **kwargs) -> None:
        self.show(message, level="info", **kwargs)


_toast_bridge = ToastBridge()


def get_toast_bridge() -> ToastBridge:
    return _toast_bridge
