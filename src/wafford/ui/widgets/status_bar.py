from __future__ import annotations

import time
from typing import TYPE_CHECKING

from textual.reactive import reactive
from textual.widget import Widget
from textual.widgets import Static

if TYPE_CHECKING:
    from textual.app import ComposeResult


class StatusBar(Widget):
    # Textual loads reusable widget styles from DEFAULT_CSS.  A plain CSS
    # attribute is only applied to screens, so without this the status bar
    # expands to fill the screen and obscures the menu beneath it.
    DEFAULT_CSS = """
    StatusBar {
        dock: bottom;
        width: 100%;
        height: 1;
        background: $surface;
        color: $text;
        layout: horizontal;
    }
    #root-status {
        width: auto;
        padding: 0 1;
        color: $success;
    }
    #sep1, #sep2, #sep3, #sep4 {
        width: 1;
        color: $muted;
        text-align: center;
    }
    #iface-display {
        width: auto;
        padding: 0 1;
        color: $secondary;
    }
    #tools-count {
        width: auto;
        padding: 0 1;
        color: $text;
    }
    #session-time {
        width: auto;
        padding: 0 1;
        color: $muted;
    }
    #attack-status {
        width: 1fr;
        text-align: right;
        padding: 0 1;
        color: $accent;
    }
    """

    root_ok: reactive[bool] = reactive(True)
    interface_name: reactive[str] = reactive("none")
    interface_mode: reactive[str] = reactive("managed")
    tools_found: reactive[int] = reactive(0)
    tools_total: reactive[int] = reactive(0)
    attack_text: reactive[str] = reactive("idle")
    _session_start: float = 0.0

    def __init__(self, **kwargs) -> None:
        super().__init__(**kwargs)
        self._session_start = time.time()

    def compose(self) -> ComposeResult:
        yield Static("✓ root", id="root-status")
        yield Static("│", id="sep1")
        yield Static("wlan0 [managed]", id="iface-display")
        yield Static("│", id="sep2")
        yield Static("Tools: 0/0", id="tools-count")
        yield Static("│", id="sep3")
        yield Static("00:00:00", id="session-time")
        yield Static("│", id="sep4")
        yield Static("idle", id="attack-status")

    def on_mount(self) -> None:
        self.set_interval(1.0, self._tick)

    def _tick(self) -> None:
        elapsed = int(time.time() - self._session_start)
        h, rem = divmod(elapsed, 3600)
        m, s = divmod(rem, 60)
        try:
            self.query_one("#session-time", Static).update(f"{h:02d}:{m:02d}:{s:02d}")
        except Exception:
            pass

    def update_root(self, has_root: bool) -> None:
        self.root_ok = has_root
        label = "✓ root" if has_root else "✗ no-root"
        color = "$success" if has_root else "$error"
        el = self.query_one("#root-status", Static)
        el.update(label)
        el.styles.color = color

    def update_interface(self, name: str, mode: str = "managed") -> None:
        self.interface_name = name
        self.interface_mode = mode
        color = "$success" if mode == "monitor" else "$warning"
        el = self.query_one("#iface-display", Static)
        el.update(f"{name} [{mode}]")
        el.styles.color = color

    def update_tools(self, found: int, total: int) -> None:
        self.tools_found = found
        self.tools_total = total
        self.query_one("#tools-count", Static).update(f"Tools: {found}/{total}")

    def update_attack(self, status: str) -> None:
        self.attack_text = status
        el = self.query_one("#attack-status", Static)
        el.update(status)

    def reset_timer(self) -> None:
        self._session_start = time.time()

    @property
    def session_elapsed(self) -> float:
        return time.time() - self._session_start
