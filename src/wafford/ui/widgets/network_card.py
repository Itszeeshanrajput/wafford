from __future__ import annotations

from typing import TYPE_CHECKING

from textual import on
from textual.containers import Horizontal
from textual.widget import Widget
from textual.widgets import Button, Static

if TYPE_CHECKING:
    from collections.abc import Callable

    from textual.app import ComposeResult

SIGNAL_STYLES = {
    (80, 101): "#00ff9f",
    (60, 80): "#88c0d0",
    (40, 60): "#ffcc00",
    (20, 40): "#ff8800",
    (0, 20): "#ff3333",
}


def _signal_color(strength: int) -> str:
    for (lo, hi), color in SIGNAL_STYLES.items():
        if lo <= strength < hi:
            return color
    return "#ff3333"


def _signal_bar(strength: int) -> str:
    if strength >= 80:
        return "▂▄▆█"
    if strength >= 60:
        return "▂▄▆░"
    if strength >= 40:
        return "▂▄░░"
    if strength >= 20:
        return "▂░░░"
    return "░░░░"


class NetworkCard(Widget):
    CSS = """
    NetworkCard {
        width: 100%;
        height: auto;
        min-height: 5;
        margin: 0 0 1 0;
        padding: 0 1;
        border: solid $muted;
        background: $surface;
    }
    NetworkCard:hover {
        border: solid $primary;
        background: $surface 90%;
    }
    NetworkCard.selected {
        border: thick $accent;
        background: $surface;
    }
    #card-header {
        width: 100%;
        height: 1;
        layout: horizontal;
    }
    #card-essid {
        width: 1fr;
        color: $primary;
        text-style: bold;
    }
    #card-enc {
        width: auto;
        text-align: right;
    }
    #card-details {
        width: 100%;
        height: auto;
        layout: horizontal;
    }
    #card-bssid {
        width: 20;
        color: $text;
    }
    #card-channel {
        width: 10;
        color: $text;
    }
    #card-signal {
        width: 20;
        color: $text;
    }
    #card-extra {
        width: 1fr;
        text-align: right;
        color: $muted;
    }
    #card-badges {
        width: 100%;
        height: 1;
        layout: horizontal;
    }
    .badge {
        width: auto;
        padding: 0 1;
        margin-right: 1;
        color: $background;
        text-style: bold;
    }
    .badge-wps {
        background: $warning;
    }
    .badge-clients {
        background: $secondary;
    }
    """

    def __init__(
        self,
        essid: str = "",
        bssid: str = "",
        channel: int = 0,
        signal: int = 0,
        encryption: str = "",
        wps: bool = False,
        client_count: int = 0,
        vendor: str = "",
        bands: str = "",
        selectable: bool = True,
        on_select: Callable[[], None] | None = None,
        **kwargs,
    ) -> None:
        super().__init__(**kwargs)
        self.essid = essid
        self.bssid = bssid
        self.channel = channel
        self.signal = signal
        self.encryption = encryption
        self.wps = wps
        self.client_count = client_count
        self.vendor = vendor
        self.bands = bands
        self.selectable_card = selectable
        self.on_select = on_select
        self._selected = False

    def compose(self) -> ComposeResult:
        with Horizontal(id="card-header"):
            yield Static(self.essid or "<Hidden>", id="card-essid")
            yield Static(self.encryption, id="card-enc")
        with Horizontal(id="card-details"):
            yield Static(self.bssid, id="card-bssid")
            yield Static(f"Ch {self.channel}", id="card-channel")
            yield Static(f"{_signal_bar(self.signal)} {self.signal}%", id="card-signal")
            parts = []
            if self.vendor:
                parts.append(self.vendor)
            if self.bands:
                parts.append(self.bands)
            yield Static(" · ".join(parts), id="card-extra")
        with Horizontal(id="card-badges"):
            if self.wps:
                yield Static("WPS", classes="badge badge-wps")
            if self.client_count > 0:
                yield Static(f"{self.client_count} clients", classes="badge badge-clients")

    @on(Button.Pressed)
    def on_click(self, event: Button.Pressed) -> None:
        del event
        self._toggle_selected()
        if self.on_select:
            self.on_select()

    def _toggle_selected(self) -> None:
        if not self.selectable_card:
            return
        self._selected = not self._selected
        if self._selected:
            self.add_class("selected")
        else:
            self.remove_class("selected")

    def set_selected(self, selected: bool) -> None:
        self._selected = selected
        if selected:
            self.add_class("selected")
        else:
            self.remove_class("selected")

    @property
    def is_selected(self) -> bool:
        return self._selected
