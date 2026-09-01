"""Channel spectrum and utilization visualizer for Wafford."""

from __future__ import annotations

from typing import TYPE_CHECKING, Any

from rich.text import Text
from textual.reactive import reactive
from textual.widget import Widget
from textual.widgets import Static

from wafford.constants import WIFI_CHANNELS_2_4_GHZ, WIFI_CHANNELS_5_GHZ

if TYPE_CHECKING:
    from textual.app import ComposeResult


class SpectrumGraph(Widget):
    """Live visualizer for 2.4GHz and 5GHz WiFi channel utilization."""

    CSS = """
    SpectrumGraph {
        width: 100%;
        height: auto;
        min-height: 8;
        background: $surface;
        padding: 0 1;
        border: round $primary;
    }
    """

    band: reactive[str] = reactive("2.4GHz")
    channel_counts: reactive[dict[int, int]] = reactive(dict)

    def compose(self) -> ComposeResult:
        yield Static(id="spectrum-display")

    def update_networks(self, networks: list[dict[str, Any]]) -> None:
        """Update channel distribution from discovered networks."""
        counts: dict[int, int] = {}
        for net in networks:
            ch = net.get("channel", 0)
            if isinstance(ch, int) and ch > 0:
                counts[ch] = counts.get(ch, 0) + 1
        self.channel_counts = counts
        self._refresh_display()

    def watch_band(self, new_band: str) -> None:
        del new_band
        self._refresh_display()

    def watch_channel_counts(self, counts: dict[int, int]) -> None:
        del counts
        self._refresh_display()

    def _refresh_display(self) -> None:
        try:
            display = self.query_one("#spectrum-display", Static)
        except Exception:
            return

        channels = WIFI_CHANNELS_2_4_GHZ if self.band == "2.4GHz" else WIFI_CHANNELS_5_GHZ[:16]
        max_count = max(self.channel_counts.values(), default=1)
        if max_count == 0:
            max_count = 1

        t = Text()
        t.append(
            f"  ⚡ Channel Spectrum [{self.band}] — Utilization Heatmap\n\n",
            style="bold cyan",
        )

        # Render bar rows (height 4)
        for row in range(4, 0, -1):
            threshold = (row / 4.0) * max_count
            line = Text("    ")
            for ch in channels:
                count = self.channel_counts.get(ch, 0)
                if count >= threshold:
                    style = (
                        "bold red"
                        if count >= 5
                        else ("bold yellow" if count >= 3 else "bold green")
                    )
                    line.append("  █  ", style=style)
                elif count > 0 and (count >= ((row - 0.5) / 4.0) * max_count):
                    style = "yellow" if count >= 3 else "green"
                    line.append("  ▄  ", style=style)
                else:
                    line.append("  ·  ", style="dim")
            t.append_text(line)
            t.append("\n")

        # Channel numbers line
        t.append("    ", style="dim")
        for ch in channels:
            style = "bold white" if self.channel_counts.get(ch, 0) > 0 else "dim"
            t.append(f" {ch:^3} ", style=style)
        t.append("\n")

        # Count numbers line
        t.append("    ", style="dim")
        for ch in channels:
            c = self.channel_counts.get(ch, 0)
            cnt_str = f"({c})" if c > 0 else "   "
            t.append(f"{cnt_str:^5}", style="cyan" if c > 0 else "dim")
        t.append("\n")

        display.update(t)
