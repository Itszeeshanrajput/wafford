from __future__ import annotations

from typing import TYPE_CHECKING

from textual.widget import Widget
from textual.widgets import Static

if TYPE_CHECKING:
    from textual.app import ComposeResult


class TooltipWidget(Widget):
    CSS = """
    TooltipWidget {
        width: auto;
        height: auto;
        layer: tooltip;
        display: none;
        offset-y: 1;
    }
    TooltipWidget.visible {
        display: block;
    }
    #tip-box {
        width: auto;
        max-width: 50;
        height: auto;
        padding: 0 1;
        border: solid $muted;
        background: $surface;
        color: $muted;
    }
    """

    def __init__(self, text: str = "", **kwargs) -> None:
        super().__init__(**kwargs)
        self.tip_text = text

    def compose(self) -> ComposeResult:
        yield Static(self.tip_text, id="tip-box")

    def set_text(self, text: str) -> None:
        self.tip_text = text
        try:
            self.query_one("#tip-box", Static).update(text)
        except Exception:
            pass

    def show_tooltip(self) -> None:
        self.add_class("visible")

    def hide_tooltip(self) -> None:
        self.remove_class("visible")


def make_tooltip(target: Widget, text: str) -> TooltipWidget:
    tip = TooltipWidget(text)
    target.tooltip = text
    return tip
