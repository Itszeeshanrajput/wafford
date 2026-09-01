from __future__ import annotations

from typing import TYPE_CHECKING

from textual.containers import Horizontal, Vertical
from textual.screen import ModalScreen
from textual.widgets import Button, Label, Static

if TYPE_CHECKING:
    from textual.app import ComposeResult


class ConfirmDialog(ModalScreen[bool]):
    CSS = """
    ConfirmDialog {
        align: center middle;
    }
    #dialog {
        width: 60;
        max-width: 90%;
        height: auto;
        max-height: 80%;
        border: thick $primary;
        background: $surface;
        padding: 1 2;
    }
    #message {
        width: 100%;
        min-height: 3;
        content-align: center middle;
        text-align: center;
        color: $text;
        margin-bottom: 1;
    }
    #buttons {
        width: 100%;
        align: center middle;
        height: auto;
    }
    Button {
        margin: 0 1;
        min-width: 12;
    }
    .destructive Button.#confirm {
        background: $error;
        color: $text;
    }
    """

    BINDINGS = [
        ("escape", "cancel", "Cancel"),
        ("enter", "confirm", "Confirm"),
    ]

    def __init__(
        self,
        message: str,
        title: str = "Confirm",
        destructive: bool = False,
        warning: bool = False,
    ) -> None:
        super().__init__()
        self.message_text = message
        self.title_text = title
        self.destructive = destructive
        self.warning = warning
        self.result = False

    def compose(self) -> ComposeResult:
        icon = "⚠" if self.warning else "ℹ"
        cls = "destructive" if self.destructive else ""
        with Vertical(id="dialog", classes=cls):
            yield Static(f"{icon} {self.title_text}", id="title", classes="bold")
            yield Label(self.message_text, id="message")
            with Horizontal(id="buttons"):
                confirm_label = "Delete" if self.destructive else "Yes"
                yield Button(confirm_label, variant="error" if self.destructive else "primary", id="confirm")
                yield Button("No", variant="default", id="cancel")

    def on_button_pressed(self, event: Button.Pressed) -> None:
        if event.button.id == "confirm":
            self.result = True
            self.dismiss(True)
        else:
            self.result = False
            self.dismiss(False)

    def action_confirm(self) -> None:
        self.result = True
        self.dismiss(True)

    def action_cancel(self) -> None:
        self.result = False
        self.dismiss(False)
