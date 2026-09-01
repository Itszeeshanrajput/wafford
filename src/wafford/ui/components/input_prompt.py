from __future__ import annotations

from typing import TYPE_CHECKING, Optional

from textual import on
from textual.containers import Horizontal, Vertical
from textual.screen import ModalScreen
from textual.widgets import Button, Input, Label, Static

if TYPE_CHECKING:
    from collections.abc import Callable

    from textual.app import ComposeResult


class InputPrompt(ModalScreen[Optional[str]]):
    CSS = """
    InputPrompt {
        align: center middle;
    }
    #prompt-box {
        width: 60;
        max-width: 90%;
        height: auto;
        border: thick $primary;
        background: $surface;
        padding: 1 2;
    }
    #prompt-label {
        width: 100%;
        color: $text;
        margin-bottom: 1;
    }
    #prompt-input {
        width: 100%;
        margin-bottom: 1;
    }
    #error-label {
        width: 100%;
        color: $error;
        height: 1;
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
        ("enter", "submit", "Submit"),
    ]

    VARIANTS = {
        "text": {},
        "number": {"type": "number"},
        "password": {"password": True},
        "filepath": {},
    }

    def __init__(
        self,
        label: str = "Enter value:",
        placeholder: str = "",
        default: str = "",
        variant: str = "title",
        validator: Callable[[str], bool] | None = None,
        error_message: str = "Invalid input",
    ) -> None:
        super().__init__()
        self.label_text = label
        self.placeholder_text = placeholder
        self.default_value = default
        self.variant = variant
        self.validator_fn = validator
        self.error_message_text = error_message
        self.result_value: str | None = None

    def compose(self) -> ComposeResult:
        v = self.VARIANTS.get(self.variant, {})
        with Vertical(id="prompt-box"):
            yield Label(self.label_text, id="prompt-label")
            yield Input(
                placeholder=self.placeholder_text,
                value=self.default_value,
                id="prompt-input",
                **v,
            )
            yield Static("", id="error-label")
            with Horizontal(id="buttons"):
                yield Button("OK", variant="primary", id="ok")
                yield Button("Cancel", variant="default", id="cancel")

    @on(Input.Changed, "#prompt-input")
    def on_input_changed(self, event: Input.Changed) -> None:
        self.query_one("#error-label", Static).update("")

    def action_submit(self) -> None:
        self._try_submit()

    def _try_submit(self) -> None:
        val = self.query_one("#prompt-input", Input).value.strip()
        if self.validator_fn and not self.validator_fn(val):
            self.query_one("#error-label", Static).update(self.error_message_text)
            return
        self.result_value = val if val else None
        self.dismiss(val if val else None)

    def on_button_pressed(self, event: Button.Pressed) -> None:
        if event.button.id == "ok":
            self._try_submit()
        else:
            self.result_value = None
            self.dismiss(None)

    def action_cancel(self) -> None:
        self.result_value = None
        self.dismiss(None)
