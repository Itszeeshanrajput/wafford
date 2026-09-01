"""ModeGuard widget — inline monitor/managed mode banner for attack screens.

Drop ``yield ModeGuard(required="monitor")`` (or ``"managed"``) at the top of
any attack screen's ``compose()``.  It shows the current interface mode, warns
when it doesn't match what the attack needs, and provides a one-click switch
button — all without leaving the screen.
"""
from __future__ import annotations

from typing import TYPE_CHECKING

from textual import on, work
from textual.app import ComposeResult
from textual.containers import Horizontal
from textual.widget import Widget
from textual.widgets import Button, Static

if TYPE_CHECKING:
    pass

# Attacks that need monitor mode
MONITOR_MODE_ATTACKS = {
    "deauth", "wpa", "wep", "pmkid", "wps", "dos", "karma",
    "enterprise", "autopwn", "evil_twin",
}
# Attacks that need managed mode
MANAGED_MODE_ATTACKS = {"captive_portal", "wifi_direct", "crack"}


class ModeGuard(Widget):
    """Inline mode-check banner.  Shows current mode, required mode, switch button."""

    DEFAULT_CSS = """
    ModeGuard {
        width: 100%;
        height: 3;
        margin-bottom: 1;
    }
    #mg-row {
        width: 100%;
        height: 3;
        layout: horizontal;
        padding: 0 1;
    }
    #mg-status {
        width: 1fr;
        height: 3;
        content-align: left middle;
    }
    #mg-switch-btn {
        width: auto;
        min-width: 22;
        height: 3;
    }
    .mg-ok {
        background: $success 20%;
        border: solid $success;
        color: $success;
    }
    .mg-warn {
        background: $warning 20%;
        border: solid $warning;
        color: $warning;
    }
    """

    def __init__(self, required: str = "monitor", **kwargs: object) -> None:
        super().__init__(**kwargs)
        # "monitor" or "managed"
        self._required = required

    def compose(self) -> ComposeResult:
        with Horizontal(id="mg-row"):
            yield Static("", id="mg-status")
            yield Button("", id="mg-switch-btn", variant="default")

    def on_mount(self) -> None:
        self._refresh_state()

    def _current_mode(self) -> str:
        iface = getattr(self.app, "selected_interface", None) or ""
        if not iface:
            return "unknown"
        try:
            from pathlib import Path
            type_path = Path(f"/sys/class/net/{iface}/type")
            if type_path.exists():
                return "monitor" if type_path.read_text().strip() == "803" else "managed"
        except OSError:
            pass
        return "unknown"

    def _refresh_state(self) -> None:
        iface = getattr(self.app, "selected_interface", None) or "none"
        current = self._current_mode()
        ok = current == self._required or current == "unknown"

        status = self.query_one("#mg-status", Static)
        btn = self.query_one("#mg-switch-btn", Button)

        if ok:
            status.update(
                f"  ✓  Interface: [bold]{iface}[/]  |  Mode: [bold]{current.upper()}[/]"
                f"  (required: {self._required.upper()})"
            )
            self.remove_class("mg-warn")
            self.add_class("mg-ok")
            btn.label = "⟳ Refresh"
            btn.variant = "default"
        else:
            status.update(
                f"  ⚠  Interface: [bold]{iface}[/]  |  Mode: [bold red]{current.upper()}[/]"
                f"  — this attack needs [bold]{self._required.upper()}[/] mode!"
            )
            self.remove_class("mg-ok")
            self.add_class("mg-warn")
            btn.label = f"⚡ Switch to {self._required.upper()}"
            btn.variant = "warning" if self._required == "managed" else "success"

    @on(Button.Pressed, "#mg-switch-btn")
    def on_switch(self, event: Button.Pressed) -> None:
        current = self._current_mode()
        if current == self._required:
            self._refresh_state()
            return
        self._do_switch()

    @work(thread=True)
    def _do_switch(self) -> None:
        try:
            from wafford.core.interface import InterfaceManager
            mgr = InterfaceManager()
            if self._required == "monitor":
                adapter = mgr.auto_enable_monitor()
            else:
                adapter = mgr.auto_enable_managed()

            if adapter:
                self.app.call_from_thread(
                    setattr, self.app, "selected_interface", adapter.name
                )
                self.app.call_from_thread(self._refresh_state)
                self.app.call_from_thread(
                    self.app._notify,
                    f"✓ {adapter.name} → {self._required.upper()} mode",
                    "success",
                )
            else:
                self.app.call_from_thread(
                    self.app._notify, "No adapter found", "error"
                )
        except Exception as exc:
            self.app.call_from_thread(
                self.app._notify, f"Mode switch failed: {exc}", "error"
            )
