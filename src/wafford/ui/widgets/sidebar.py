from __future__ import annotations

from typing import TYPE_CHECKING

from textual import on
from textual.containers import ScrollableContainer
from textual.widget import Widget
from textual.widgets import Button, Static

if TYPE_CHECKING:
    from collections.abc import Callable

    from textual.app import ComposeResult

CATEGORIES = {
    "Recon": [
        ("Interface Mgmt", "interface_menu"),
        ("Network Scan", "scan_menu"),
        ("Bluetooth Recon", "bluetooth_menu"),
        ("WiFi Direct", "wifi_direct_menu"),
    ],
    "Attacks": [
        ("Deauth/DoS", "deauth_menu"),
        ("Evil Twin", "evil_twin_menu"),
        ("Captive Portal", "captive_portal_menu"),
        ("WPA Attacks", "wpa_menu"),
        ("WEP Attacks", "wep_menu"),
        ("Karma/Mana", "karma_menu"),
    ],
    "Advanced": [
        ("Enterprise 802.1X", "enterprise_menu"),
        ("Password Crack", "crack_menu"),
        ("PMKID Attack", "pmkid_menu"),
    ],
    "Tools": [
        ("Wordlists", "wordlist_menu"),
        ("Plugins", "plugin_menu"),
        ("Reports", "report_menu"),
    ],
    "System": [
        ("Settings", "settings_menu"),
        ("Logs", "log_viewer"),
        ("Dependencies", "dep_manager"),
        ("Updates", "update_menu"),
    ],
}


class Sidebar(Widget):
    CSS = """
    Sidebar {
        width: 30;
        height: 100%;
        background: $surface;
        border-right: solid $muted;
        padding: 1 0;
    }
    #sidebar-title {
        width: 100%;
        text-align: center;
        color: $primary;
        text-style: bold;
        height: 1;
        margin-bottom: 1;
    }
    #sidebar-scroll {
        width: 100%;
        height: 1fr;
    }
    .category-label {
        width: 100%;
        color: $accent;
        text-style: bold;
        height: 1;
        padding: 0 1;
        margin-top: 1;
    }
    .sidebar-btn {
        width: 100%;
        height: 1;
        background: transparent;
        color: $text;
        text-align: left;
        border: none;
        padding: 0 1 0 2;
        margin: 0;
    }
    .sidebar-btn:hover {
        background: $primary 20%;
        color: $primary;
    }
    .sidebar-btn.active {
        background: $primary 30%;
        color: $primary;
        text-style: bold;
    }
    """

    def __init__(self, on_navigate: Callable[[str], None] | None = None, **kwargs) -> None:
        super().__init__(**kwargs)
        self._on_navigate = on_navigate
        self._active_item: str = ""

    def compose(self) -> ComposeResult:
        yield Static("WAFFORD", id="sidebar-title")
        with ScrollableContainer(id="sidebar-scroll"):
            for category, items in CATEGORIES.items():
                yield Static(f"── {category} ──", classes="category-label")
                for name, screen_id in items:
                    btn = Button(name, classes="sidebar-btn", id=f"nav-{screen_id}")
                    btn._screen_target = screen_id  # type: ignore[attr-defined]
                    yield btn

    @on(Button.Pressed, ".sidebar-btn")
    def on_nav_click(self, event: Button.Pressed) -> None:
        screen_id = getattr(event.button, "_screen_target", None)
        if screen_id and self._on_navigate:
            self._on_navigate(screen_id)
        self._set_active(event.button.id or "")

    def _set_active(self, btn_id: str) -> None:
        if self._active_item:
            try:
                old = self.query_one(f"#{self._active_item}", Button)
                old.remove_class("active")
            except Exception:
                pass
        self._active_item = btn_id
        try:
            new = self.query_one(f"#{btn_id}", Button)
            new.add_class("active")
        except Exception:
            pass

    def set_active(self, screen_id: str) -> None:
        btn_id = f"nav-{screen_id}"
        self._set_active(btn_id)
