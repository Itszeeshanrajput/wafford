from __future__ import annotations

import time
from typing import Any, Literal

from textual.app import App
from textual.binding import Binding
from textual.css.query import NoMatches

from wafford.ui.screens import SCREEN_CLASSES
from wafford.ui.theme import apply_theme, get_theme
from wafford.ui.widgets.sidebar import Sidebar
from wafford.ui.widgets.status_bar import StatusBar
from wafford.ui.widgets.toast import ToastWidget, get_toast_bridge

SCREEN_MAP: dict[str, str] = {
    "main_menu": "MainMenu",
    "attack_menu": "AttackMenu",
    "interface_menu": "InterfaceMgmt",
    "scan_menu": "NetworkScan",
    "deauth_menu": "DeauthDoS",
    "evil_twin_menu": "EvilTwin",
    "captive_portal_menu": "CaptivePortal",
    "wpa_menu": "WPAAttacks",
    "wep_menu": "WEPAttacks",
    "pmkid_menu": "PMKIDAttack",
    "karma_menu": "KarmaMana",
    "enterprise_menu": "Enterprise802X",
    "wifi_direct_menu": "WiFiDirect",
    "dos_menu": "DoSAttack",
    "bluetooth_menu": "BluetoothRecon",
    "crack_menu": "PasswordCrack",
    "wordlist_menu": "Wordlists",
    "plugin_menu": "Plugins",
    "report_menu": "Reports",
    "settings_menu": "Settings",
    "log_viewer": "LogViewer",
    "dep_manager": "DepManager",
    "update_menu": "UpdateMenu",
}


class WaffordApp(App[None]):
    CSS = """
    Screen {
        background: $background;
    }
    #app-layout {
        width: 100%;
        height: 100%;
    }
    #main-content {
        width: 1fr;
        height: 100%;
    }
    Header {
        background: $primary;
        color: $background;
    }
    Footer {
        background: $surface;
        color: $text;
    }
    """

    TITLE = "Wafford WiFi Auditing Framework"
    SUB_TITLE = "v1.0.0"

    BINDINGS = [
        Binding("ctrl+q", "quit", "Quit", show=True),
        Binding("ctrl+l", "open_logs", "Logs", show=True),
        Binding("ctrl+s", "open_settings", "Settings", show=True),
        Binding("ctrl+d", "open_deps", "Dependencies", show=True),
        Binding("f1", "show_help", "Help", show=True),
        Binding("f5", "refresh", "Refresh", show=True),
        Binding("ctrl+b", "toggle_sidebar", "Sidebar", show=True),
    ]

    def __init__(self, theme_name: str = "DARK", **kwargs) -> None:
        super().__init__(**kwargs)
        self.wafford_theme = get_theme(theme_name)
        apply_theme(self, theme_name)
        self.current_session: dict[str, Any] = {}
        self.selected_network: dict | None = None
        self.selected_interface: str | None = None
        self.attack_engine: Any = None
        self.db_manager: Any = None
        self.config: dict[str, Any] = {
            "theme": theme_name,
            "default_scan_duration": 30,
            "default_deauth_packets": 64,
            "wordlist_path": "/usr/share/wordlists",
            "log_level": "INFO",
            "auto_update": True,
            "language": "en",
        }
        self._session_start = time.time()
        self._toast_widget: ToastWidget | None = None

    def on_mount(self) -> None:
        for name, screen_cls in SCREEN_CLASSES.items():
            self.install_screen(screen_cls(), name)

        self._toast_widget = ToastWidget()
        try:
            self.mount(self._toast_widget)
        except Exception:
            pass

        try:
            status_bar = self.query_one("#status-bar", StatusBar)
            status_bar.update_root(True)
            status_bar.update_interface("wlan0", "managed")
            status_bar.update_tools(12, 15)
        except Exception:
            pass

        toast_bridge = get_toast_bridge()
        if self._toast_widget:
            toast_bridge.attach(self._toast_widget)
        toast_bridge.success("Wafford started successfully")

        self.push_screen("MainMenu")

    def _navigate_to(self, screen_id: str) -> None:
        screen_name = SCREEN_MAP.get(screen_id)
        if screen_name:
            try:
                self.push_screen(screen_name)
            except Exception:
                pass

    def get_toast(self) -> Any:
        return get_toast_bridge()

    def notify(
        self,
        message: str,
        *,
        title: str = "",
        severity: Literal["information", "warning", "error"] = "information",
        timeout: float | None = None,  # noqa: ARG002
        markup: bool = True,  # noqa: ARG002
    ) -> None:
        bridge = get_toast_bridge()
        bridge.show(message, level=severity, title=title or None)

    def _notify(self, message: str, level: str = "info", title: str | None = None) -> None:
        bridge = get_toast_bridge()
        if title:
            bridge.show(message, level=level, title=title)
        else:
            getattr(bridge, level, bridge.info)(message)

    async def action_quit(self) -> None:
        self.exit()

    def action_open_logs(self) -> None:
        self.push_screen("LogViewer")

    def action_open_settings(self) -> None:
        self.push_screen("Settings")

    def action_open_deps(self) -> None:
        self.push_screen("DepManager")

    def action_show_help(self) -> None:
        self._notify(
            "Wafford WiFi Auditing Framework v1.0.0\n"
            "Ctrl+Q: Quit | Ctrl+L: Logs | Ctrl+S: Settings | Ctrl+D: Deps\n"
            "F1: Help | F5: Refresh",
            level="info",
            title="Help",
        )

    def action_refresh(self) -> None:
        self._notify("Refreshed", level="info")

    def action_toggle_sidebar(self) -> None:
        try:
            sidebar = self.query_one("#sidebar", Sidebar)
            sidebar.display = not sidebar.display
        except NoMatches:
            pass

    def select_network(self, network: dict[str, Any]) -> None:
        self.selected_network = network
        self._notify(
            f"Selected: {network.get('essid', 'Unknown')} ({network.get('bssid', '')})",
            level="success",
        )

    def select_interface(self, iface: str) -> None:
        self.selected_interface = iface
        self._notify(f"Interface set: {iface}", level="info")

    @property
    def session_duration(self) -> float:
        return time.time() - self._session_start
