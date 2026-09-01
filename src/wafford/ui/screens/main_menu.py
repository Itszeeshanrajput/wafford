"""Modern Reactive Main Dashboard Screen for Wafford."""

from __future__ import annotations

import os
from typing import TYPE_CHECKING

from rich.text import Text
from textual import on
from textual.containers import Grid, Horizontal, Vertical
from textual.screen import Screen
from textual.widgets import Button, Header, Static

from wafford.tools.detector import ToolDetector
from wafford.ui.widgets.status_bar import StatusBar

if TYPE_CHECKING:
    from textual.app import ComposeResult

NAV_MAP = {
    "interface_menu": "InterfaceMgmt",
    "scan_menu": "NetworkScan",
    "autopwn_menu": "AutoPWN",
    "wps_menu": "WPSAttack",
    "wpa_menu": "WPAAttacks",
    "pmkid_menu": "PMKIDAttack",
    "crack_menu": "PasswordCrack",
    "deauth_menu": "DeauthDoS",
    "evil_twin_menu": "EvilTwin",
    "captive_portal_menu": "CaptivePortal",
    "karma_menu": "KarmaMana",
    "wep_menu": "WEPAttacks",
    "dos_menu": "DoSAttack",
    "bluetooth_menu": "BluetoothRecon",
    "enterprise_menu": "Enterprise802X",
    "wifi_direct_menu": "WiFiDirect",
    "wordlist_menu": "Wordlists",
    "report_menu": "Reports",
    "settings_menu": "Settings",
    "log_viewer": "LogViewer",
    "dep_manager": "DepManager",
    "update_menu": "UpdateMenu",
}


class MainMenu(Screen[None]):
    """Modern Cyberpunk / Dark Security Dashboard."""

    CSS = """
    MainMenu {
        background: $background;
    }
    #menu-layout {
        width: 100%;
        height: 1fr;
        padding: 1 2;
    }
    #header-section {
        width: 100%;
        height: auto;
        padding: 1;
        background: $surface;
        border: round $primary;
        margin-bottom: 1;
    }
    #app-title {
        color: $primary;
        text-style: bold;
        text-align: center;
    }
    #app-subtitle {
        color: $muted;
        text-align: center;
    }
    #telemetry-bar {
        width: 100%;
        height: 3;
        layout: horizontal;
        margin-bottom: 1;
        background: $surface;
        padding: 0 1;
    }
    .telemetry-pill {
        width: auto;
        padding: 0 2;
        text-align: center;
        border-right: solid $muted;
    }
    #menu-grid {
        width: 100%;
        height: 1fr;
        grid-size: 4 4;
        grid-gutter: 1 1;
    }
    .menu-card {
        width: 100%;
        height: 100%;
        min-height: 5;
        background: $surface;
        border: tall $muted;
        color: $text;
        text-align: center;
        padding: 1;
    }
    .menu-card:hover {
        border: tall $primary;
        background: $surface 85%;
    }
    .menu-card.-primary-card {
        border: tall $accent;
    }
    """

    BINDINGS = [
        ("escape", "back_to_self", "Menu"),
        ("ctrl+k", "open_palette", "Command Palette"),
    ]

    MENU_ITEMS = [
        ("🤖", "Auto-PWN Pipeline", "1-Click Autonomous Audit", "autopwn_menu", True),
        ("📡", "Network Scanner", "Live Channel Spectrum", "scan_menu", True),
        ("⚡", "WPS Pixie Dust", "DH Key & PIN Cracker", "wps_menu", True),
        ("🔐", "WPA/WPA2 Attacks", "4-Way Handshake Capture", "wpa_menu", False),
        ("🔑", "PMKID Capture", "Clientless hcxdumptool", "pmkid_menu", False),
        ("💥", "Password Cracker", "Hashcat & Aircrack Engine", "crack_menu", False),
        ("🛑", "Deauth / Jamming", "Targeted & Broadcast", "deauth_menu", False),
        ("👥", "Evil Twin Rogue AP", "DNS Hijack & Client Track", "evil_twin_menu", False),
        ("🎣", "Captive Portal", "Phishing Credential Sniffer", "captive_portal_menu", False),
        ("🌀", "Karma / MANA", "Probe Interception AP", "karma_menu", False),
        ("🔓", "WEP Cracking", "PTW & ARP Injection", "wep_menu", False),
        ("🌪️", "Wireless DoS Flood", "Beacon/Auth/EAPOL Flood", "dos_menu", False),
        ("📱", "Bluetooth Recon", "BLE & Classic Device Recon", "bluetooth_menu", False),
        ("🏢", "Enterprise 802.1X", "Hostapd-WPE Evil RADIUS", "enterprise_menu", False),
        ("🔌", "Interface Manager", "Monitor Mode & MAC Spoof", "interface_menu", False),
        ("⚙️", "Settings & Themes", "Config, DB, GPS & Layout", "settings_menu", False),
    ]

    def compose(self) -> ComposeResult:
        yield Header(show_clock=True)
        with Vertical(id="menu-layout"):
            with Vertical(id="header-section"):
                yield Static("⚡ WAFFORD  —  Next-Gen WiFi Auditing Framework", id="app-title")
                yield Static("Professional Autonomous Wireless Security Suite (Ctrl+K for Command Palette)", id="app-subtitle")

            with Horizontal(id="telemetry-bar"):
                yield Static("Loading Hardware Telemetry...", classes="telemetry-pill", id="pill-iface")
                yield Static("Root: ...", classes="telemetry-pill", id="pill-root")
                yield Static("Tools: ...", classes="telemetry-pill", id="pill-tools")
                yield Static("Active Target: None", classes="telemetry-pill", id="pill-target")

            with Grid(id="menu-grid"):
                for icon, title, desc, target, is_primary in self.MENU_ITEMS:
                    btn = Button(
                        f"{icon}  {title}\n{desc}",
                        id=f"btn-{target}",
                        classes=f"menu-card {'-primary-card' if is_primary else ''}",
                    )
                    btn._nav_target = target  # type: ignore[attr-defined]
                    yield btn

        yield StatusBar(id="status-bar")

    def on_mount(self) -> None:
        self._update_telemetry()

    def _update_telemetry(self) -> None:
        has_root = os.geteuid() == 0
        root_style = "bold green" if has_root else "bold red"
        self.query_one("#pill-root", Static).update(Text(f"Root: {'✓ YES' if has_root else '✗ NO ROOT'}", style=root_style))

        # Check adapter
        adapters = ToolDetector.check_wifi_adapter()
        active_iface = getattr(self.app, "selected_interface", None) or (adapters[0] if adapters else "wlan0")
        self.query_one("#pill-iface", Static).update(Text(f"Adapter: {active_iface}", style="bold cyan"))

        # Check tools count
        detector = ToolDetector()
        summary = detector.get_summary()
        self.query_one("#pill-tools", Static).update(Text(f"Tools: {summary.split(',')[0]}", style="bold green"))

        # Target
        target = getattr(self.app, "selected_network", None)
        if target:
            self.query_one("#pill-target", Static).update(Text(f"Target: {target.get('essid', 'Target')} ({target.get('bssid', '')})", style="bold yellow"))
        else:
            self.query_one("#pill-target", Static).update(Text("Target: [No Target Selected]", style="dim"))

    @on(Button.Pressed, ".menu-card")
    def on_menu_card_pressed(self, event: Button.Pressed) -> None:
        target = getattr(event.button, "_nav_target", None)
        if not target:
            return
        screen_name = NAV_MAP.get(target, target)
        try:
            self.app.push_screen(screen_name)
        except Exception:
            if hasattr(self.app, "notify"):
                self.app.notify(f"Screen '{screen_name}' not available", severity="warning")

    def action_open_palette(self) -> None:
        if hasattr(self.app, "action_open_palette"):
            self.app.action_open_palette()

    def action_back_to_self(self) -> None:
        pass
