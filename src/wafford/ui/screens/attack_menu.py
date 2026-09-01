"""Attack Selection Screen for Wafford with Context-Aware Targeting."""

from __future__ import annotations

from typing import TYPE_CHECKING

from textual import on
from textual.containers import Horizontal, ScrollableContainer, Vertical
from textual.screen import Screen
from textual.widgets import Button, Header, Static

from wafford.ui.widgets.status_bar import StatusBar

if TYPE_CHECKING:
    from textual.app import ComposeResult

SCREEN_NAME = {
    "autopwn_menu": "AutoPWN",
    "wps_menu": "WPSAttack",
    "wpa_menu": "WPAAttacks",
    "pmkid_menu": "PMKIDAttack",
    "crack_menu": "PasswordCrack",
    "wep_menu": "WEPAttacks",
    "evil_twin_menu": "EvilTwin",
    "karma_menu": "KarmaMana",
    "captive_portal_menu": "CaptivePortal",
    "dos_menu": "DoSAttack",
    "deauth_menu": "DeauthDoS",
}

ATTACK_TYPES: dict[str, list[tuple[str, str, str]]] = {
    "WPA3": [
        ("🤖 Auto-PWN Pipeline", "Autonomous scan, deauth, and crack pipeline", "autopwn_menu"),
        ("📸 Handshake Capture", "Capture EAPOL 4-way handshake via deauth bursts", "wpa_menu"),
        ("🔑 PMKID Attack", "Clientless PMKID capture from AP via hcxdumptool", "pmkid_menu"),
        ("💥 Offline Password Crack", "Dictionary/brute-force crack using Hashcat", "crack_menu"),
        ("🛑 Deauth Jamming", "Targeted or broadcast disconnect flooding", "deauth_menu"),
    ],
    "WPA2": [
        ("🤖 Auto-PWN Pipeline", "Autonomous scan, deauth, and crack pipeline", "autopwn_menu"),
        ("⚡ WPS Pixie Dust / PIN", "Offline DH key recovery & PIN brute-forcing", "wps_menu"),
        ("📸 Handshake Capture", "Capture EAPOL 4-way handshake via deauth bursts", "wpa_menu"),
        ("🔑 PMKID Attack", "Clientless PMKID capture from AP via hcxdumptool", "pmkid_menu"),
        ("💥 Offline Password Crack", "Dictionary/brute-force crack using Hashcat", "crack_menu"),
        ("👥 Evil Twin Rogue AP", "Rogue AP with DNS spoofing & client monitor", "evil_twin_menu"),
        ("🎣 Captive Portal", "Phishing login portal credential harvester", "captive_portal_menu"),
        ("🛑 Deauth Jamming", "Targeted or broadcast disconnect flooding", "deauth_menu"),
    ],
    "WPA": [
        ("📸 Handshake Capture", "Capture EAPOL 4-way handshake via deauth bursts", "wpa_menu"),
        ("💥 Offline Password Crack", "Dictionary/brute-force crack using Hashcat", "crack_menu"),
        ("🛑 Deauth Jamming", "Targeted or broadcast disconnect flooding", "deauth_menu"),
    ],
    "WEP": [
        ("🔓 PTW Attack (Statistical)", "Pyshkov-Weinmann-Tews IV-based key recovery", "wep_menu"),
        ("⚡ ARP Replay", "Inject ARP requests to generate rapid IVs", "wep_menu"),
        ("✂️ Fragmentation Attack", "Fragment packet interception and keystream recovery", "wep_menu"),
        ("🔪 ChopChop Attack", "Packet forgery without known key", "wep_menu"),
    ],
    "OPN": [
        ("👥 Evil Twin Rogue AP", "Rogue AP with DNS spoofing & client monitor", "evil_twin_menu"),
        ("🌀 Karma / MANA Sniffer", "Impersonate probed networks dynamically", "karma_menu"),
        ("🎣 Captive Portal", "Phishing login portal credential harvester", "captive_portal_menu"),
        ("🌪️ Wireless DoS Flood", "Beacon, Auth, and Association flooding", "dos_menu"),
    ],
}


class AttackMenu(Screen[None]):
    """Context-aware attack selection based on target network encryption."""

    CSS = """
    AttackMenu {
        background: $background;
    }
    #atk-layout {
        width: 100%;
        height: 1fr;
        padding: 1 2;
    }
    #target-card {
        width: 100%;
        height: auto;
        padding: 1 2;
        border: round $primary;
        background: $surface;
        margin-bottom: 1;
    }
    #target-info {
        color: $text;
        text-style: bold;
    }
    #attack-grid {
        width: 100%;
        height: 1fr;
    }
    .atk-card {
        width: 100%;
        height: auto;
        min-height: 4;
        margin: 0 0 1 0;
        padding: 1 2;
        border: solid $muted;
        background: $surface;
        color: $text;
    }
    .atk-card:hover {
        border: solid $primary;
        background: $surface 85%;
    }
    #back-row {
        width: 100%;
        height: 3;
        margin-top: 1;
    }
    """

    BINDINGS = [
        ("escape", "go_back", "Back"),
    ]

    def __init__(self, target: dict | None = None, **kwargs) -> None:
        super().__init__(**kwargs)
        self.target = target

    def compose(self) -> ComposeResult:
        net = self.target or getattr(self.app, "selected_network", None) or {
            "essid": "Target Network",
            "bssid": "AA:BB:CC:DD:EE:FF",
            "channel": 6,
            "signal": -65,
            "encryption": "WPA2",
            "vendor": "Unknown",
        }
        enc = net.get("encryption", "WPA2").upper()
        norm_enc = "WPA2"
        if "WEP" in enc:
            norm_enc = "WEP"
        elif "WPA3" in enc:
            norm_enc = "WPA3"
        elif "OPN" in enc or "OPEN" in enc or "NONE" in enc:
            norm_enc = "OPN"
        elif "WPA" in enc:
            norm_enc = "WPA"

        yield Header(show_clock=True)
        with Vertical(id="atk-layout"):
            Static("⚔ Targeted Attack Selection", classes="menu-title")
            with Vertical(id="target-card"):
                yield Static(
                    f"🎯 Target: {net.get('essid', 'N/A')} ({net.get('bssid', 'N/A')})\n"
                    f"📡 Channel: {net.get('channel', '?')} | Signal: {net.get('signal', '?')} dBm | Encryption: {enc} | Vendor: {net.get('vendor', 'Unknown')}",
                    id="target-info",
                )
            Static(f"Available attack vectors for {enc}:", classes="panel-title")
            with ScrollableContainer(id="attack-grid"):
                attacks = ATTACK_TYPES.get(norm_enc, ATTACK_TYPES["WPA2"])
                for title, desc, screen in attacks:
                    btn = Button(
                        f"{title}\n{desc}",
                        id=f"atk-{screen}",
                        variant="default",
                        classes="atk-card",
                    )
                    btn._nav_target = screen  # type: ignore[attr-defined]
                    yield btn
            with Horizontal(id="back-row"):
                yield Button("← Back to Scanner", id="back-btn", variant="default")

        yield StatusBar(id="status-bar")

    @on(Button.Pressed, "#back-btn")
    def on_back(self, event: Button.Pressed) -> None:
        self.action_go_back()

    @on(Button.Pressed, ".atk-card")
    def on_card_click(self, event: Button.Pressed) -> None:
        target = getattr(event.button, "_nav_target", None)
        if not target:
            return
        screen_name = SCREEN_NAME.get(target, target)
        try:
            self.app.push_screen(screen_name)
        except Exception:
            if hasattr(self.app, "notify"):
                self.app.notify(f"Screen '{screen_name}' not available", severity="warning")

    def action_go_back(self) -> None:
        self.app.pop_screen()
