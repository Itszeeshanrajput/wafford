"""Command palette modal widget for instant navigation in Wafford."""

from __future__ import annotations

from typing import TYPE_CHECKING

from textual.containers import Vertical
from textual.screen import ModalScreen
from textual.widgets import Input, OptionList, Static
from textual.widgets.option_list import Option

if TYPE_CHECKING:
    from textual.app import ComposeResult

COMMANDS = [
    ("scan", "📡 Network Scanner", "Scan 2.4GHz & 5GHz APs and connected clients"),
    ("interfaces", "🔌 Interface Manager", "Toggle monitor mode, randomize MAC, test packet injection"),
    ("attack", "⚔️ Attack Selection", "Targeted attacks: WPA2, WEP, WPS, Evil Twin, Captive Portal"),
    ("autopwn", "🤖 Auto-PWN Pipeline", "Automated scan, deauth, capture, and offline crack pipeline"),
    ("wps", "⚡ WPS Pixie Dust / PIN", "Pixie Dust attack and offline PIN brute-forcing"),
    ("wpa", "🤝 WPA/WPA2 Handshake", "Deauth clients and capture 4-way EAPOL handshakes"),
    ("pmkid", "🔑 PMKID Capture", "Clientless PMKID capture using hcxdumptool"),
    ("crack", "💥 Password Cracker", "WPA/WPA2 hash cracking via Hashcat and Aircrack-ng"),
    ("deauth", "🛑 Deauthentication", "Targeted, broadcast, and continuous deauth jamming"),
    ("evil_twin", "👥 Evil Twin Rogue AP", "Rogue access point with DNS hijacking and client tracking"),
    ("captive_portal", "🎣 Captive Portal", "Phishing portals with real-time credential harvester"),
    ("karma", "🌀 Karma / MANA Attack", "Probe response sniffer and dynamic rogue AP"),
    ("wep", "🔓 WEP Cracking", "PTW, ARP replay, fragmentation, and statistical cracking"),
    ("dos", "🌪️ Wireless DoS Flood", "Beacon, Auth, Assoc, Deauth, and EAPOL flood frames"),
    ("bluetooth", "📱 Bluetooth Recon", "BLE & Classic device discovery and SDP enumeration"),
    ("enterprise", "🏢 Enterprise 802.1X", "Rogue RADIUS and EAP identity harvesting"),
    ("wifi_direct", "📶 WiFi Direct / P2P", "P2P device discovery and Group Owner negotiation"),
    ("wordlists", "📚 Wordlist Manager", "Download, sort, deduplicate, filter, and inspect wordlists"),
    ("reports", "📊 Audit Reports", "Generate HTML, PDF, Markdown, JSON, and WiGLE reports"),
    ("settings", "⚙️ Framework Settings", "Configure theme, default interfaces, attack timeouts, and tools"),
    ("logs", "📜 Live Log Viewer", "Real-time framework event log streaming"),
    ("deps", "🛠️ Dependency Manager", "Check and install required external tools"),
    ("update", "🔄 Check for Updates", "Self-updater and version verification"),
]


class CommandPalette(ModalScreen[str]):
    """Quick command palette for fuzzy search and jumping to any screen."""

    CSS = """
    CommandPalette {
        align: center middle;
        background: rgba(0, 0, 0, 0.75);
    }
    #palette-container {
        width: 70;
        height: 22;
        background: $surface;
        border: thick $primary;
        padding: 1 2;
    }
    #palette-title {
        text-style: bold;
        color: $primary;
        margin-bottom: 1;
    }
    #palette-input {
        margin-bottom: 1;
        border: tall $secondary;
    }
    #palette-options {
        height: 12;
        background: $background;
        border: tall $muted;
    }
    #palette-hint {
        color: $muted;
        margin-top: 1;
        text-align: center;
    }
    """

    BINDINGS = [
        ("escape", "dismiss_palette", "Close"),
        ("enter", "select_current", "Select"),
    ]

    def compose(self) -> ComposeResult:
        with Vertical(id="palette-container"):
            yield Static("⚡ Wafford Command Palette (Ctrl+K)", id="palette-title")
            yield Input(placeholder="Search screens, attacks, tools...", id="palette-input")
            yield OptionList(
                *[Option(f"{title} — {desc}", id=cmd_id) for cmd_id, title, desc in COMMANDS],
                id="palette-options",
            )
            yield Static("↑/↓: Navigate | Enter: Select | Esc: Close", id="palette-hint")

    def on_mount(self) -> None:
        self.query_one("#palette-input", Input).focus()

    def on_input_changed(self, event: Input.Changed) -> None:
        query = event.value.strip().lower()
        options = self.query_one("#palette-options", OptionList)
        options.clear_options()
        for cmd_id, title, desc in COMMANDS:
            if not query or query in cmd_id.lower() or query in title.lower() or query in desc.lower():
                options.add_option(Option(f"{title} — {desc}", id=cmd_id))

    def on_option_list_option_selected(self, event: OptionList.OptionSelected) -> None:
        if event.option.id:
            self.dismiss(event.option.id)

    def action_dismiss_palette(self) -> None:
        self.dismiss("")

    def action_select_current(self) -> None:
        options = self.query_one("#palette-options", OptionList)
        if options.highlighted is not None:
            opt = options.get_option_at_index(options.highlighted)
            if opt and opt.id:
                self.dismiss(opt.id)
                return
        self.dismiss("")
