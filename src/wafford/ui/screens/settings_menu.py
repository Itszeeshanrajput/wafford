"""Settings Management Screen for Wafford with Persistent ConfigManager Sync."""

from __future__ import annotations

from typing import TYPE_CHECKING

from textual.containers import Horizontal, Vertical
from textual.screen import Screen
from textual.widgets import Button, Checkbox, Header, Input, Label, Select, Static

if TYPE_CHECKING:
    from typing import Any

    from textual.app import ComposeResult

from wafford.config import ConfigManager
from wafford.ui.theme import apply_theme, list_themes
from wafford.ui.widgets.status_bar import StatusBar


class SettingsMenu(Screen[None]):
    """Framework Configuration and Theme Customization Screen."""

    CSS = """
    SettingsMenu {
        background: $background;
    }
    #st-layout {
        width: 100%;
        height: 1fr;
        padding: 1 2;
    }
    #st-form-card {
        height: 1fr;
        padding: 1 2;
        border: round $primary;
        background: $surface;
        margin-bottom: 1;
        overflow-y: scroll;
    }
    .st-section-title {
        width: 100%;
        text-style: bold;
        color: $accent;
        margin-top: 1;
        margin-bottom: 0;
    }
    .st-field {
        layout: horizontal;
        width: 100%;
        height: 3;
        margin-bottom: 1;
    }
    .st-label {
        width: 30;
        color: $primary;
        text-style: bold;
    }
    .st-input {
        width: 1fr;
    }
    #st-buttons {
        height: 3;
        layout: horizontal;
    }
    #st-buttons Button {
        margin-right: 1;
    }
    """

    BINDINGS = [
        ("escape", "go_back", "Back"),
        ("ctrl+s", "save_settings", "Save"),
    ]

    def __init__(self, **kwargs: Any) -> None:
        super().__init__(**kwargs)
        self._mgr = ConfigManager()

    def compose(self) -> ComposeResult:
        cfg = self._mgr.load()
        yield Header(show_clock=True)
        with Vertical(id="st-layout"):
            Static("⚙ Framework Configuration & Customization", classes="menu-title")
            with Vertical(id="st-form-card"):
                # ── UI / General ──────────────────────────────────────
                Static("General", classes="st-section-title")
                with Horizontal(classes="st-field"):
                    yield Label("UI Theme Palette", classes="st-label")
                    yield Select(
                        [(t, t) for t in list_themes()],
                        value=cfg.ui.theme.upper(),
                        id="st-theme",
                        classes="st-input",
                    )

                with Horizontal(classes="st-field"):
                    yield Label("Language", classes="st-label")
                    yield Select(
                        [
                            ("English", "en"),
                            ("Español", "es"),
                            ("Deutsch", "de"),
                            ("Français", "fr"),
                            ("日本語", "ja"),
                        ],
                        value=cfg.ui.language,
                        id="st-language",
                        classes="st-input",
                    )

                with Horizontal(classes="st-field"):
                    yield Label("Auto-update on boot", classes="st-label")
                    yield Checkbox(
                        "Check updates on startup",
                        id="st-auto-update",
                        value=cfg.update.auto_update,
                    )

                # ── Scan ──────────────────────────────────────────────
                Static("Scan Defaults", classes="st-section-title")
                with Horizontal(classes="st-field"):
                    yield Label("Default Scan Duration (s)", classes="st-label")
                    yield Input(value=str(cfg.scan.duration), id="st-scan-dur", classes="st-input")

                with Horizontal(classes="st-field"):
                    yield Label("Channel Hop Dwell (ms)", classes="st-label")
                    yield Input(
                        value=str(cfg.scan.channel_hop_dwell_ms),
                        id="st-channel-dwell",
                        classes="st-input",
                    )

                # ── Attack ────────────────────────────────────────────
                Static("Attack Defaults", classes="st-section-title")
                with Horizontal(classes="st-field"):
                    yield Label("Default Deauth Packets", classes="st-label")
                    yield Input(
                        value=str(cfg.attack.deauth_packets),
                        id="st-deauth-pkt",
                        classes="st-input",
                    )

                # ── Cracking ──────────────────────────────────────────
                Static("Cracking Defaults", classes="st-section-title")
                with Horizontal(classes="st-field"):
                    yield Label("Default Wordlist Path", classes="st-label")
                    yield Input(value=cfg.crack.wordlist_path, id="st-wl-path", classes="st-input")

                with Horizontal(classes="st-field"):
                    yield Label("GPU Device Index", classes="st-label")
                    yield Input(
                        value=str(cfg.crack.gpu_device_index),
                        id="st-gpu-idx",
                        classes="st-input",
                    )

                # ── Logging ───────────────────────────────────────────
                Static("Logging", classes="st-section-title")
                with Horizontal(classes="st-field"):
                    yield Label("Log Level", classes="st-label")
                    yield Select(
                        [
                            ("DEBUG", "DEBUG"),
                            ("INFO", "INFO"),
                            ("WARNING", "WARNING"),
                            ("ERROR", "ERROR"),
                        ],
                        value=cfg.logging.log_level,
                        id="st-log-level",
                        classes="st-input",
                    )

                # ── GPS / Wardriving ──────────────────────────────────
                Static("GPS / Wardriving", classes="st-section-title")
                with Horizontal(classes="st-field"):
                    yield Label("GPS Tracking Enabled", classes="st-label")
                    yield Checkbox("Enable GPS logging", id="st-gps-enable", value=cfg.gps.enabled)

                with Horizontal(classes="st-field"):
                    yield Label("GPS Port", classes="st-label")
                    yield Input(value=str(cfg.gps.port), id="st-gps-port", classes="st-input")

                # ── MITM / Proxy ──────────────────────────────────────
                Static("MITM / Rogue-AP Proxy", classes="st-section-title")
                with Horizontal(classes="st-field"):
                    yield Label("MITM Proxy Enabled", classes="st-label")
                    yield Checkbox("Enable proxy", id="st-mitm-enable", value=cfg.mitm.enabled)

                with Horizontal(classes="st-field"):
                    yield Label("Proxy Host", classes="st-label")
                    yield Input(value=cfg.mitm.proxy_host, id="st-mitm-host", classes="st-input")

                with Horizontal(classes="st-field"):
                    yield Label("Proxy Port", classes="st-label")
                    yield Input(
                        value=str(cfg.mitm.proxy_port),
                        id="st-mitm-port",
                        classes="st-input",
                    )

                # ── EAPOL Validation ──────────────────────────────────
                Static("EAPOL Validation", classes="st-section-title")
                with Horizontal(classes="st-field"):
                    yield Label("EAPOL Validation", classes="st-label")
                    yield Checkbox(
                        "Enable EAPOL checks",
                        id="st-eapol-enable",
                        value=cfg.eapol.enabled,
                    )

                with Horizontal(classes="st-field"):
                    yield Label("EAPOL Timeout (ms)", classes="st-label")
                    yield Input(
                        value=str(cfg.eapol.timeout_ms),
                        id="st-eapol-timeout",
                        classes="st-input",
                    )

                with Horizontal(classes="st-field"):
                    yield Label("EAPOL Max Retries", classes="st-label")
                    yield Input(
                        value=str(cfg.eapol.max_retries),
                        id="st-eapol-retries",
                        classes="st-input",
                    )

            with Horizontal(id="st-buttons"):
                yield Button("💾 Save Settings", id="btn-st-save", variant="success")
                yield Button("🔄 Reset to Defaults", id="btn-st-reset", variant="warning")
                yield Button("← Back", id="btn-st-back", variant="default")

        yield StatusBar(id="status-bar")

    async def on_button_pressed(self, event: Button.Pressed) -> None:
        bid = event.button.id
        if bid == "btn-st-save":
            self.action_save_settings()
        elif bid == "btn-st-reset":
            self._reset_settings()
        elif bid == "btn-st-back":
            self.action_go_back()

    def action_save_settings(self) -> None:
        try:
            theme_val = self.query_one("#st-theme", Select).value or "DARK"
            lang_val = self.query_one("#st-language", Select).value or "en"
            auto_up = self.query_one("#st-auto-update", Checkbox).value
            scan_dur = int(self.query_one("#st-scan-dur", Input).value.strip() or "30")
            ch_dwell = int(self.query_one("#st-channel-dwell", Input).value.strip() or "50")
            deauth_cnt = int(self.query_one("#st-deauth-pkt", Input).value.strip() or "5")
            wl_path = (
                self.query_one("#st-wl-path", Input).value.strip()
                or "/usr/share/wordlists/rockyou.txt"
            )
            gpu_idx = int(self.query_one("#st-gpu-idx", Input).value.strip() or "0")
            log_lvl = self.query_one("#st-log-level", Select).value or "INFO"
            gps_on = self.query_one("#st-gps-enable", Checkbox).value
            gps_port = int(self.query_one("#st-gps-port", Input).value.strip() or "2947")
            mitm_on = self.query_one("#st-mitm-enable", Checkbox).value
            mitm_host = self.query_one("#st-mitm-host", Input).value.strip() or "127.0.0.1"
            mitm_port = int(self.query_one("#st-mitm-port", Input).value.strip() or "8080")
            eapol_on = self.query_one("#st-eapol-enable", Checkbox).value
            eapol_timeout = int(self.query_one("#st-eapol-timeout", Input).value.strip() or "5000")
            eapol_retries = int(self.query_one("#st-eapol-retries", Input).value.strip() or "3")

            self._mgr.set("ui.theme", str(theme_val))
            self._mgr.set("ui.language", str(lang_val))
            self._mgr.set("update.auto_update", auto_up)
            self._mgr.set("scan.duration", scan_dur)
            self._mgr.set("scan.channel_hop_dwell_ms", ch_dwell)
            self._mgr.set("attack.deauth_packets", deauth_cnt)
            self._mgr.set("crack.wordlist_path", wl_path)
            self._mgr.set("crack.gpu_device_index", gpu_idx)
            self._mgr.set("logging.log_level", str(log_lvl))
            self._mgr.set("gps.enabled", gps_on)
            self._mgr.set("gps.port", gps_port)
            self._mgr.set("mitm.enabled", mitm_on)
            self._mgr.set("mitm.proxy_host", mitm_host)
            self._mgr.set("mitm.proxy_port", mitm_port)
            self._mgr.set("eapol.enabled", eapol_on)
            self._mgr.set("eapol.timeout_ms", eapol_timeout)
            self._mgr.set("eapol.max_retries", eapol_retries)
            self._mgr.save()

            # Apply theme instantly
            apply_theme(self.app, str(theme_val))

            if hasattr(self.app, "notify"):
                self.app.notify(
                    "Configuration saved & applied successfully!",
                    severity="information",
                )
        except Exception as e:
            if hasattr(self.app, "notify"):
                self.app.notify(f"Failed to save config: {e}", severity="error")

    def _reset_settings(self) -> None:
        try:
            self._mgr.reset()
            cfg = self._mgr.config
            self.query_one("#st-theme", Select).value = cfg.ui.theme
            self.query_one("#st-language", Select).value = cfg.ui.language
            self.query_one("#st-auto-update", Checkbox).value = cfg.update.auto_update
            self.query_one("#st-scan-dur", Input).value = str(cfg.scan.duration)
            self.query_one("#st-channel-dwell", Input).value = str(cfg.scan.channel_hop_dwell_ms)
            self.query_one("#st-deauth-pkt", Input).value = str(cfg.attack.deauth_packets)
            self.query_one("#st-wl-path", Input).value = cfg.crack.wordlist_path
            self.query_one("#st-gpu-idx", Input).value = str(cfg.crack.gpu_device_index)
            self.query_one("#st-log-level", Select).value = cfg.logging.log_level
            self.query_one("#st-gps-enable", Checkbox).value = cfg.gps.enabled
            self.query_one("#st-gps-port", Input).value = str(cfg.gps.port)
            self.query_one("#st-mitm-enable", Checkbox).value = cfg.mitm.enabled
            self.query_one("#st-mitm-host", Input).value = cfg.mitm.proxy_host
            self.query_one("#st-mitm-port", Input).value = str(cfg.mitm.proxy_port)
            self.query_one("#st-eapol-enable", Checkbox).value = cfg.eapol.enabled
            self.query_one("#st-eapol-timeout", Input).value = str(cfg.eapol.timeout_ms)
            self.query_one("#st-eapol-retries", Input).value = str(cfg.eapol.max_retries)
            apply_theme(self.app, cfg.ui.theme)
            if hasattr(self.app, "notify"):
                self.app.notify("Settings reset to defaults", severity="warning")
        except Exception as e:
            if hasattr(self.app, "notify"):
                self.app.notify(f"Reset error: {e}", severity="error")

    def action_go_back(self) -> None:
        self.app.pop_screen()
