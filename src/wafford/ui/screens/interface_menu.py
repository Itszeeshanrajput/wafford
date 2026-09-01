# ruff: noqa: SLF001
from __future__ import annotations

from typing import TYPE_CHECKING, cast

from textual import on, work
from textual.containers import Horizontal, ScrollableContainer, Vertical
from textual.screen import Screen
from textual.widgets import Button, Static

if TYPE_CHECKING:
    from textual.app import ComposeResult

    from wafford.ui.app import WaffordApp
class InterfaceMenu(Screen):
    CSS = """
    InterfaceMenu {
        background: $background;
    }
    #if-layout {
        width: 100%;
        height: 100%;
        padding: 1 2;
    }
    #if-header {
        width: 100%;
        height: 3;
        color: $primary;
        text-style: bold;
        text-align: center;
        margin-bottom: 1;
    }
    #if-buttons {
        width: 100%;
        height: 3;
        layout: horizontal;
        margin-bottom: 1;
    }
    #if-buttons Button {
        margin-right: 1;
        min-width: 15;
    }
    #quick-actions {
        width: 100%;
        height: auto;
        layout: horizontal;
        margin-bottom: 1;
        padding: 1 0;
    }
    #quick-actions Button {
        margin-right: 1;
        min-width: 25;
    }
    .btn-auto-monitor {
        background: $success;
        color: $background;
        text-style: bold;
    }
    .btn-auto-managed {
        background: $warning;
        color: $background;
        text-style: bold;
    }
    .btn-auto-detect {
        background: $primary;
        color: $background;
        text-style: bold;
    }
    #quick-separator {
        width: 100%;
        height: 1;
        color: $muted;
        text-align: center;
        margin-bottom: 1;
    }
    #if-scroll {
        width: 100%;
        height: 1fr;
    }
    .iface-card {
        width: 100%;
        height: auto;
        min-height: 8;
        margin: 0 0 1 0;
        padding: 1 2;
        border: solid $muted;
        background: $surface;
    }
    .iface-card.active {
        border: thick $primary;
    }
    .iface-name {
        color: $primary;
        text-style: bold;
        width: 100%;
        height: 1;
    }
    .iface-details {
        width: 100%;
        height: auto;
        color: $text;
    }
    .iface-modes {
        width: 100%;
        height: auto;
        layout: horizontal;
        margin-top: 1;
    }
    .mode-btn {
        margin-right: 1;
        min-width: 15;
    }
    .mode-monitor {
        background: $success;
        color: $background;
    }
    .mode-managed {
        background: $warning;
        color: $background;
    }
    .badge-monitor {
        background: $success;
        color: $background;
        text-style: bold;
        padding: 0 1;
    }
    .badge-managed {
        background: $warning;
        color: $background;
        text-style: bold;
        padding: 0 1;
    }
    #status-msg {
        width: 100%;
        height: 1;
        color: $success;
        text-style: bold;
        text-align: center;
        margin-top: 1;
    }
    """

    BINDINGS = [
        ("escape", "go_back", "Back"),
        ("r", "refresh_interfaces", "Refresh"),
    ]

    @property
    def app(self) -> WaffordApp:  # type: ignore[override]
        return cast("WaffordApp", super().app)

    def __init__(self, **kwargs) -> None:
        super().__init__(**kwargs)
        self._interfaces: list[dict] = []
        self._manager = None
        self._selected_iface: str | None = None

    def compose(self) -> ComposeResult:
        with Vertical(id="if-layout"):
            yield Static("📡  Interface Management", id="if-header")

            with Horizontal(id="quick-actions"):
                yield Button(
                    "⚡  Auto → Monitor Mode",
                    id="auto-monitor-btn",
                    variant="success",
                    classes="btn-auto-monitor",
                )
                yield Button(
                    "⚡  Auto → Managed Mode",
                    id="auto-managed-btn",
                    variant="warning",
                    classes="btn-auto-managed",
                )
                yield Button(
                    "🔍  Auto-Detect Best Card",
                    id="auto-detect-btn",
                    variant="primary",
                    classes="btn-auto-detect",
                )

            yield Static("─" * 60, id="quick-separator")

            with Horizontal(id="if-buttons"):
                yield Button("⟳  Refresh", id="refresh-btn", variant="default")
                yield Button("🔍  Detect All", id="detect-btn", variant="default")
                yield Button("←  Back", id="back-btn", variant="default")

            yield Static("", id="status-msg")
            yield ScrollableContainer(id="if-scroll")

    def on_mount(self) -> None:
        self._load_interfaces()

    def _get_manager(self):
        if self._manager is None:
            from wafford.core.interface import InterfaceManager
            self._manager = InterfaceManager()
        return self._manager

    def _load_interfaces(self) -> None:
        try:
            mgr = self._get_manager()
            adapters = mgr.detect_interfaces()
            self._interfaces = []
            for a in adapters:
                self._interfaces.append({
                    "name": a.name,
                    "mac": a.mac,
                    "chipset": a.chipset or "Unknown",
                    "driver": a.driver or "Unknown",
                    "mode": a.mode,
                    "bands": ", ".join(a.supported_bands) if a.supported_bands else "Unknown",
                    "supports_monitor": a.mode == "monitor" or bool(a.supported_bands),
                    "injection": False,
                    "physical_id": a.physical_id,
                })
        except Exception:
            # Fallback demo data when root/system tools unavailable
            if not self._interfaces:
                self._interfaces = [
                    {
                        "name": "wlan0",
                        "mac": "XX:XX:XX:XX:XX:XX",
                        "chipset": "Auto-detect (run as root)",
                        "driver": "unknown",
                        "mode": "managed",
                        "bands": "2.4GHz",
                        "supports_monitor": True,
                        "injection": False,
                    },
                ]
        self._render_interfaces()

    def _render_interfaces(self) -> None:
        scroll = self.query_one("#if-scroll", ScrollableContainer)
        scroll.remove_children()
        if not self._interfaces:
            scroll.mount(Static("  No wireless interfaces found. Insert a WiFi adapter and click Refresh."))
            return
        for iface in self._interfaces:
            card = self._build_card(iface)
            scroll.mount(card)

    def _build_card(self, iface: dict) -> Static:
        mode = iface["mode"]
        mode_badge = "● MONITOR" if mode == "monitor" else "● MANAGED"
        support = "✓ Monitor" if iface["supports_monitor"] else "✗ No Monitor"
        inject = "✓ Injection" if iface["injection"] else "  Injection"

        content = (
            f"  {iface['name']}  [{mode_badge}]\n"
            f"  MAC:    {iface['mac']}\n"
            f"  Chipset: {iface['chipset']}\n"
            f"  Driver:  {iface['driver']}\n"
            f"  Bands:   {iface['bands']}\n"
            f"  {support}  |  {inject}"
        )
        return Static(content, classes="iface-card")

    def _set_status(self, msg: str, level: str = "info") -> None:
        status = self.query_one("#status-msg", Static)
        status.update(f"  {msg}")
        if level == "success":
            status.styles.color = "green"
        elif level == "error":
            status.styles.color = "red"
        elif level == "warning":
            status.styles.color = "yellow"
        else:
            status.styles.color = "cyan"
        self.app._notify(msg, level=level)

    # ── One-click: Auto → Monitor Mode ────────────────────────────────
    @on(Button.Pressed, "#auto-monitor-btn")
    def on_auto_monitor(self, event: Button.Pressed) -> None:
        """Auto-select best WiFi card and enable monitor mode in one click."""
        self._set_status("⚡ Auto-selecting best card & enabling monitor mode...", "info")
        self._run_auto_monitor()

    @work(thread=True)
    def _run_auto_monitor(self) -> None:
        try:
            mgr = self._get_manager()
            adapter = mgr.auto_enable_monitor()
            if adapter is None:
                self.app.call_from_thread(self._set_status, "✗ No WiFi adapter found", "error")
                return
            self._selected_iface = adapter.name
            msg = f"✓ {adapter.name} → MONITOR MODE enabled"
            self.app.call_from_thread(self._set_status, msg, "success")
            self.app.call_from_thread(setattr, self.app, "selected_interface", adapter.name)
            self.app.call_from_thread(self._load_interfaces)
        except Exception as e:
            self.app.call_from_thread(self._set_status, f"✗ Failed: {e}", "error")

    # ── One-click: Auto → Managed Mode ───────────────────────────────
    @on(Button.Pressed, "#auto-managed-btn")
    def on_auto_managed(self, event: Button.Pressed) -> None:
        """Auto-select interface and restore to managed mode in one click."""
        self._set_status("⚡ Restoring managed mode...", "info")
        self._run_auto_managed()

    @work(thread=True)
    def _run_auto_managed(self) -> None:
        try:
            mgr = self._get_manager()
            adapter = mgr.auto_enable_managed()
            if adapter is None:
                self.app.call_from_thread(self._set_status, "✗ No WiFi adapter found", "error")
                return
            self._selected_iface = adapter.name
            msg = f"✓ {adapter.name} → MANAGED MODE restored"
            self.app.call_from_thread(self._set_status, msg, "success")
            self.app.call_from_thread(setattr, self.app, "selected_interface", adapter.name)
            self.app.call_from_thread(self._load_interfaces)
        except Exception as e:
            self.app.call_from_thread(self._set_status, f"✗ Failed: {e}", "error")

    # ── One-click: Auto-Detect Best Card ─────────────────────────────
    @on(Button.Pressed, "#auto-detect-btn")
    def on_auto_detect(self, event: Button.Pressed) -> None:
        """Auto-detect and highlight the best WiFi card."""
        self._set_status("🔍 Auto-detecting best WiFi card...", "info")
        self._run_auto_detect()

    @work(thread=True)
    def _run_auto_detect(self) -> None:
        try:
            mgr = self._get_manager()
            adapter = mgr.auto_select_interface()
            if adapter is None:
                self.app.call_from_thread(self._set_status, "✗ No WiFi adapter found", "error")
                return
            self._selected_iface = adapter.name
            mode_str = adapter.mode.upper()
            msg = f"✓ Best card: {adapter.name} ({adapter.driver or 'unknown driver'}) [{mode_str}]"
            self.app.call_from_thread(self._set_status, msg, "success")
            self.app.call_from_thread(setattr, self.app, "selected_interface", adapter.name)
            self.app.call_from_thread(self._load_interfaces)
        except Exception as e:
            self.app.call_from_thread(self._set_status, f"✗ Failed: {e}", "error")

    # ── Standard buttons ─────────────────────────────────────────────
    @on(Button.Pressed, "#refresh-btn")
    def on_refresh(self, event: Button.Pressed) -> None:
        self._set_status("Refreshing interfaces...", "info")
        self._load_interfaces()

    @on(Button.Pressed, "#detect-btn")
    def on_detect(self, event: Button.Pressed) -> None:
        self._set_status("Detecting all interfaces...", "info")
        self._load_interfaces()

    @on(Button.Pressed, "#back-btn")
    def on_back(self, event: Button.Pressed) -> None:
        self.action_go_back()

    def action_go_back(self) -> None:
        self.app.pop_screen()

    def action_refresh_interfaces(self) -> None:
        self._set_status("Refreshing...", "info")
        self._load_interfaces()
