"""Textual TUI application for Wafford."""

from __future__ import annotations

import logging

from textual.app import ComposeResult, Screen
from textual.containers import Container, Vertical
from textual.widgets import Header, Footer, Static, Button

logger = logging.getLogger(__name__)


class WelcomeScreen(Screen):
    """Welcome screen for Wafford TUI."""

    BINDINGS = [("q", "quit", "Quit")]

    def compose(self) -> ComposeResult:
        """Create child widgets for the welcome screen."""
        yield Header()
        yield Vertical(
            Static("Welcome to Wafford WiFi Auditing Framework", id="title"),
            Static("Select an option below to begin", id="subtitle"),
            Container(
                Button("Scan Networks", id="btn_scan"),
                Button("View Reports", id="btn_reports"),
                Button("Settings", id="btn_settings"),
                Button("Help", id="btn_help"),
                id="button_container",
            ),
            id="welcome_container",
        )
        yield Footer()

    def on_button_pressed(self, event: Button.Pressed) -> None:
        """Handle button presses."""
        if event.button.id == "btn_scan":
            logger.info("User selected: Scan Networks")
        elif event.button.id == "btn_reports":
            logger.info("User selected: View Reports")
        elif event.button.id == "btn_settings":
            logger.info("User selected: Settings")
        elif event.button.id == "btn_help":
            logger.info("User selected: Help")


class WaffordApp:
    """Main Wafford TUI application using Textual."""

    def __init__(self) -> None:
        """Initialize Wafford TUI application."""
        logger.info("Initializing Wafford TUI application")
        try:
            from textual.app import App

            self.app: App = App()
        except ImportError as exc:
            logger.error("Textual not installed: %s", exc)
            raise

    def run(self) -> None:
        """Run the TUI application."""
        try:
            logger.info("Starting Wafford TUI")
            # Placeholder: in production, create screens and run the app
            logger.info("Wafford TUI would display here")
        except Exception as exc:
            logger.error("TUI error: %s", exc)
            raise
