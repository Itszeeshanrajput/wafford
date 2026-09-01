"""Plugin discovery and loading system for Wafford."""

from __future__ import annotations

import importlib.util
import logging
import sys
from pathlib import Path
from typing import Any

from wafford.constants import PLUGIN_DIR
from wafford.exceptions import PluginError

logger = logging.getLogger(__name__)


class PluginRegistry:
    """Registry for managing Wafford plugins."""

    def __init__(self, plugin_dir: Path | str | None = None) -> None:
        """Initialize plugin registry.

        Args:
            plugin_dir: Directory containing plugins. Defaults to PLUGIN_DIR.
        """
        self.plugin_dir = Path(plugin_dir or PLUGIN_DIR)
        self.plugins: dict[str, Any] = {}
        self.metadata: dict[str, dict[str, Any]] = {}

    def discover_plugins(self) -> list[str]:
        """Discover all available plugins.

        Returns:
            List of plugin names.
        """
        if not self.plugin_dir.exists():
            logger.warning("Plugin directory not found: %s", self.plugin_dir)
            return []

        plugin_names = []
        for py_file in self.plugin_dir.glob("*.py"):
            if py_file.name.startswith("_"):
                continue
            plugin_names.append(py_file.stem)
        return plugin_names

    def load_plugin(self, name: str) -> Any:
        """Load a plugin by name.

        Args:
            name: Plugin name (without .py extension).

        Returns:
            Loaded plugin module.

        Raises:
            PluginError: If plugin cannot be loaded.
        """
        if name in self.plugins:
            return self.plugins[name]

        plugin_file = self.plugin_dir / f"{name}.py"
        if not plugin_file.exists():
            raise PluginError(f"Plugin not found: {name}", plugin=name)

        try:
            spec = importlib.util.spec_from_file_location(f"wafford_plugin_{name}", plugin_file)
            if spec and spec.loader:
                module = importlib.util.module_from_spec(spec)
                sys.modules[spec.name] = module
                spec.loader.exec_module(module)
                self.plugins[name] = module
                logger.info("Loaded plugin: %s", name)
                return module
            raise PluginError(f"Failed to load plugin: {name}", plugin=name)
        except Exception as exc:
            raise PluginError(f"Plugin load error: {exc}", plugin=name) from exc

    def get_plugin_info(self, name: str) -> dict[str, Any]:
        """Get plugin metadata.

        Args:
            name: Plugin name.

        Returns:
            Plugin metadata dictionary.
        """
        if name not in self.metadata:
            try:
                module = self.load_plugin(name)
                self.metadata[name] = getattr(module, "__plugin_info__", {"name": name})
            except PluginError:
                self.metadata[name] = {"name": name, "error": "Failed to load"}
        return self.metadata[name]

    def list_plugins(self) -> dict[str, dict[str, Any]]:
        """List all available plugins with metadata.

        Returns:
            Dictionary mapping plugin names to metadata.
        """
        plugins = {}
        for name in self.discover_plugins():
            plugins[name] = self.get_plugin_info(name)
        return plugins
