"""Wafford Plugin System.

Provides a modular plugin architecture for extending WiFi auditing capabilities.
"""

from wafford.plugins.api import (
    PluginBase,
    PluginContext,
    register_attack,
    register_hook,
    register_menu_item,
    register_network_field,
    register_screen,
)
from wafford.plugins.loader import PluginLoader
from wafford.plugins.registry import PluginRegistry
from wafford.plugins.sandbox import PluginSandbox

__all__ = [
    "PluginBase",
    "PluginContext",
    "PluginLoader",
    "PluginRegistry",
    "PluginSandbox",
    "register_attack",
    "register_hook",
    "register_menu_item",
    "register_network_field",
    "register_screen",
]
