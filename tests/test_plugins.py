"""Tests for plugin system."""

from pathlib import Path
import pytest


def test_plugin_registry_init():
    """Test plugin registry initialization."""
    from wafford.plugins.loader import PluginRegistry
    
    registry = PluginRegistry()
    assert registry.plugins == {}
    assert registry.metadata == {}


def test_discover_plugins():
    """Test plugin discovery."""
    from wafford.plugins.loader import PluginRegistry
    
    registry = PluginRegistry()
    plugins = registry.discover_plugins()
    assert isinstance(plugins, list)


def test_plugin_load_nonexistent():
    """Test loading nonexistent plugin raises error."""
    from wafford.plugins.loader import PluginRegistry
    from wafford.exceptions import PluginError
    
    registry = PluginRegistry()
    with pytest.raises(PluginError):
        registry.load_plugin("nonexistent_plugin")
