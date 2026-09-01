"""Tests for custom exceptions."""

from wafford.exceptions import (
    WaffordError,
    InterfaceError,
    ScanError,
    AttackError,
    PluginError,
    DatabaseError,
)


def test_wafford_error():
    """Test base WaffordError."""
    err = WaffordError("Test error")
    assert "Test error" in str(err)
    assert err.code == 1


def test_interface_error():
    """Test InterfaceError."""
    err = InterfaceError("Interface failed", interface="wlan0")
    assert "Interface failed" in str(err)
    assert "wlan0" in str(err)


def test_attack_error():
    """Test AttackError."""
    err = AttackError("Attack failed", attack_type="deauth")
    assert "Attack failed" in str(err)
    assert "deauth" in str(err)


def test_plugin_error():
    """Test PluginError."""
    err = PluginError("Plugin load failed", plugin="test_plugin")
    assert "Plugin load failed" in str(err)
    assert "test_plugin" in str(err)


def test_database_error():
    """Test DatabaseError."""
    err = DatabaseError("DB connection failed")
    assert "DB connection failed" in str(err)
