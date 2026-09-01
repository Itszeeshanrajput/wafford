"""Central plugin registry — register, unregister, query, enable/disable."""

from __future__ import annotations

import logging
import threading
from typing import TYPE_CHECKING, Any

from wafford.plugins.api import PluginBase, PluginState

if TYPE_CHECKING:
    from collections.abc import Callable, Iterator

logger = logging.getLogger(__name__)


class PluginRegistry:
    """Thread-safe registry that tracks all known plugins and their state."""

    def __init__(self) -> None:
        self._plugins: dict[str, PluginBase] = {}
        self._meta: dict[str, dict[str, Any]] = {}
        self._hooks: dict[str, list[Callable[..., Any]]] = {}
        self._lock = threading.Lock()

    # -- registration ------------------------------------------------------

    def register(self, plugin: PluginBase) -> None:
        with self._lock:
            if plugin.name in self._plugins:
                logger.warning(
                    "Overwriting existing plugin registration for '%s'", plugin.name
                )
            self._plugins[plugin.name] = plugin
            self._meta[plugin.name] = plugin.metadata()
            logger.info("Registered plugin: %s", plugin.name)

    def unregister(self, name: str) -> bool:
        with self._lock:
            if name not in self._plugins:
                return False
            del self._plugins[name]
            self._meta.pop(name, None)
            # Remove any hooks contributed by this plugin.
            for event_name in list(self._hooks):
                self._hooks[event_name] = [
                    h for h in self._hooks[event_name] if h.get("_plugin") != name
                ]
                if not self._hooks[event_name]:
                    del self._hooks[event_name]
            logger.info("Unregistered plugin: %s", name)
            return True

    # -- queries ------------------------------------------------------------

    def get(self, name: str) -> PluginBase | None:
        with self._lock:
            return self._plugins.get(name)

    def list_plugins(self) -> list[dict[str, Any]]:
        with self._lock:
            return [
                {
                    **self._meta.get(name, {}),
                    "enabled": p.is_enabled,
                }
                for name, p in self._plugins.items()
            ]

    def list_enabled(self) -> list[PluginBase]:
        with self._lock:
            return [p for p in self._plugins.values() if p.is_enabled]

    def list_disabled(self) -> list[PluginBase]:
        with self._lock:
            return [
                p
                for p in self._plugins.values()
                if p.state is PluginState.LOADED or p.state is PluginState.DISABLED
            ]

    def __contains__(self, name: str) -> bool:
        with self._lock:
            return name in self._plugins

    def __len__(self) -> int:
        with self._lock:
            return len(self._plugins)

    def __iter__(self) -> Iterator[str]:
        with self._lock:
            return iter(list(self._plugins.keys()))

    # -- enable / disable ---------------------------------------------------

    def enable(self, name: str) -> bool:
        plugin = self.get(name)
        if plugin is None:
            logger.error("Cannot enable unknown plugin '%s'", name)
            return False
        if plugin.is_enabled:
            return True
        try:
            plugin.on_enable()
            return True
        except Exception:
            logger.exception("Plugin '%s' failed on_enable", name)
            plugin._state = PluginState.ERROR
            return False

    def disable(self, name: str) -> bool:
        plugin = self.get(name)
        if plugin is None:
            return False
        if not plugin.is_enabled:
            return True
        try:
            plugin.on_disable()
            return True
        except Exception:
            logger.exception("Plugin '%s' failed on_disable", name)
            plugin._state = PluginState.ERROR
            return False

    def enable_all(self) -> dict[str, bool]:
        return {name: self.enable(name) for name in self}

    def disable_all(self) -> dict[str, bool]:
        return {name: self.disable(name) for name in self}

    # -- hook management ----------------------------------------------------

    def add_hook(self, event: str, handler: Callable[..., Any], *, plugin: str = "") -> None:
        with self._lock:
            self._hooks.setdefault(event, [])
            entry = handler
            entry._plugin = plugin  # type: ignore[attr-defined]
            self._hooks[event].append(entry)
            self._hooks[event].sort(
                key=lambda h: getattr(h, "_priority", 0)  # type: ignore[arg-type]
            )

    def get_hooks(self, event: str) -> list[Callable[..., Any]]:
        with self._lock:
            return list(self._hooks.get(event, []))

    def remove_hooks_for(self, plugin_name: str) -> None:
        with self._lock:
            for event_name in self._hooks:
                self._hooks[event_name] = [
                    h
                    for h in self._hooks[event_name]
                    if getattr(h, "_plugin", None) != plugin_name
                ]

    def fire_hook(self, event: str, *args: Any, **kwargs: Any) -> list[Any]:
        results: list[Any] = []
        for handler in self.get_hooks(event):
            try:
                results.append(handler(*args, **kwargs))
            except Exception:
                logger.exception(
                    "Hook '%s' handler %s raised", event, handler.__qualname__
                )
        return results
