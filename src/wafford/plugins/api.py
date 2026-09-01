"""Plugin API — base classes, decorators, and context for Wafford plugins."""

from __future__ import annotations

import abc
import logging
from dataclasses import dataclass, field
from enum import Enum, auto
from typing import TYPE_CHECKING, Any

if TYPE_CHECKING:
    from collections.abc import Callable

logger = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# Internal registries populated by decorators
# ---------------------------------------------------------------------------

_hook_registry: dict[str, list[Callable[..., Any]]] = {}
_attack_registry: dict[str, dict[str, Any]] = {}
_screen_registry: dict[str, dict[str, Any]] = {}
_menu_registry: list[dict[str, Any]] = []
_network_field_registry: list[dict[str, Any]] = []


# ---------------------------------------------------------------------------
# Decorators
# ---------------------------------------------------------------------------


def register_hook(event: str, *, priority: int = 0):
    """Register a function as a hook handler for *event*.

    Lower *priority* values execute first.
    """

    def decorator(fn: Callable[..., Any]) -> Callable[..., Any]:
        _hook_registry.setdefault(event, [])
        _hook_registry[event].append({"handler": fn, "priority": priority})
        _hook_registry[event].sort(key=lambda e: e["priority"])
        return fn

    return decorator


def register_attack(
    name: str,
    *,
    description: str = "",
    layer: str = "unknown",
    requires: dict[str, Any] | None = None,
):
    """Register a function as an attack module."""

    def decorator(fn: Callable[..., Any]) -> Callable[..., Any]:
        _attack_registry[name] = {
            "handler": fn,
            "description": description,
            "layer": layer,
            "requires": requires or {},
        }
        return fn

    return decorator


def register_screen(
    screen_id: str,
    *,
    title: str = "",
    handler: Callable[..., Any] | None = None,
):
    """Register a TUI screen provided by a plugin."""

    def decorator(fn: Callable[..., Any]) -> Callable[..., Any]:
        _screen_registry[screen_id] = {
            "handler": fn,
            "title": title,
        }
        return fn

    if handler is not None:
        _screen_registry[screen_id] = {
            "handler": handler,
            "title": title,
        }
        return handler

    return decorator


def register_menu_item(
    label: str,
    *,
    parent: str | None = None,
    screen_id: str | None = None,
    callback: Callable[..., Any] | None = None,
    icon: str = "",
    order: int = 100,
):
    """Register an entry in the Wafford menu system."""
    _menu_registry.append(
        {
            "label": label,
            "parent": parent,
            "screen_id": screen_id,
            "callback": callback,
            "icon": icon,
            "order": order,
        }
    )

    def decorator(fn: Callable[..., Any]) -> Callable[..., Any]:
        if callback is None:
            _menu_registry[-1]["callback"] = fn
        return fn

    return decorator


def register_network_field(
    field_id: str,
    *,
    label: str = "",
    extractor: Callable[..., Any] | None = None,  # noqa: ARG001
    order: int = 100,
):
    """Register an extra field displayed per discovered network."""

    def decorator(fn: Callable[..., Any]) -> Callable[..., Any]:
        _network_field_registry.append(
            {
                "field_id": field_id,
                "label": label or field_id,
                "extractor": fn,
                "order": order,
            }
        )
        return fn

    return decorator


# ---------------------------------------------------------------------------
# PluginContext
# ---------------------------------------------------------------------------


@dataclass
class PluginContext:
    """Runtime context supplied to every plugin on load / execute."""

    plugin_name: str
    plugin_dir: str
    config: dict[str, Any] = field(default_factory=dict)
    shared: dict[str, Any] = field(default_factory=dict)

    def log(self, level: int, msg: str, *args: Any, **kwargs: Any) -> None:
        """Convenience logger scoped to the owning plugin."""
        logger.log(level, f"[{self.plugin_name}] {msg}", *args, **kwargs)

    def debug(self, msg: str, *args: Any, **kwargs: Any) -> None:
        self.log(logging.DEBUG, msg, *args, **kwargs)

    def info(self, msg: str, *args: Any, **kwargs: Any) -> None:
        self.log(logging.INFO, msg, *args, **kwargs)

    def warning(self, msg: str, *args: Any, **kwargs: Any) -> None:
        self.log(logging.WARNING, msg, *args, **kwargs)

    def error(self, msg: str, *args: Any, **kwargs: Any) -> None:
        self.log(logging.ERROR, msg, *args, **kwargs)

    def get_shared(self, key: str, default: Any = None) -> Any:
        return self.shared.get(key, default)

    def set_shared(self, key: str, value: Any) -> None:
        self.shared[key] = value


# ---------------------------------------------------------------------------
# PluginBase
# ---------------------------------------------------------------------------


class PluginState(Enum):
    UNLOADED = auto()
    LOADED = auto()
    ENABLED = auto()
    DISABLED = auto()
    ERROR = auto()


class PluginBase(abc.ABC):  # noqa: B024
    """Abstract base class that every Wafford plugin must subclass."""

    name: str = "unnamed_plugin"
    version: str = "0.0.0"
    author: str = ""
    description: str = ""
    min_wafford_version: str = "0.0.0"

    def __init__(self) -> None:
        self._state = PluginState.UNLOADED
        self._context: PluginContext | None = None
        self._logger = logging.getLogger(f"plugin.{self.name}")

    # -- lifecycle hooks ---------------------------------------------------

    def on_load(self, context: PluginContext) -> None:
        """Called once when the plugin is first loaded."""
        self._context = context
        self._state = PluginState.LOADED

    def on_enable(self) -> None:
        """Called when the plugin is activated."""
        self._state = PluginState.ENABLED

    def on_disable(self) -> None:
        """Called when the plugin is deactivated."""
        self._state = PluginState.DISABLED

    def on_unload(self) -> None:
        """Called before the plugin is removed from memory."""
        self._state = PluginState.UNLOADED
        self._context = None

    # -- introspection -----------------------------------------------------

    @property
    def state(self) -> PluginState:
        return self._state

    @property
    def context(self) -> PluginContext | None:
        return self._context

    @property
    def is_enabled(self) -> bool:
        return self._state is PluginState.ENABLED

    def metadata(self) -> dict[str, Any]:
        return {
            "name": self.name,
            "version": self.version,
            "author": self.author,
            "description": self.description,
            "min_wafford_version": self.min_wafford_version,
            "state": self._state.name,
        }
