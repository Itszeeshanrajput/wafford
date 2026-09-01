"""Plugin discovery, loading, unloading, and hot-reloading."""

from __future__ import annotations

import importlib
import importlib.util
import logging
import os
import sys
import threading
from pathlib import Path
from typing import TYPE_CHECKING, Any

from wafford.plugins.api import PluginBase, PluginContext, PluginState

if TYPE_CHECKING:
    import types

logger = logging.getLogger(__name__)

_DEFAULT_PLUGIN_DIR = os.path.expanduser("~/.wafford/plugins")


class PluginLoader:
    """Discovers and manages plugin Python packages inside a plugin directory."""

    def __init__(
        self,
        plugin_dir: str = _DEFAULT_PLUGIN_DIR,
        *,
        config: dict[str, Any] | None = None,
        shared: dict[str, Any] | None = None,
    ) -> None:
        self._plugin_dir = Path(plugin_dir)
        self._config = config or {}
        self._shared = shared or {}
        self._loaded: dict[str, PluginBase] = {}
        self._module_map: dict[str, types.ModuleType] = {}
        self._lock = threading.Lock()

    # -- public API --------------------------------------------------------

    @property
    def plugin_dir(self) -> Path:
        return self._plugin_dir

    @property
    def loaded_plugins(self) -> dict[str, PluginBase]:
        with self._lock:
            return dict(self._loaded)

    def ensure_plugin_dir(self) -> None:
        """Create the plugin directory if it doesn't exist."""
        self._plugin_dir.mkdir(parents=True, exist_ok=True)

    def discover(self) -> list[dict[str, str]]:
        """Return metadata dicts for every discoverable plugin (not yet loaded)."""
        self.ensure_plugin_dir()
        results: list[dict[str, str]] = []
        for entry in sorted(self._plugin_dir.iterdir()):
            if entry.is_dir() and (entry / "__init__.py").exists():
                results.append(
                    {
                        "name": entry.name,
                        "path": str(entry),
                    }
                )
            elif entry.suffix == ".py" and entry.stem.startswith("plugin_"):
                results.append(
                    {
                        "name": entry.stem,
                        "path": str(entry),
                    }
                )
        return results

    def load(self, name: str) -> PluginBase | None:
        """Load a single plugin by *name* and return its instance."""
        with self._lock:
            if name in self._loaded:
                logger.warning("Plugin '%s' is already loaded", name)
                return self._loaded[name]

            instance, module = self._load_plugin_module(name)
            if instance is None:
                return None

            ctx = PluginContext(
                plugin_name=name,
                plugin_dir=str(self._plugin_dir / name),
                config=dict(self._config),
                shared=self._shared,
            )
            try:
                instance.on_load(ctx)
            except Exception:
                logger.exception("Plugin '%s' failed on_load", name)
                instance._state = PluginState.ERROR
                return None

            self._loaded[name] = instance
            self._module_map[name] = module
            logger.info("Loaded plugin: %s v%s", name, instance.version)
            return instance

    def load_all(self) -> dict[str, PluginBase | None]:
        """Discover and load every plugin in the directory."""
        results: dict[str, PluginBase | None] = {}
        for info in self.discover():
            results[info["name"]] = self.load(info["name"])
        return results

    def unload(self, name: str) -> bool:
        """Unload a loaded plugin by *name*."""
        with self._lock:
            instance = self._loaded.get(name)
            if instance is None:
                logger.warning("Plugin '%s' is not loaded", name)
                return False
            try:
                instance.on_unload()
            except Exception:
                logger.exception("Plugin '%s' raised in on_unload", name)
            del self._loaded[name]
            self._module_map.pop(name, None)
            logger.info("Unloaded plugin: %s", name)
            return True

    def reload(self, name: str) -> PluginBase | None:
        """Unload then load a plugin again (hot-reload)."""
        self.unload(name)
        # Invalidate cached module so Python re-imports it.
        to_remove = [
            mod_name
            for mod_name in sys.modules
            if mod_name == f"plugin_{name}" or mod_name.startswith(f"plugin_{name}.")
        ]
        for mod_name in to_remove:
            sys.modules.pop(mod_name, None)
        return self.load(name)

    def enable(self, name: str) -> bool:
        instance = self._loaded.get(name)
        if instance is None or instance.state is PluginState.ENABLED:
            return False
        try:
            instance.on_enable()
            logger.info("Enabled plugin: %s", name)
            return True
        except Exception:
            logger.exception("Plugin '%s' failed on_enable", name)
            instance._state = PluginState.ERROR
            return False

    def disable(self, name: str) -> bool:
        instance = self._loaded.get(name)
        if instance is None or instance.state is not PluginState.ENABLED:
            return False
        try:
            instance.on_disable()
            logger.info("Disabled plugin: %s", name)
            return True
        except Exception:
            logger.exception("Plugin '%s' failed on_disable", name)
            instance._state = PluginState.ERROR
            return False

    # -- internal ----------------------------------------------------------

    def _load_plugin_module(self, name: str) -> tuple:
        """Import a plugin package/file and return ``(instance, module)``."""
        plugin_path = self._plugin_dir / name

        if plugin_path.is_dir():
            init_file = plugin_path / "__init__.py"
            if not init_file.exists():
                logger.error("Plugin '%s' directory has no __init__.py", name)
                return None, None
            return self._load_package(name, plugin_path, init_file)
        if plugin_path.with_suffix(".py").exists():
            py_file = plugin_path.with_suffix(".py")
            return self._load_single_file(name, py_file)
        logger.error("Cannot find plugin '%s' at %s", name, plugin_path)
        return None, None

    def _load_package(
        self, name: str, pkg_dir: Path, init_file: Path
    ) -> tuple:
        module_name = f"plugin_{name}"
        spec = importlib.util.spec_from_file_location(
            module_name, str(init_file), submodule_search_locations=[str(pkg_dir)]
        )
        if spec is None or spec.loader is None:
            logger.error("Cannot create import spec for plugin '%s'", name)
            return None, None
        module = importlib.util.module_from_spec(spec)
        sys.modules[module_name] = module
        try:
            spec.loader.exec_module(module)
        except Exception:
            logger.exception("Failed to execute plugin module '%s'", module_name)
            sys.modules.pop(module_name, None)
            return None, None
        return self._extract_instance(module, name), module

    def _load_single_file(self, name: str, py_file: Path) -> tuple:
        module_name = f"plugin_{name}"
        spec = importlib.util.spec_from_file_location(module_name, str(py_file))
        if spec is None or spec.loader is None:
            logger.error("Cannot create import spec for plugin '%s'", name)
            return None, None
        module = importlib.util.module_from_spec(spec)
        sys.modules[module_name] = module
        try:
            spec.loader.exec_module(module)
        except Exception:
            logger.exception("Failed to execute plugin module '%s'", module_name)
            sys.modules.pop(module_name, None)
            return None, None
        return self._extract_instance(module, name), module

    @staticmethod
    def _extract_instance(module: Any, name: str) -> PluginBase | None:
        """Find the first ``PluginBase`` subclass in *module* and instantiate."""
        for attr_name in dir(module):
            attr = getattr(module, attr_name)
            if (
                isinstance(attr, type)
                and issubclass(attr, PluginBase)
                and attr is not PluginBase
            ):
                return attr()
        logger.error("No PluginBase subclass found in plugin '%s'", name)
        return None
