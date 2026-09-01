import logging

from wafford.plugins.api import PluginContext

logger = logging.getLogger(__name__)

BUILTIN_PLUGINS = [
    "wafford.plugins.builtin.handshake_to_hashcat",
    "wafford.plugins.builtin.gps_tagger",
    "wafford.plugins.builtin.auto_report",
]


def register_builtin_plugins(loader, context: PluginContext):
    for module_name in BUILTIN_PLUGINS:
        try:
            module = __import__(module_name, fromlist=["*"])
            plugin_class = getattr(module, "BUILTIN_PLUGIN", None)
            if plugin_class is None:
                for attr_name in dir(module):
                    attr = getattr(module, attr_name)
                    if (
                        isinstance(attr, type)
                        and hasattr(attr, "name")
                        and attr.__module__ == module_name
                    ):
                        if getattr(attr, "BUILTIN", False):
                            plugin_class = attr
                            break
            if plugin_class is None:
                logger.warning("No plugin class found in builtin module %s", module_name)
                continue
            manifest = {
                "name": getattr(plugin_class, "name", module_name.rsplit(".", 1)[-1]),
                "version": getattr(plugin_class, "version", "0.1.0"),
                "author": getattr(plugin_class, "author", "Wafford"),
                "description": getattr(plugin_class, "description", ""),
                "entry_point": module_name,
                "capabilities": getattr(plugin_class, "capabilities", []),
                "enabled": True,
            }
            loader.load_plugin(_ManifestLike(**manifest), context)
        except Exception:
            logger.exception("Failed to register builtin plugin %s", module_name)


class _ManifestLike:
    def __init__(self, name, version, author, description, entry_point, capabilities, enabled):
        self.name = name
        self.version = version
        self.author = author
        self.description = description
        self.entry_point = entry_point
        self.capabilities = capabilities
        self.enabled = enabled
        self.min_wafford_version = "0.1.0"
        self.dependencies = []


__all__ = [
    "BUILTIN_PLUGINS",
    "register_builtin_plugins",
]
