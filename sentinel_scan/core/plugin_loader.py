import importlib
import os
import inspect
from typing import List
from sentinel_scan.core.base import BasePlugin

class PluginLoader:
    @staticmethod
    def load_plugins(plugin_dir: str) -> List[BasePlugin]:
        plugins = []
        if not os.path.exists(plugin_dir):
            return plugins

        for filename in os.listdir(plugin_dir):
            if filename.endswith(".py") and filename != "__init__.py":
                module_name = filename[:-3]
                # This is a bit tricky with relative paths,
                # assuming plugins are in sentinel_scan.plugins
                try:
                    full_module_path = f"sentinel_scan.plugins.{module_name}"
                    module = importlib.import_module(full_module_path)

                    for name, obj in inspect.getmembers(module):
                        if inspect.isclass(obj) and issubclass(obj, BasePlugin) and obj is not BasePlugin:
                            plugins.append(obj())
                except Exception as e:
                    print(f"Failed to load plugin {filename}: {e}")
        return plugins
