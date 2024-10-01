# @file plugin_manager.py
# This module contains code that supports Build Plugins
##
# Copyright (c) Microsoft Corporation
#
# SPDX-License-Identifier: BSD-2-Clause-Patent
##
"""This module contains code that supports Build Plugins."""

import importlib.util
import logging
import os
import sys
import warnings

from edk2toolext.environment import shell_environment


class PluginDescriptor(object):
    """Plugin Descripter.

    Attributes:
        descripter(Dict): descriptor
        Obj (obj): Object
        Name (str): name attribute from descriptor
        Module (obj): module attribute from descriptor
    """

    def __init__(self, t: dict) -> None:
        """Inits the Plugin descriptor with the Descriptor."""
        self.descriptor = t
        self.Obj = None
        self.Name = t["name"]
        self.Module = t["module"]

    def __str__(self) -> str:
        """String representation of the plugin descriptor."""
        return "PLUGIN DESCRIPTOR:{0}".format(self.Name)


class PluginManager(object):
    """A class that manages all plugins in the environment.

    Attributes:
        Descriptors (List[PluginDescriptor]): list of plugin descriptors
    """

    def __init__(self) -> None:
        """Inits an empty plugin manager."""
        self.Descriptors = []

    def SetListOfEnvironmentDescriptors(self, newlist: list) -> int:
        """Passes a tuple of environment descriptor dictionaries to be loaded as plugins."""
        env = shell_environment.GetBuildVars()
        failed = []
        if newlist is None:
            return []
        for a in newlist:
            b = PluginDescriptor(a)
            if self._load(b) == 0:
                val = env.GetValue(b.Module.upper())
                if val and val == "skip":
                    logging.info(f"{b.Module} turned off by environment variable")
                    continue
                self.Descriptors.append(b)
            else:
                failed.append(a)
        return failed

    def GetPluginsOfClass(self, classobj: type) -> list[object]:
        """Return list of all plugins of a given class.

        Returns:
            list[object]: plugin instances of the requested class
        """
        temp = []
        for a in self.Descriptors:
            if isinstance(a.Obj, classobj):
                temp.append(a)
        return temp

    def GetAllPlugins(self) -> list[object]:
        """Return list of all plugins."""
        return self.Descriptors

    def _load(self, PluginDescriptor: "PluginDescriptor") -> int:
        """Load and instantiate the plugin.

        Args:
            PluginDescriptor(PluginDescriptor): the plugin descriptor
        """
        PluginDescriptor.Obj = None

        py_file_path = PluginDescriptor.descriptor["module"] + ".py"
        py_module_path = os.path.join(
            os.path.dirname(os.path.abspath(PluginDescriptor.descriptor["descriptor_file"])), py_file_path
        )
        py_module_name = "UefiBuild_Plugin_" + PluginDescriptor.descriptor["module"]

        logging.debug("Loading Plugin from %s", py_module_path)

        try:
            spec = importlib.util.spec_from_file_location(py_module_name, py_module_path)
            module = importlib.util.module_from_spec(spec)
            sys.modules[py_module_name] = module

            py_module_dir = os.path.dirname(py_module_path)
            if py_module_dir not in sys.path:
                sys.path.append(py_module_dir)

            # Turn on Deprecation warnings for code in the plugin
            warnings.filterwarnings("default", category=DeprecationWarning, module=module.__name__)

            spec.loader.exec_module(module)
        except Exception:
            exc_info = sys.exc_info()
            logging.error("Failed to import plugin: %s", py_module_path, exc_info=exc_info)
            return -1

        # Instantiate the plugin
        try:
            obj = getattr(module, PluginDescriptor.descriptor["module"])
            PluginDescriptor.Obj = obj()
        except AttributeError:
            exc_info = sys.exc_info()
            logging.error("Failed to instantiate plugin: %s", py_module_path, exc_info=exc_info)
            return -1

        return 0
