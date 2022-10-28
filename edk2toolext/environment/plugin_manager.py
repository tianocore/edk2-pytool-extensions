# @file plugin_manager.py
# This module contains code that supports Build Plugins
##
# Copyright (c) Microsoft Corporation
#
# SPDX-License-Identifier: BSD-2-Clause-Patent
##
"""This module contains code that supports Build Plugins."""

import sys
import os
import imp
import logging
from edk2toolext.environment import shell_environment


class PluginDescriptor(object):
    """Plugin Descripter.

    Attributes:
        descripter(Dict): descriptor
        Obj (obj): Object
        Name (str): name attribute from descriptor
        Module (obj): module attribute from descriptor
    """
    def __init__(self, t):
        """Inits the Plugin descriptor with the Descriptor."""
        self.descriptor = t
        self.Obj = None
        self.Name = t["name"]
        self.Module = t["module"]

    def __str__(self):
        """String representation of the plugin descriptor."""
        return "PLUGIN DESCRIPTOR:{0}".format(self.Name)


class PluginManager(object):
    """A class that manages all plugins in the environment.

    Attributes:
        Descriptors (List[PluginDescriptor]): list of plugin descriptors
    """
    def __init__(self):
        """Inits an empty plugin manager."""
        self.Descriptors = []

    def SetListOfEnvironmentDescriptors(self, newlist):
        """Passes a tuple of environment descriptor dictionaries to be loaded as plugins."""
        env = shell_environment.GetBuildVars()
        failed = []
        if newlist is None:
            return []
        for a in newlist:
            b = PluginDescriptor(a)
            if (self._load(b) == 0):
                val = env.GetValue(b.Module.upper())
                if val and val == "skip":
                    logging.info(f"{b.Module} turned off by environment variable")
                    continue
                self.Descriptors.append(b)
            else:
                failed.append(a)
        return failed

    def GetPluginsOfClass(self, classobj):
        """Return list of all plugins of a given class."""
        temp = []
        for a in self.Descriptors:
            if (isinstance(a.Obj, classobj)):
                temp.append(a)
        return temp

    def GetAllPlugins(self):
        """Return list of all plugins."""
        return self.Descriptors

    def _load(self, PluginDescriptor):
        """Load and instantiate the plugin.

        Arguments:
            PluginDescriptor(PluginDescriptor): the plugin descriptor
        """
        PluginDescriptor.Obj = None
        PythonFileName = PluginDescriptor.descriptor["module"] + ".py"
        PyModulePath = os.path.join(os.path.dirname(os.path.abspath(
            PluginDescriptor.descriptor["descriptor_file"])), PythonFileName)
        logging.debug("Loading Plugin from %s", PyModulePath)
        try:
            with open(PyModulePath, "r") as plugin_file:
                _module = imp.load_module(
                    "UefiBuild_Plugin_" + PluginDescriptor.descriptor["module"],
                    plugin_file,
                    PyModulePath,
                    ("py", "r", imp.PY_SOURCE))

        except Exception:
            exc_info = sys.exc_info()
            logging.error("Failed to import plugin: %s",
                          PyModulePath, exc_info=exc_info)
            return -1

        # Instantiate the plugin
        try:
            obj = getattr(_module, PluginDescriptor.descriptor["module"])
            PluginDescriptor.Obj = obj()
        except AttributeError:
            exc_info = sys.exc_info()
            logging.error("Failed to instantiate plugin: %s",
                          PyModulePath, exc_info=exc_info)
            return -1

        return 0
