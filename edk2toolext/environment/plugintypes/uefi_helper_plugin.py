# @file uefi_helper_plugin
# Plugin that supports adding Extension or helper methods
# to the build environment
##
# Copyright (c) Microsoft Corporation
#
# SPDX-License-Identifier: BSD-2-Clause-Patent
##
"""Plugin that supports adding Extension or helper methods to the build environment."""

import logging
from typing import Callable

from edk2toolext.environment.plugin_manager import PluginManager


class IUefiHelperPlugin(object):
    """The class that should be subclassed when creating a UEFI Helper Plugin."""

    def RegisterHelpers(self, obj: "HelperFunctions") -> None:
        """Allows a plugin to register its functions.

        !!! tip
            ```obj.Register()```

        Args:
            obj (HelperFunctions): HelperFunctions object that allows functional registration
        """


class HelperFunctions(object):
    """A class that contains all registed functions.

    Attributes:
        RegisteredFunctions(dict): registered functions
    """

    def __init__(self) -> None:
        """Initializes instance."""
        self.RegisteredFunctions = {}

    def DebugLogRegisteredFunctions(self) -> None:
        """Logs all registered functions and their source path.

        Uses logging.debug to write all registered functions and their source path.
        """
        logging.debug("Logging all Registered Helper Functions:")
        for name, file in self.RegisteredFunctions.items():
            logging.debug("  Function %s registered from file %s", name, file)
        logging.debug("Finished logging %d functions", len(self.RegisteredFunctions))

    def Register(self, name: str, function: Callable, filepath: str) -> None:
        """Registers a plugin.

        Plugins that want to register a helper function should call
        this routine for each function

        Args:
            name (str): name of the function
            function (Callable): function being registered
            filepath (str): filepath to this file

        !!! tip
            ```os.path.abspath(__file__)```
        """
        if name in self.RegisteredFunctions.keys():
            raise Exception(
                "Function %s already registered from plugin file %s.  Can't register again from %s"
                % (name, self.RegisteredFunctions[name], filepath)
            )
        setattr(self, name, function)
        self.RegisteredFunctions[name] = filepath

    def HasFunction(self, name: str) -> bool:
        """Returns if a function exists.

        Args:
            name (str): name of the function

        Returns:
            (bool): if the function is registered or not.
        """
        if name in self.RegisteredFunctions.keys():
            return True
        else:
            return False

    def LoadFromPluginManager(self, pm: PluginManager) -> int:
        """Load all IUefiHelperPlugins into the class.

        Uses the PluginManager class to get all IUefiHelperPlugins in the environment,
        then stores them all in a dict.

        Args:
            pm (PluginManager): class holding all plugins

        Returns:
            (int): number of plugins that failed to be loaded.
        """
        error = 0
        for Descriptor in pm.GetPluginsOfClass(IUefiHelperPlugin):
            logging.info(Descriptor)
            logging.debug("Helper Plugin Register: %s", Descriptor.Name)
            try:
                Descriptor.Obj.RegisterHelpers(self)
            except Exception as e:
                logging.warning("Unable to register {0}".format(Descriptor.Name))
                logging.error(e)
                error += 1
        return error
