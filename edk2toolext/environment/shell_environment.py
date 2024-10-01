# @file shell_environment.py
# This module contains code that helps to manage the build environment
# including PATH, PYTHONPATH, and ENV variables.
##
# Copyright (c) Microsoft Corporation
#
# SPDX-License-Identifier: BSD-2-Clause-Patent
##
"""Code that helps manage and maintain the build environment.

This management includes PATH, PYTHONPATH and ENV Variables.
"""

import copy
import logging
import os
import sys
from typing import Any

from edk2toolext.environment import var_dict

LOGGING_GROUP = "EnvDict"
MY_LOGGER = logging.getLogger(LOGGING_GROUP)


#
# Copy the Singleton pattern from...
#   https://stackoverflow.com/a/6798042
#
class Singleton(type):  # noqa
    _instances = {}

    def __call__(cls, *args, **kwargs):  # noqa
        if cls not in cls._instances:
            cls._instances[cls] = super(Singleton, cls).__call__(*args, **kwargs)
        return cls._instances[cls]


class ShellEnvironment(metaclass=Singleton):
    """An active copy of the current OS environment.

    Allows for easy manipulation of the environment including taking
    screenshots (checkpoints) that are stored and can be accessed
    later.
    """

    # Easy definition for the very first checkpoint
    # when the environment is first created.
    INITIAL_CHECKPOINT = 0

    def __init__(self) -> None:
        """Inits the local environment with the initial os environment."""
        # Add all of our logging to the EnvDict group.
        self.logger = logging.getLogger(LOGGING_GROUP)

        # Initialize all other things.
        self.active_environ = None
        self.active_path = None
        self.active_pypath = None
        self.active_buildvars = var_dict.VarDict()
        self.checkpoints = []

        # Grab a copy of the environment as it exists.
        self.import_environment()

        # Create the initial checkpoint.
        self.checkpoint()

    #
    # Management methods.
    # These methods manage the singleton, the surrounding environment, and checkpoints.
    #
    def import_environment(self) -> None:
        """Loads the local environment with os environment."""
        # Create a complete copy of os.environ
        self.active_environ = dict()
        for key, value in os.environ.items():
            self.active_environ[key] = value

        # Record the PATH elements of the current environment.
        path = self.active_environ.get("PATH", "")

        # Filter removes empty elements.
        # List creates an actual list rather than a generator.
        # Filter removes empty strings.
        self.active_path = list(filter(None, path.split(os.pathsep)))

        # Record the PYTHONPATH elements of the current environment.
        # When reading PYTHONPATH, try reading the live path from sys.
        self.active_pypath = sys.path

        # Remove PATH and PYTHONPATH from environ copy to force use of active_path and active_pypath
        self.active_environ.pop("PATH", None)
        self.active_environ.pop("PYTHONPATH", None)

    def export_environment(self) -> None:
        """Exports enviornment to the OS."""
        # Purge all keys that aren't in the export.
        for key, value in os.environ.items():
            if key not in self.active_environ:
                os.environ.pop(key)

        # Export all internal keys.
        for key, value in self.active_environ.items():
            os.environ[key] = value

        # Set the PATH and PYTHONPATH vars.
        os.environ["PATH"] = os.pathsep.join(self.active_path)
        os.environ["PYTHONPATH"] = os.pathsep.join(self.active_pypath)

        sys.path = self.active_pypath

    def log_environment(self) -> None:
        """Logs the current environment to the logger."""
        self.logger.debug("FINAL PATH:")
        self.logger.debug(", ".join(self.active_path))

        self.logger.debug("FINAL PYTHONPATH:")
        self.logger.debug(", ".join(self.active_pypath))

        self.logger.debug("FINAL ENVIRON:")
        environ_list = []
        for key, value in self.active_environ.items():
            environ_list.append("({0}:{1})".format(key, value))
        self.logger.debug(", ".join(environ_list))

    def checkpoint(self) -> int:
        """Creates a checkpoint in time.

        Checkpoint stores the following:
        1. active_environment
        2. active_path
        3. active_pypath
        4. active_buildvars
        """
        new_index = len(self.checkpoints)
        self.checkpoints.append(
            {
                "environ": copy.copy(self.active_environ),
                "path": self.active_path,
                "pypath": self.active_pypath,
                "buildvars": copy.copy(self.active_buildvars),
            }
        )

        return new_index

    def restore_checkpoint(self, index: int) -> None:
        """Restore a specific checkpoint."""
        if index < len(self.checkpoints):
            check_point = self.checkpoints[index]
            self.active_environ = copy.copy(check_point["environ"])
            self.active_path = check_point["path"]
            self.active_pypath = check_point["pypath"]
            self.active_buildvars = copy.copy(check_point["buildvars"])

            self.export_environment()

        else:
            raise IndexError("Checkpoint %s does not exist" % index)

    def restore_initial_checkpoint(self) -> None:
        """Restore the initial checkpoint made."""
        self.restore_checkpoint(ShellEnvironment.INITIAL_CHECKPOINT)

    #
    # Environment manipulation methods.
    # These methods interact with the current environment.
    #
    def _internal_set_path(self, path_elements: str) -> None:
        self.active_path = list(path_elements)
        os.environ["PATH"] = os.pathsep.join(self.active_path)

    def _internal_set_pypath(self, path_elements: str) -> None:
        self.active_pypath = list(path_elements)
        os.environ["PYTHONPATH"] = os.pathsep.join(self.active_pypath)
        sys.path = self.active_pypath

    def set_path(self, new_path: str) -> None:
        """Set the path.

        Args:
            new_path (str): path to override with
        """
        self.logger.debug("Overriding PATH with new value.")
        if isinstance(new_path, str):
            new_path = list(new_path.split(os.pathsep))
        self._internal_set_path(new_path)

    def set_pypath(self, new_path: str) -> None:
        """Set the pypath.

        Args:
            new_path (str): path to override with
        """
        self.logger.debug("Overriding PYTHONPATH with new value.")
        if isinstance(new_path, str):
            new_path = list(new_path.split(os.pathsep))
        self._internal_set_pypath(new_path)

    def append_path(self, path_element: str) -> None:
        """Append to the end of path.

        if path_element already exists within path it will be removed
        from the current location and appended to the end

        Args:
            path_element (str): path element to append
        """
        self.logger.debug("Appending PATH element '%s'." % path_element)
        if path_element in self.active_path:
            # remove so we don't have duplicates but we respect the order
            # requested by the caller
            self.active_path.remove(path_element)
        self._internal_set_path(self.active_path + [path_element])

    def insert_path(self, path_element: str) -> None:
        """Insert at front of the path.

        if path_element already exists within path it will be removed
        from the current location and prepended to the front

        Args:
            path_element (str): path element to insert
        """
        self.logger.debug("Inserting PATH element '%s'." % path_element)
        if path_element in self.active_path:
            # remove so we don't have duplicates but we respect the order
            # requested by the caller
            self.active_path.remove(path_element)
        self._internal_set_path([path_element] + self.active_path)

    def append_pypath(self, path_element: str) -> None:
        """Append to the end of pypath.

        if path_element already exists within pypath it will be removed
        from the current location and appended to the end

        Args:
            path_element (str): path element to append
        """
        self.logger.debug("Appending PYTHONPATH element '%s'." % path_element)
        if path_element in self.active_pypath:
            # remove so we don't have duplicates but we respect the order
            # requested by the caller
            self.active_pypath.remove(path_element)
        self._internal_set_pypath(self.active_pypath + [path_element])

    def insert_pypath(self, path_element: str) -> None:
        """Insert at front of the pypath.

        if path_element already exists within pypath it will be removed
        from the current location and prepended to the front

        Args:
            path_element (str): path element to insert
        """
        self.logger.debug("Inserting PYTHONPATH element '%s'." % path_element)
        if path_element in self.active_pypath:
            # remove so we don't have duplicates but we respect the order
            # requested by the caller
            self.active_pypath.remove(path_element)
        self._internal_set_pypath([path_element] + self.active_pypath)

    def replace_path_element(self, old_path_element: str, new_path_element: str) -> None:
        """Replaces the PATH element.

        Generates a new PATH by iterating through the old PATH and replacing
        old_path_element with new_path_element where it is found.

        Args:
            old_path_element (str): element to replace
            new_path_element (str): element to replace with

        """
        self.logger.debug("Replacing PATH element {0} with {1}".format(old_path_element, new_path_element))
        self._internal_set_path([x if x != old_path_element else new_path_element for x in self.active_path])

    def replace_pypath_element(self, old_pypath_element: str, new_pypath_element: str) -> None:
        """Replaces the PYPATH element.

        Generates a new PYPATH by iterating through the old PYPATH and replacing
        old_pypath_element with new_pypath_element where it is found.

        Args:
            old_pypath_element (str): element to replace
            new_pypath_element (str): element to replace with

        """
        self.logger.debug("Replacing PYPATH element {0} with {1}".format(old_pypath_element, new_pypath_element))
        self._internal_set_pypath([x if x != old_pypath_element else new_pypath_element for x in self.active_pypath])

    def remove_path_element(self, path_element: str) -> None:
        """Removes the PATH element.

        Generates a new PATH by iterating through the old PATH and removing
        path_element if it is found.

        Args:
            path_element (str): path element to remove
        """
        self.logger.debug("Removing PATH element {0}".format(path_element))
        self._internal_set_path([x for x in self.active_path if x != path_element])

    def remove_pypath_element(self, pypath_element: str) -> None:
        """Removes the PYPATH element.

        Generates a new PYPATH by iterating through the old PYPATH and removing
        pypath_element if it is found.

        Args:
            pypath_element (str): pypath element to remove
        """
        self.logger.debug("Removing PYPATH element {0}".format(pypath_element))
        self._internal_set_pypath([x for x in self.active_pypath if x != pypath_element])

    def get_build_var(self, var_name: str) -> str:
        """Gets the build variable.

        Args:
            var_name (str): variable to get the value of
        Returns:
            (obj): value associated with the var_name
        """
        return self.active_buildvars.GetValue(var_name)

    def set_build_var(self, var_name: str, var_data: str) -> None:
        """Sets the variable as internal build variable.

        Unlike set_shell_var, var_data can be `None`; this sets var_name as a non-valued
        build variable (e.g. E1000_ENABLE). Additional information can be found at:
        https://www.tianocore.org/edk2-pytool-extensions/integrate/build/#setting-getting-environment-variables.

        !!! note
            Variables set in this manner are only accessable inside stuart, and are not an
            os environment variable. Refer to set_shell_var to set an os environment variable.

        Args:
            var_name (str): variable to set the value for
            var_data (obj): data to set
        """
        self.logger.debug("Updating BUILD VAR element '%s': '%s'." % (var_name, var_data))
        self.active_buildvars.SetValue(var_name, var_data, "", overridable=True)

    def get_shell_var(self, var_name: str) -> str:
        """Gets the shell variable.

        Args:
            var_name (str): variable to get the value of

        Returns:
            (str): value associated with the var name
        """
        return self.active_environ.get(var_name, None)

    def set_shell_var(self, var_name: str, var_data: str) -> None:
        """Sets the variable as an OS environment variable.

        Args:
            var_name (str): variable to set the value for
            var_data (str): data to set

        Raises:
            (ValueError): var_data is None
        """
        # Check for the "special" shell vars.
        if var_data is None:
            raise ValueError("Unexpected var_data: None")
        if var_name.upper() == "PATH":
            self.set_path(var_data)
        elif var_name.upper() == "PYTHONPATH":
            self.set_pypath(var_data)
        else:
            self.logger.debug("Updating SHELL VAR element '%s': '%s'." % (var_name, var_data))
            self.active_environ[var_name] = var_data
            os.environ[var_name] = var_data


def GetEnvironment() -> ShellEnvironment:
    """Returns the environment.

    Returns:
        (ShellEnvironment): Singleton class
    """
    return ShellEnvironment()


def GetBuildVars() -> var_dict.VarDict:
    """The current checkpoint buildvar values.

    Returns:
        (VarDict): A special dictionary containing build vars
    """

    #
    # Tricky!
    # Define a wrapper class that always forwards commands to the
    # BuildVars associated with the current environment.
    #
    # Will be deprecated.
    #
    class BuildVarsWrapper(object):
        def __init__(self) -> None:
            self.internal_shell_env = ShellEnvironment()

        def __getattr__(self, attrname: str) -> Any:  # noqa: ANN401
            # Instead, invoke on the active BuildVars object.
            return getattr(self.internal_shell_env.active_buildvars, attrname)

    return BuildVarsWrapper()


#
# TODO: These are convenience methods that should be deprecated.
#
checkpoint_list = []


def CheckpointBuildVars() -> None:
    """Creates a checkpoint [a screenshot in time] of all current build var values."""
    global checkpoint_list
    new_checkpoint = ShellEnvironment().checkpoint()
    checkpoint_list.append(new_checkpoint)
    MY_LOGGER.debug("Created checkpoint {0} for build vars".format(new_checkpoint))


def RevertBuildVars() -> None:
    """Reverts all build var values to the most recent checkpoint."""
    global checkpoint_list
    if len(checkpoint_list) > 0:
        last_checkpoint = checkpoint_list.pop()
        MY_LOGGER.debug("Reverting to checkpoint {0} for build vars".format(last_checkpoint))
        ShellEnvironment().restore_checkpoint(last_checkpoint)
    else:
        MY_LOGGER.getLogger("No more checkpoints!")
        raise RuntimeError("No more checkpoints!")
