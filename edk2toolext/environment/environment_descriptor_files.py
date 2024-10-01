# @file EnvironmentDescriptorFiles.py
# This module contains code for working with the JSON environment
# descriptor files. It can parse the files, validate them, and return
# objects representing their contents.
#
##
# Copyright (c) Microsoft Corporation
#
# SPDX-License-Identifier: BSD-2-Clause-Patent
##
"""This module contains code for working with the JSON environment descriptor files.

It can parse the files, validate them, and return objects representing their contents.
"""

import os

import yaml


class PathEnv(object):
    """Path env object that is created from the descriptor file.

    Attributes:
        scope (string): scope the path env is associated with
        flags (List[str]): flags associated with the path env
        var_name (string): ENV var to set with the object
        descriptor_location (string): location of the PathEnv
        published_path (string): location of the PathEnv
    """

    def __init__(self, descriptor: dict) -> None:
        """Init with the descriptor information."""
        super(PathEnv, self).__init__()

        #
        # Set the data for this object.
        #
        self.scope = descriptor["scope"]
        self.flags = descriptor["flags"]
        self.var_name = descriptor.get("var_name", None)

        self.descriptor_location = os.path.dirname(descriptor["descriptor_file"])
        self.published_path = self.descriptor_location


class DescriptorFile(object):
    """The base class for the different types of descriptor files.

    Attributes:
        file_path (str): descriptor file path
        descriptor_contents (Dict): Contents of the descriptor file
    """

    def __init__(self, file_path: str) -> None:
        """Loads the contents of the descriptor file and validates.

        Args:
            file_path (str): path to descriptor file

        Raises:
            (ValueError): Missing specified value from descriptor file
        """
        super(DescriptorFile, self).__init__()

        self.file_path = file_path
        self.descriptor_contents = None

        with open(file_path, "r") as file:
            try:
                self.descriptor_contents = yaml.safe_load(file)
            except Exception:
                pass  # We'll pick up this error when looking at the data.

        #
        # Make sure that we loaded the file successfully.
        #
        if self.descriptor_contents is None:
            raise ValueError("Could not load contents of descriptor file '%s'!" % file_path)

        # The file path is an implicit descriptor field.
        self.descriptor_contents["descriptor_file"] = self.file_path

        # All files require a scope.
        if "scope" not in self.descriptor_contents:
            raise ValueError("File '%s' missing required field '%s'!" % (self.file_path, "scope"))

        # If a file has flags, make sure they're sane.
        if "flags" in self.descriptor_contents:
            # If a flag requires a name, make sure a name is provided.
            for name_required in ("set_shell_var", "set_build_var"):
                if name_required in self.descriptor_contents["flags"]:
                    if "var_name" not in self.descriptor_contents:
                        raise ValueError(
                            "File '%s' has a flag requesting a var, but does not provide 'var_name'!" % self.file_path
                        )

        # clean up each string item for more reliable processing
        for k, v in self.descriptor_contents.items():
            if isinstance(v, str):
                self.descriptor_contents[k] = self.sanitize_string(v)

    def sanitize_string(self, s: str) -> str:
        """Clean up a string "value" in the descriptor file."""
        # Perform any actions needed to clean the string.
        return s.strip()


class PathEnvDescriptor(DescriptorFile):
    """Descriptor File for a PATH ENV."""

    def __init__(self, file_path: str) -> None:
        """Inits the descriptor as a PathEnvDescriptor from the provided path.

        Loads the contents of the filepath into descriptor_contents

        Args:
            file_path (str): path to the yaml descriptor file
        """
        super(PathEnvDescriptor, self).__init__(file_path)

        #
        # Validate file contents.
        #
        # Make sure that the required fields are present.
        for required_field in ("flags",):
            if required_field not in self.descriptor_contents:
                raise ValueError("File '%s' missing required field '%s'!" % (self.file_path, required_field))


class ExternDepDescriptor(DescriptorFile):
    """Descriptor File for a External Dependency.

    Attributes:
            descriptor_contents (Dict): Contents of the Descriptor yaml file
            file_path (PathLike): path to the descriptor file
    """

    def __init__(self, file_path: str) -> None:
        """Inits the descriptor as a ExternDepDescriptor from the provided path.

        Loads the contents of the filepath into descriptor_contents

        Args:
            file_path (str): path to the yaml descriptor file
        """
        super(ExternDepDescriptor, self).__init__(file_path)

        #
        # Validate file contents.
        #
        # Make sure that the required fields are present.
        for required_field in ("scope", "type", "name", "source", "version"):
            if required_field not in self.descriptor_contents:
                raise ValueError("File '%s' missing required field '%s'!" % (self.file_path, required_field))


class PluginDescriptor(DescriptorFile):
    """Descriptor File for a Plugin.

    Attributes:
        descriptor_contents (Dict): Contents of the Descriptor yaml file
        file_path (PathLike): path to the descriptor file
    """

    def __init__(self, file_path: str) -> None:
        """Inits the descriptor as a PluginDescriptor from the provided path.

        Loads the contents of the filepath into descriptor_contents

        Args:
            file_path (str): path to the yaml descriptor file
        """
        super(PluginDescriptor, self).__init__(file_path)

        #
        # Validate file contents.
        #
        # Make sure that the required fields are present.
        for required_field in ("scope", "name", "module"):
            if required_field not in self.descriptor_contents:
                raise ValueError("File '%s' missing required field '%s'!" % (self.file_path, required_field))

        # Make sure the module item doesn't have .py on the end
        if self.descriptor_contents["module"].lower().endswith(".py"):
            # remove last 3 chars
            self.descriptor_contents["module"] = self.descriptor_contents["module"][:-3]
