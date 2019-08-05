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
import os
import yaml


class PathEnv(object):
    def __init__(self, descriptor):
        super(PathEnv, self).__init__()

        #
        # Set the data for this object.
        #
        self.scope = descriptor['scope']
        self.flags = descriptor['flags']
        self.var_name = descriptor.get('var_name', None)

        self.descriptor_location = os.path.dirname(
            descriptor['descriptor_file'])
        self.published_path = self.descriptor_location


class DescriptorFile(object):
    def __init__(self, file_path):
        super(DescriptorFile, self).__init__()

        self.file_path = file_path
        self.descriptor_contents = None

        with open(file_path, 'r') as file:
            try:
                self.descriptor_contents = yaml.safe_load(file)
            except:
                pass  # We'll pick up this error when looking at the data.

        #
        # Make sure that we loaded the file successfully.
        #
        if self.descriptor_contents is None:
            raise ValueError(
                "Could not load contents of descriptor file '%s'!" % file_path)

        # The file path is an implicit descriptor field.
        self.descriptor_contents['descriptor_file'] = self.file_path

        # All files require a scope.
        if 'scope' not in self.descriptor_contents:
            raise ValueError("File '%s' missing required field '%s'!" %
                             (self.file_path, 'scope'))

        # If a file has flags, make sure they're sane.
        if 'flags' in self.descriptor_contents:
            # If a flag requires a name, make sure a name is provided.
            for name_required in ('set_shell_var', 'set_build_var'):
                if name_required in self.descriptor_contents['flags']:
                    if 'var_name' not in self.descriptor_contents:
                        raise ValueError(
                            "File '%s' has a flag requesting a var, but does not provide 'var_name'!" % self.file_path)

        # clean up each string item for more reliable processing
        for (k, v) in self.descriptor_contents.items():
            if(isinstance(v, str)):
                self.descriptor_contents[k] = self.sanitize_string(v)

    #
    # Clean up a string "value" in the descriptor file.
    #
    def sanitize_string(self, s):
        # Perform any actions needed to clean the string.
        return s.strip()


class PathEnvDescriptor(DescriptorFile):
    def __init__(self, file_path):
        super(PathEnvDescriptor, self).__init__(file_path)

        #
        # Validate file contents.
        #
        # Make sure that the required fields are present.
        for required_field in ('flags',):
            if required_field not in self.descriptor_contents:
                raise ValueError("File '%s' missing required field '%s'!" % (
                    self.file_path, required_field))


class ExternDepDescriptor(DescriptorFile):
    def __init__(self, file_path):
        super(ExternDepDescriptor, self).__init__(file_path)

        #
        # Validate file contents.
        #
        # Make sure that the required fields are present.
        for required_field in ('scope', 'type', 'name', 'source', 'version'):
            if required_field not in self.descriptor_contents:
                raise ValueError("File '%s' missing required field '%s'!" % (
                    self.file_path, required_field))


class PluginDescriptor(DescriptorFile):
    def __init__(self, file_path):
        super(PluginDescriptor, self).__init__(file_path)

        #
        # Validate file contents.
        #
        # Make sure that the required fields are present.
        for required_field in ('scope', 'name', 'module'):
            if required_field not in self.descriptor_contents:
                raise ValueError("File '%s' missing required field '%s'!" % (
                    self.file_path, required_field))

        # Make sure the module item doesn't have .py on the end
        if(self.descriptor_contents["module"].lower().endswith(".py")):
            # remove last 3 chars
            self.descriptor_contents["module"] = self.descriptor_contents["module"][:-3]
