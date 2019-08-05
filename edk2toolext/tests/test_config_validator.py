## @file test_config_validator.py
# This contains unit tests for config validator
#
##
# Copyright (c) Microsoft Corporation
#
# SPDX-License-Identifier: BSD-2-Clause-Patent
##
import tempfile
import logging
import os
import unittest
from io import StringIO
from edk2toolext import config_validator
import yaml


test_dir = None
plugin_list = []


class Edk2Path_Injected(object):
    def __init__(self):
        self.WorkspacePath = None

    def GetAbsolutePathOnThisSytemFromEdk2RelativePath(self, package):
        return os.path.abspath(self.WorkspacePath)


class PluginList_Injected(object):
    def __init__(self, name):
        self.descriptor = dict()
        self.Obj = None
        self.Name = name


class Testconfig_validator(unittest.TestCase):

    @classmethod
    def setUpClass(cls):
        global test_dir
        global plugin_list

        logger = logging.getLogger('')
        logger.addHandler(logging.NullHandler())
        unittest.installHandler()
        # get a temporary directory that we can create the right folders
        test_dir = Edk2Path_Injected()
        test_dir.WorkspacePath = tempfile.mkdtemp()

    def test_valid_config(self):
        global test_dir
        global plugin_list
        yaml_string = StringIO("""
        {
            "Name": "Project Mu Plus Repo CI Build",
            "GroupName": "MuPlus",

            # Workspace path relative to this file
            "RelativeWorkspaceRoot": "",
            "Scopes": [ "corebuild" ],

            # Other Repos that are dependencies
            "Dependencies": [
                # FileSystem Path relative to workspace
                # Url
                # Branch
                # Commit
                {
                    "Path": "MU_BASECORE",
                    "Url": "https://github.com/Microsoft/mu_basecore.git",
                    "Branch": "release/201808"
                },
            ],

            # Edk2 style PackagesPath for resolving dependencies.
            # Only needed if it isn't this package and isn't a dependency
            "PackagesPath": [],

            # Packages in this repo
            "Packages": [
                "UefiTestingPkg"
            ],
            "ArchSupported": [
                "IA32",
                "X64",
                "AARCH64"
            ],
            "Targets": [
                "DEBUG",
                "RELEASE"
            ]
        }
        """)

        valid_config = yaml.safe_load(yaml_string)
        # make sure the valid configuration is read just fine
        try:
            config_validator.check_mu_confg(valid_config, test_dir, plugin_list)
        except Exception as e:
            self.fail("We shouldn't throw an exception", e)

    def test_invalid_configs(self):
        global test_dir
        global plugin_list
        bad_yaml_string = StringIO("""
        {
            "Name": "Project Mu Plus Repo CI Build",
            "GroupName": "MuPlus",

            # Workspace path relative to this file
            "RelativeWorkspaceRoot": "",
            "InvalidAttribute": "this will throw an error",
            "Scopes": [ "corebuild" ],

            # Other Repos that are dependencies
            "Dependencies": [
                # FileSystem Path relative to workspace
                # Url
                # Branch
                # Commit
                {
                    "Path": "MU_BASECORE",
                    "Url": "https://github.com/Microsoft/mu_basecore.git",
                    "Branch": "release/201808"
                },
            ],

            # Edk2 style PackagesPath for resolving dependencies.
            # Only needed if it isn't this package and isn't a dependency
            "PackagesPath": [],

            # Packages in this repo
            "Packages": [
                "UefiTestingPkg"
            ],
            "ArchSupported": [
                "IA32",
                "X64",
                "AARCH64"
            ],
            "Targets": [
                "DEBUG",
                "RELEASE"
            ]
        }
        """)
        invalid_config = yaml.safe_load(bad_yaml_string)
        with self.assertRaises(Exception):
            config_validator.check_mu_confg(invalid_config, test_dir, plugin_list)

    def test_invalid_url_config(self):
        global test_dir
        global plugin_list

        bad_url_yaml_string = StringIO("""
        {
            "Name": "Project Mu Plus Repo CI Build",
            "GroupName": "MuPlus",

            # Workspace path relative to this file
            "RelativeWorkspaceRoot": "",
            "Scopes": [ "corebuild" ],

            # Other Repos that are dependencies
            "Dependencies": [
                # FileSystem Path relative to workspace
                # Url
                # Branch
                # Commit
                {
                    "Path": "MU_BASECORE",
                    "Url": "https://github.com/InvalidRepo",
                    "Branch": "release/201808"
                },
            ],

            # Edk2 style PackagesPath for resolving dependencies.
            # Only needed if it isn't this package and isn't a dependency
            "PackagesPath": [],

            # Packages in this repo
            "Packages": [
                "UefiTestingPkg"
            ],
            "ArchSupported": [
                "IA32",
                "X64",
                "AARCH64"
            ],
            "Targets": [
                "DEBUG",
                "RELEASE"
            ]
        }
        """)

        invalid_config = yaml.safe_load(bad_url_yaml_string)
        with self.assertRaises(Exception):
            config_validator.check_mu_confg(invalid_config, test_dir, plugin_list)


if __name__ == '__main__':
    unittest.main()
