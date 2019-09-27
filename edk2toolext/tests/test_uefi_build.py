# @file test_uefi_build.py
# Unit test suite for the UefiB class.
#
##
# Copyright (c) Microsoft Corporation
#
# SPDX-License-Identifier: BSD-2-Clause-Patent
##
import unittest
from edk2toolext.environment import uefi_build
from edk2toolext.environment.plugintypes import uefi_helper_plugin
from edk2toolext.environment.plugin_manager import PluginManager
import argparse
import tempfile


class TestUefiBuild(unittest.TestCase):

    def setUp(self):
        self.WORKSPACE = tempfile.mkdtemp()
        pass

    def tearDown(self):
        pass

    @classmethod
    def setUpClass(cls):
        pass

    @classmethod
    def tearDownClass(cls):
        pass

    def test_init(self):
        builder = uefi_build.UefiBuilder()
        self.assertIsNotNone(builder)

    def test_commandline_options(self):
        builder = uefi_build.UefiBuilder()
        parserObj = argparse.ArgumentParser()
        builder.AddCommandLineOptions(parserObj)
        args = [
            ["--CLEAN", "--SKIPBUILD"],
            ["--FLASHONLY"],
            ["--CLEANONLY"],
            ["--FLASHROM"],
            ["--UPDATECONF"],
            ["--FLASHONLY"],
            ["--SKIPPREBUILD"],
            ["--SKIPPOSTBUILD"]
        ]
        for argpart in args:
            results = parserObj.parse_args(argpart)
            builder.RetrieveCommandLineOptions(results)

    def test_go_skip_building(self):
        builder = uefi_build.UefiBuilder()
        builder.SkipPostBuild = True
        builder.SkipBuild = True
        builder.SkipBuild = True
        manager = PluginManager()
        helper = uefi_helper_plugin.HelperFunctions()
        ret = builder.Go(self.WORKSPACE, "", helper, manager)
        self.assertEqual(ret, 0)

    # TODO finish unit test


if __name__ == '__main__':
    unittest.main()
