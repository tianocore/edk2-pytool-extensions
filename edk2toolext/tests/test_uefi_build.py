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
import os
from edk2toolext.environment import shell_environment


class TestUefiBuild(unittest.TestCase):

    def setUp(self):
        self.WORKSPACE = tempfile.mkdtemp()
        TestUefiBuild.create_min_uefi_build_tree(self.WORKSPACE)
        pass

    def tearDown(self):
        shell_environment.GetEnvironment().restore_initial_checkpoint()
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

    @classmethod
    def write_to_file(cls, path, contents, close=True):
        f = open(path, "w")
        f.writelines(contents)
        if close:
            f.close()

    @classmethod
    def create_min_uefi_build_tree(cls, root):
        conf_folder = os.path.join(root, "Conf")
        os.makedirs(conf_folder)
        target_path = os.path.join(conf_folder, "target.template")
        TestUefiBuild.write_to_file(target_path, ["ACTIVE_PLATFORM = Test.dsc\n",
                                                  "TOOL_CHAIN_TAG = test\n",
                                                  "TARGET = DEBUG\n"])
        tools_path = os.path.join(conf_folder, "tools_def.template")
        TestUefiBuild.write_to_file(tools_path, ["hello"])
        build_path = os.path.join(conf_folder, "build_rule.template")
        TestUefiBuild.write_to_file(build_path, ["hello"])
        platform_path = os.path.join(root, "Test.dsc")
        TestUefiBuild.write_to_file(platform_path, ["[Defines]\n",
                                                    "OUTPUT_DIRECTORY = Build"])

    def test_commandline_options(self):
        builder = uefi_build.UefiBuilder()
        parserObj = argparse.ArgumentParser()
        builder.AddPlatformCommandLineOptions(parserObj)
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
            builder.RetrievePlatformCommandLineOptions(results)

    def test_go_skip_building(self):
        builder = uefi_build.UefiBuilder()
        builder.SkipPostBuild = True
        builder.SkipBuild = True
        builder.SkipBuild = True
        manager = PluginManager()
        shell_environment.GetBuildVars().SetValue("EDK_TOOLS_PATH", self.WORKSPACE, "empty")
        helper = uefi_helper_plugin.HelperFunctions()
        ret = builder.Go(self.WORKSPACE, "", helper, manager)
        self.assertEqual(ret, 0)

    # TODO finish unit test


if __name__ == '__main__':
    unittest.main()
