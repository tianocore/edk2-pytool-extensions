# @file test_uefi_build.py
# Unit test suite for the UefiB class.
#
##
# Copyright (c) Microsoft Corporation
#
# SPDX-License-Identifier: BSD-2-Clause-Patent
##
import unittest
import pytest
from edk2toolext.environment import uefi_build
from edk2toolext.environment.plugintypes import uefi_helper_plugin, uefi_build_plugin
from edk2toolext.environment.plugin_manager import PluginManager, PluginDescriptor
from edk2toollib.utility_functions import GetHostInfo
import argparse
import tempfile
import os
import stat
from inspect import cleandoc
from edk2toolext.environment import shell_environment

# Raise exceptions in Plugins to show that they successfuly execute.
class _AllPlugin(uefi_build_plugin.IUefiBuildPlugin):
    def runs_on(self, thebuilder) -> str:
        return "all"
    
    def do_pre_build(self, thebuilder):
        raise Exception

    def do_post_build(self, thebuilder):
        raise Exception

class _SingleModulePlugin(uefi_build_plugin.IUefiBuildPlugin):
    def runs_on(self, thebuilder) -> str:
        return "single-module"

    def do_pre_build(self, thebuilder):
        raise Exception

    def do_post_build(self, thebuilder):    
        raise Exception

class _MultiModulePlugin(uefi_build_plugin.IUefiBuildPlugin):
    def runs_on(self, thebuilder) -> str:
        return "multi-module"

    def do_pre_build(self, thebuilder):
        raise Exception

    def do_post_build(self, thebuilder):
        raise Exception

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

    def test_build_wrapper(self):
        """Tests that a build wrapper can be used."""
        builder = uefi_build.UefiBuilder()

        # Post-build is not needed to test the build wrapper
        builder.SkipPostBuild = True

        # Some basic build variables need to be set to make it through
        # the build preamble to the point the wrapper gets called.
        shell_environment.GetBuildVars().SetValue("TARGET_ARCH",
                                                  "IA32",
                                                  "Set in build wrapper test")
        shell_environment.GetBuildVars().SetValue("EDK_TOOLS_PATH",
                                                  self.WORKSPACE,
                                                  "Set in build wrapper test")

        # "build_wrapper" -> The actual build_wrapper script
        # "test_file" -> An empty file written by build_wrapper
        build_wrapper_path = os.path.join(self.WORKSPACE, "build_wrapper")
        test_file_path = os.path.join(self.WORKSPACE, "test_file")

        # This script will write an empty file called "test_file" to the
        # temporary directory (workspace) to demonstrate that it ran successfully
        build_wrapper_file_content = """
            import os
            import sys

            test_file_dir = os.path.dirname(os.path.realpath(__file__))
            test_file_path = os.path.join(test_file_dir, "test_file")

            with open(test_file_path, 'w'):
                pass

            sys.exit(0)
            """

        build_wrapper_cmd = "python"
        build_wrapper_params = os.path.normpath(build_wrapper_path)

        TestUefiBuild.write_to_file(
            build_wrapper_path,
            cleandoc(build_wrapper_file_content))

        if GetHostInfo().os == "Linux":
            os.chmod(build_wrapper_path,
                     os.stat(build_wrapper_path).st_mode | stat.S_IEXEC)

        # This is the main point of this test. The wrapper file should be
        # executed instead of the build command. In real scenarios, the wrapper
        # script would subsequently call the build command.
        shell_environment.GetBuildVars().SetValue(
            "EDK_BUILD_CMD", build_wrapper_cmd, "Set in build wrapper test")
        shell_environment.GetBuildVars().SetValue(
            "EDK_BUILD_PARAMS", build_wrapper_params, "Set in build wrapper test")

        manager = PluginManager()
        helper = uefi_helper_plugin.HelperFunctions()
        ret = builder.Go(self.WORKSPACE, "", helper, manager)

        # Check the build wrapper return code
        self.assertEqual(ret, 0)

        # Check that the build wrapper ran successfully by checking that the
        # file written by the build wrapper file exists
        self.assertTrue(os.path.isfile(test_file_path))

    
    # TODO finish unit test


def test_build_plugins():
    builder = uefi_build.UefiBuilder()
    builder.env = shell_environment.GetBuildVars()
    builder.pm = PluginManager()

    ####################################
    # Test Valid Plugin for "all" type #
    ####################################
    plugin = PluginDescriptor.__new__(PluginDescriptor)
    plugin.Obj = _AllPlugin()

    ####################################
    # a. Run on multi-module build     #
    ####################################
    builder.env.SetValue("BUILDMODULE", "", "Set in Test", overridable=True)
    builder.pm.Descriptors = [plugin]
    with pytest.raises(Exception):
        builder.PreBuild()
    with pytest.raises(Exception):
        builder.PostBuild()

    ####################################
    # b. Run on single-module build    #
    ####################################
    builder.env.SetValue("BUILDMODULE", "Path/To/Module", "Set in Test", overridable=True)
    with pytest.raises(Exception):
        builder.PreBuild()  # plugin should run, so we should assert
    with pytest.raises(Exception):
        builder.PostBuild()  # plugin should run, so we should assert

    ##############################################
    # Test Valid Plugin for "single-module" type #
    ##############################################
    plugin = PluginDescriptor.__new__(PluginDescriptor)
    plugin.Obj = _SingleModulePlugin()

    ##############################################
    # a. Run on multi-mode build                 #
    ##############################################
    builder.env.SetValue("BUILDMODULE", "", "Set in Test", overridable=True)
    builder.pm.Descriptors = [plugin]
    builder.PreBuild()  # Plugin should not run, so we should not assert
    builder.PostBuild()  # Plugin should not run, so we should not assert

    ##############################################
    # b. Run on single-module build              #
    ##############################################
    builder.env.SetValue("BUILDMODULE", "Path/To/Module", "Set in Test", overridable=True)
    builder.pm.Descriptors = [plugin]
    with pytest.raises(Exception):
        builder.PreBuild()  # plugin should run, so we should assert
    with pytest.raises(Exception):
        builder.PostBuild()  # plugin should run, so we should assert

    #############################################
    # Test Valid Plugin for "multi-module" type #
    #############################################
    plugin = PluginDescriptor.__new__(PluginDescriptor)
    plugin.Obj = _MultiModulePlugin()

    #############################################
    # a. Run on multi-mode build                #
    #############################################
    builder.env.SetValue("BUILDMODULE", "", "Set in Test", overridable=True)
    builder.pm.Descriptors = [plugin]
    with pytest.raises(Exception):
        builder.PreBuild()  # plugin should run, so we should assert
    with pytest.raises(Exception):
        builder.PostBuild()  # plugin should run, so we should assert

    #############################################
    # b. Run on single-module build             #
    #############################################
    builder.env.SetValue("BUILDMODULE", "Path/To/Module", "Set in Test", overridable=True)
    builder.pm.Descriptors = [plugin]
    builder.PreBuild()  # Plugin should not run, so we should not assert
    builder.PostBuild()  # Plugin should not run, so we should not assert
