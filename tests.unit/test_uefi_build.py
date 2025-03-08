# @file test_uefi_build.py
# Unit test suite for the UefiB class.
#
##
# Copyright (c) Microsoft Corporation
#
# SPDX-License-Identifier: BSD-2-Clause-Patent
##
"""Unit test for the UefiBuilder class."""

import argparse
import logging
import os
import stat
import tempfile
import unittest
from inspect import cleandoc

import pytest
from edk2toolext.environment import shell_environment, uefi_build
from edk2toolext.environment.plugin_manager import PluginManager
from edk2toolext.environment.plugintypes import uefi_helper_plugin
from edk2toollib.utility_functions import GetHostInfo


class TestUefiBuild(unittest.TestCase):
    """Unit test for the UefiBuilder class."""

    def setUp(self) -> None:
        """Create a temporary workspace and a minimal UEFI build tree."""
        self.WORKSPACE = tempfile.mkdtemp()
        TestUefiBuild.create_min_uefi_build_tree(self.WORKSPACE)

    def tearDown(self) -> None:
        """Restore the initial checkpoint."""
        shell_environment.GetEnvironment().restore_initial_checkpoint()

    def test_init(self) -> None:
        """Test that the UefiBuilder can be initialized."""
        builder = uefi_build.UefiBuilder()
        self.assertIsNotNone(builder)

    @classmethod
    def write_to_file(cls, path: str, contents: str, close: bool = True) -> None:
        """Write contents to a file."""
        f = open(path, "w")
        f.writelines(contents)
        if close:
            f.close()

    @classmethod
    def create_min_uefi_build_tree(cls, root: str) -> None:
        """Create a minimal UEFI build tree."""
        conf_folder = os.path.join(root, "Conf")
        os.makedirs(conf_folder)
        target_path = os.path.join(conf_folder, "target.template")
        TestUefiBuild.write_to_file(
            target_path, ["ACTIVE_PLATFORM = Test.dsc\n", "TOOL_CHAIN_TAG = test\n", "TARGET = DEBUG\n"]
        )
        tools_path = os.path.join(conf_folder, "tools_def.template")
        TestUefiBuild.write_to_file(tools_path, ["*_VS2022_*_*_FAMILY        = MSFT"])
        build_path = os.path.join(conf_folder, "build_rule.template")
        TestUefiBuild.write_to_file(build_path, ["hello"])
        platform_path = os.path.join(root, "Test.dsc")
        TestUefiBuild.write_to_file(platform_path, ["[Defines]\n", "OUTPUT_DIRECTORY = Build"])

    def test_commandline_options(self) -> None:
        """Test that command line options can be added and retrieved."""
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
            ["--SKIPPOSTBUILD"],
        ]
        for argpart in args:
            results = parserObj.parse_args(argpart)
            builder.RetrievePlatformCommandLineOptions(results)

    def test_go_skip_building(self) -> None:
        """Test that building can be skipped."""
        builder = uefi_build.UefiBuilder()
        builder.SkipPostBuild = True
        builder.SkipBuild = True
        builder.SkipBuild = True
        manager = PluginManager()
        shell_environment.GetBuildVars().SetValue("EDK_TOOLS_PATH", self.WORKSPACE, "empty")
        helper = uefi_helper_plugin.HelperFunctions()
        ret = builder.Go(self.WORKSPACE, "", helper, manager)
        self.assertEqual(ret, 0)

    def test_build_wrapper(self) -> None:
        """Tests that a build wrapper can be used."""
        builder = uefi_build.UefiBuilder()

        # Post-build is not needed to test the build wrapper
        builder.SkipPostBuild = True

        # Some basic build variables need to be set to make it through
        # the build preamble to the point the wrapper gets called.
        shell_environment.GetBuildVars().SetValue("TARGET_ARCH", "IA32", "Set in build wrapper test")
        shell_environment.GetBuildVars().SetValue("EDK_TOOLS_PATH", self.WORKSPACE, "Set in build wrapper test")

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

        TestUefiBuild.write_to_file(build_wrapper_path, cleandoc(build_wrapper_file_content))

        if GetHostInfo().os == "Linux":
            os.chmod(build_wrapper_path, os.stat(build_wrapper_path).st_mode | stat.S_IEXEC)

        # This is the main point of this test. The wrapper file should be
        # executed instead of the build command. In real scenarios, the wrapper
        # script would subsequently call the build command.
        shell_environment.GetBuildVars().SetValue("EDK_BUILD_CMD", build_wrapper_cmd, "Set in build wrapper test")
        shell_environment.GetBuildVars().SetValue("EDK_BUILD_PARAMS", build_wrapper_params, "Set in build wrapper test")

        manager = PluginManager()
        helper = uefi_helper_plugin.HelperFunctions()
        ret = builder.Go(self.WORKSPACE, "", helper, manager)

        # Check the build wrapper return code
        self.assertEqual(ret, 0)

        # Check that the build wrapper ran successfully by checking that the
        # file written by the build wrapper file exists
        self.assertTrue(os.path.isfile(test_file_path))

    # TODO finish unit test


def test_missing_ENV_variables(tmp_path: str, caplog: pytest.LogCaptureFixture) -> None:
    """Test that the build fails and logs a clean message when environment variables are missing."""
    with caplog.at_level(logging.ERROR):
        TestUefiBuild().create_min_uefi_build_tree(tmp_path)
        target_template = os.path.join(tmp_path, "Conf", "target.template")
        builder = uefi_build.UefiBuilder()
        manager = PluginManager()
        helper = uefi_helper_plugin.HelperFunctions()

        #
        # 1. Make sure we error and log a clean message when TOOL_CHAIN_TAG is missing
        #
        shell_environment.GetBuildVars().SetValue("EDK_TOOLS_PATH", str(tmp_path), "Set in build wrapper test")
        os.remove(target_template)
        TestUefiBuild.write_to_file(target_template, ["ACTIVE_PLATFORM = Test.dsc\n"])
        ret = builder.Go(str(tmp_path), "", helper, manager)

        # two error messages are logged when the environment variable is missing
        assert ret == -1
        assert len(list(filter(lambda r: r.levelno == logging.ERROR, caplog.records))) == 2
        assert len(list(filter(lambda r: "TOOL_CHAIN_TAG" in r.message, caplog.records))) == 1

        #
        # 2. Delete artifacts
        #
        for file in (tmp_path / "Conf").glob("**/*.txt"):
            file.unlink()
        caplog.clear()

        #
        # 3. Make sure we error and log a clean message when TARGET is missing
        #
        os.remove(target_template)
        TestUefiBuild.write_to_file(target_template, ["ACTIVE_PLATFORM = Test.dsc\n", "TOOL_CHAIN_TAG = VS2022\n"])
        ret = builder.Go(str(tmp_path), "", helper, manager)

        # two error messages are logged when the environment variable is missing
        assert ret == -1
        assert len(list(filter(lambda r: r.levelno == logging.ERROR, caplog.records))) == 2
        assert len(list(filter(lambda r: "TARGET" in r.message, caplog.records))) == 1


if __name__ == "__main__":
    unittest.main()
