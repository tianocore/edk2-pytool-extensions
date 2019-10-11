# @file test_edk2_plat_build.py
# This contains unit tests for the edk2_plat_build
##
# Copyright (c) Microsoft Corporation
#
# SPDX-License-Identifier: BSD-2-Clause-Patent
##
import unittest
from edk2toolext.invocables.edk2_platform_build import Edk2PlatformBuild
import tempfile
import sys
import os
import logging
from importlib import reload
from edk2toolext.environment import shell_environment

class_info = '''
from edk2toolext.invocables.edk2_platform_build import BuildSettingsManager
class TestSettingsManager(BuildSettingsManager):

    def GetActiveScopes(self):
        return []

    def GetWorkspaceRoot(self):
        return WORKSPACE

    def GetPackagesPath(self):
        return []

    def AddCommandLineOptions(self, parserObj):
        pass

    def RetrieveCommandLineOptions(self, args):
        pass

    def GetName(self):
        return "TestPlatBuild"

    def GetArchitecturesSupported(self):
        return []

    def GetPackagesSupported(self):
        return []

    def GetTargetsSupported(self):
        return []

from edk2toolext.environment.uefi_build import UefiBuilder
class TestBuilder(UefiBuilder):
    def SetPlatformEnv(self):
        self.env.SetValue("EDK2_BASE_TOOLS_DIR", WORKSPACE, "empty")
        return 0
'''


class TestEdk2PlatBuild(unittest.TestCase):

    def setUp(self):
        TestEdk2PlatBuild.restart_logging()
        pass

    def tearDown(self):
        shell_environment.GetEnvironment().restore_initial_checkpoint()
        TestEdk2PlatBuild.restart_logging()
        pass

    @classmethod
    def create_min_uefi_build_tree(cls, root):
        conf_folder = os.path.join(root, "Conf")
        os.makedirs(conf_folder)
        target_path = os.path.join(conf_folder, "target.template")
        cls.write_to_file(target_path, ["ACTIVE_PLATFORM = Test.dsc\n",
                                        "TOOL_CHAIN_TAG = test\n",
                                        "TARGET_ARCH = X64\n",
                                        "TARGET = DEBUG\n"])
        tools_path = os.path.join(conf_folder, "tools_def.template")
        cls.write_to_file(tools_path, ["hello"])
        build_path = os.path.join(conf_folder, "build_rule.template")
        cls.write_to_file(build_path, ["hello"])
        platform_path = os.path.join(root, "Test.dsc")
        cls.write_to_file(platform_path, ["[Defines]\n",
                                          "OUTPUT_DIRECTORY = Build"])

    @classmethod
    def restart_logging(cls):
        logging.shutdown()
        reload(logging)

    @classmethod
    def setUpClass(cls):
        pass

    @classmethod
    def tearDownClass(cls):
        pass

    def test_init(self):
        builder = Edk2PlatformBuild()
        self.assertIsNotNone(builder)

    @classmethod
    def write_to_file(cls, path, contents, close=True):
        f = open(path, "w")
        f.writelines(contents)
        if close:
            f.close()

    def test_ci_setup(self):
        WORKSPACE = tempfile.mkdtemp()
        builder = Edk2PlatformBuild()
        self.create_min_uefi_build_tree(WORKSPACE)
        workspace_abs = os.path.abspath(WORKSPACE).replace("\\", "\\\\")
        settings_file = os.path.abspath(os.path.join(WORKSPACE, "settings.py"))
        real_class = class_info.replace("WORKSPACE", f'"{workspace_abs}"')
        print(settings_file)
        TestEdk2PlatBuild.write_to_file(settings_file, real_class)
        sys.argv = ["stuart_build", "-c", settings_file]
        try:
            builder.Invoke()
        except SystemExit:
            # self.assertEqual(e.code, 0, "We should have a non zero error code")
            # we'll fail because we don't have the build command
            pass
