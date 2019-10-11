# @file test_edk2_setup.py
# This contains unit tests for the edk2_ci_setup
##
# Copyright (c) Microsoft Corporation
#
# SPDX-License-Identifier: BSD-2-Clause-Patent
##
import unittest
from edk2toolext.invocables.edk2_setup import Edk2PlatformSetup
import tempfile
import sys
import os
import logging
from importlib import reload
from edk2toolext.environment import shell_environment

class_info = '''
from edk2toolext.invocables.edk2_setup import SetupSettingsManager
class TestSettingsManager(SetupSettingsManager):

    def GetActiveScopes(self):
        return []

    def GetWorkspaceRoot(self):
        return WORKSPACE

    def GetRequiredSubmodules(self):
        return []

    def AddCommandLineOptions(self, parserObj):
        pass

    def RetrieveCommandLineOptions(self, args):
        pass

    def GetName(self):
        return "TestCI"

    def GetArchitecturesSupported(self):
        return []

    def GetPackagesSupported(self):
        return []

    def GetTargetsSupported(self):
        return []
'''


class TestEdk2Setup(unittest.TestCase):

    def setUp(self):
        TestEdk2Setup.restart_logging()
        pass

    def tearDown(self):
        shell_environment.GetEnvironment().restore_initial_checkpoint()
        TestEdk2Setup.restart_logging()
        pass

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
        builder = Edk2PlatformSetup()
        self.assertIsNotNone(builder)

    @classmethod
    def write_to_file(cls, path, contents, close=True):
        f = open(path, "w")
        f.writelines(contents)
        if close:
            f.close()

    def test_ci_setup(self):
        WORKSPACE = tempfile.mkdtemp()
        builder = Edk2PlatformSetup()
        workspace_abs = os.path.abspath(WORKSPACE).replace("\\", "\\\\")
        settings_file = os.path.abspath(os.path.join(WORKSPACE, "settings.py"))
        real_class = class_info.replace("WORKSPACE", f'"{workspace_abs}"')
        print(settings_file)
        TestEdk2Setup.write_to_file(settings_file, real_class)
        sys.argv = ["stuart_setup", "-c", settings_file]
        try:
            builder.Invoke()
        except SystemExit as e:
            self.assertEqual(e.code, 0, "We should have a non zero error code")
            pass
