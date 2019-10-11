# @file test_edk2_update.py
# This contains unit tests for the edk2_cupdate
##
# Copyright (c) Microsoft Corporation
#
# SPDX-License-Identifier: BSD-2-Clause-Patent
##
import unittest
from edk2toolext.invocables.edk2_update import Edk2Update
import tempfile
import sys
import os
import logging
from importlib import reload
from edk2toolext.environment import shell_environment

class_info = '''
from edk2toolext.invocables.edk2_update import UpdateSettingsManager
class TestSettingsManager(UpdateSettingsManager):

    def GetActiveScopes(self):
        return []

    def GetWorkspaceRoot(self):
        return WORKSPACE

    def AddCommandLineOptions(self, parserObj):
        pass

    def RetrieveCommandLineOptions(self, args):
        pass

    def GetName(self):
        return "TestUpdate"

    def GetArchitecturesSupported(self):
        return []

    def GetPackagesSupported(self):
        return []

    def GetTargetsSupported(self):
        return []
'''


class TestEdk2Update(unittest.TestCase):

    def update(self):
        TestEdk2Update.restart_logging()
        pass

    def tearDown(self):
        shell_environment.GetEnvironment().restore_initial_checkpoint()
        TestEdk2Update.restart_logging()
        pass

    @classmethod
    def restart_logging(cls):
        logging.shutdown()
        reload(logging)

    @classmethod
    def updateClass(cls):
        pass

    @classmethod
    def tearDownClass(cls):
        pass

    def test_init(self):
        builder = Edk2Update()
        self.assertIsNotNone(builder)

    @classmethod
    def write_to_file(cls, path, contents, close=True):
        f = open(path, "w")
        f.writelines(contents)
        if close:
            f.close()

    def test_ci_update(self):
        WORKSPACE = tempfile.mkdtemp()
        builder = Edk2Update()
        workspace_abs = os.path.abspath(WORKSPACE).replace("\\", "\\\\")
        settings_file = os.path.abspath(os.path.join(WORKSPACE, "settings.py"))
        real_class = class_info.replace("WORKSPACE", f'"{workspace_abs}"')
        print(settings_file)
        TestEdk2Update.write_to_file(settings_file, real_class)
        sys.argv = ["stuart_update", "-c", settings_file]
        try:
            builder.Invoke()
        except SystemExit as e:
            self.assertEqual(e.code, 0, "We should have a non zero error code")
            pass
