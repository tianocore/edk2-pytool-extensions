# @file test_edk2_update.py
# This contains unit tests for the edk2_update
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
from edk2toolext.environment import self_describing_environment

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

# TODO: move to something lighter weight that has external dependencies
# Perhaps create a custom nuget package that has itself in it?
basecore_ext_dep = '''
{
  "scope": "global",
  "type": "git",
  "name": "MU_BASECORE",
  "source": "https://github.com/Microsoft/mu_basecore.git",
  "version": "cf124c91494a482553238f921845872ab31325b1",
  "flags": []
}
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

    # This tests that we can fetch basecore and get the environment descriptors in it
    def test_update_basecore(self):
        WORKSPACE = tempfile.mkdtemp()
        builder = Edk2Update()
        workspace_abs = os.path.abspath(WORKSPACE).replace("\\", "\\\\")
        settings_filepath = os.path.abspath(os.path.join(WORKSPACE, "settings.py"))
        extdep_filepath = os.path.abspath(os.path.join(WORKSPACE, "basecore_ext_dep.yaml"))
        real_class = class_info.replace("WORKSPACE", f'"{workspace_abs}"')

        # inject the settings file and the ext dep into our temp workspace
        TestEdk2Update.write_to_file(extdep_filepath, basecore_ext_dep)
        TestEdk2Update.write_to_file(settings_filepath, real_class)
        sys.argv = ["stuart_update", "-c", settings_filepath]
        try:
            builder.Invoke()
        except SystemExit as e:
            self.assertEqual(e.code, 0, "We should have a non zero error code")
            pass
        # now we should check that our workspace is how we expect it
        (build_env, shell_env) = self_describing_environment.BootstrapEnvironment(workspace_abs, [])
        # make sure we find more than 1 path
        self.assertGreater(len(build_env.path), 0)
