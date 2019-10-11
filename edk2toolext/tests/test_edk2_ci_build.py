# @file test_edk2_ci_build.py
# This contains unit tests for the edk2_ci_build
##
# Copyright (c) Microsoft Corporation
#
# SPDX-License-Identifier: BSD-2-Clause-Patent
##
import unittest
from edk2toolext.invocables.edk2_ci_build import CiBuildSettingsManager
from edk2toolext.invocables.edk2_ci_build import Edk2CiBuild
import tempfile
import os
from edk2toolext.environment import shell_environment


class TestEdk2CiBuild(unittest.TestCase):

    def setUp(self):
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
        builder = Edk2CiBuild()
        self.assertIsNotNone(builder)

    @classmethod
    def write_to_file(cls, path, contents, close=True):
        f = open(path, "w")
        f.writelines(contents)
        if close:
            f.close()

    class TestSettingsManager(CiBuildSettingsManager):
        def GetActiveScopes(self):
            return []

        def GetWorkspaceRoot(self):
            ''' get WorkspacePath '''
            if self.WORKSPACE is None:
                self.WORKSPACE = tempfile.mkdtemp()
            return self.WORKSPACE

        def GetPackagesPath(self):
            return []
        
        def GetName(self):
            return "TestCI"
