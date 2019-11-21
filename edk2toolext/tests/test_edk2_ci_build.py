# @file test_edk2_ci_build.py
# This contains unit tests for the edk2_ci_build
##
# Copyright (c) Microsoft Corporation
#
# SPDX-License-Identifier: BSD-2-Clause-Patent
##
import unittest
from edk2toolext.invocables.edk2_ci_build import Edk2CiBuild
import sys
import os
import logging
import shutil
from importlib import reload
from edk2toolext.environment import shell_environment


class TestEdk2CiBuild(unittest.TestCase):

    minimalTree = os.path.join(os.path.dirname(__file__), "minimal_uefi_tree")

    def setUp(self):
        TestEdk2CiBuild.restart_logging()
        pass

    def tearDown(self):
        shell_environment.GetEnvironment().restore_initial_checkpoint()
        buildFolder = os.path.join(self.minimalTree, "Build")
        shutil.rmtree(buildFolder, ignore_errors=True)
        TestEdk2CiBuild.restart_logging()
        pass

    @classmethod
    def setUpClass(cls):
        pass

    @classmethod
    def tearDownClass(cls):
        pass

    @classmethod
    def restart_logging(cls):
        logging.shutdown()
        reload(logging)

    def test_init(self):
        builder = Edk2CiBuild()
        self.assertIsNotNone(builder)

    def test_ci_build(self):
        builder = Edk2CiBuild()
        settings_file = os.path.join(self.minimalTree, "settings.py")
        sys.argv = ["stuart_ci_build", "-c", settings_file]
        try:
            builder.Invoke()
        except SystemExit as e:
            self.assertEqual(e.code, 0, "We should have a non zero error code")
            pass
