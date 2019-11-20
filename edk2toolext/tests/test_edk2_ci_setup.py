# @file test_edk2_ci_setup.py
# This contains unit tests for the edk2_ci_setup
##
# Copyright (c) Microsoft Corporation
#
# SPDX-License-Identifier: BSD-2-Clause-Patent
##
import unittest
from edk2toolext.invocables.edk2_ci_setup import Edk2CiBuildSetup
import sys
import os
import logging
from importlib import reload
from edk2toolext.environment import shell_environment


class TestEdk2CiSetup(unittest.TestCase):

    def setUp(self):
        TestEdk2CiSetup.restart_logging()
        pass

    def tearDown(self):
        shell_environment.GetEnvironment().restore_initial_checkpoint()
        TestEdk2CiSetup.restart_logging()
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
        builder = Edk2CiBuildSetup()
        self.assertIsNotNone(builder)

    def test_ci_setup(self):
        builder = Edk2CiBuildSetup()
        settings_file = os.path.join(os.path.dirname(__file__), "minimal_uefi_tree", "settings.py")
        sys.argv = ["stuart_ci_setup", "-c", settings_file]
        try:
            builder.Invoke()
        except SystemExit as e:
            self.assertEqual(e.code, 0, "We should have a non zero error code")
            pass
