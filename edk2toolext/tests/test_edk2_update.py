# @file test_edk2_update.py
# This contains unit tests for the edk2_cupdate
##
# Copyright (c) Microsoft Corporation
#
# SPDX-License-Identifier: BSD-2-Clause-Patent
##
import unittest
from edk2toolext.invocables.edk2_update import Edk2Update
import sys
import os
import shutil
import logging
from importlib import reload
from edk2toolext.environment import shell_environment


class TestEdk2Update(unittest.TestCase):

    minimalTree = os.path.join(os.path.dirname(__file__), "minimal_uefi_tree")

    def update(self):
        TestEdk2Update.restart_logging()
        pass

    def tearDown(self):
        shell_environment.GetEnvironment().restore_initial_checkpoint()
        buildFolder = os.path.join(self.minimalTree, "Build")
        shutil.rmtree(buildFolder, ignore_errors=True)
        TestEdk2Update.restart_logging()
        pass

    @classmethod
    def restart_logging(cls):
        '''
        We restart logging as logging is closed at the end of edk2 invokables.
        We also initalize it at the start.
        Reloading is the easiest way to get fresh state
        '''
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

    def test_ci_update(self):
        builder = Edk2Update()
        settings_file = os.path.join(self.minimalTree, "settings.py")
        sys.argv = ["stuart_update", "-c", settings_file]
        try:
            builder.Invoke()
        except SystemExit as e:
            self.assertEqual(e.code, 0, "We should have a non zero error code")
            pass
