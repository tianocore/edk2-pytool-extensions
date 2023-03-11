# @file test_edk2_coverage.py
# This contains unit tests for the edk2_coverage
##
# Copyright (c) Microsoft Corporation
#
# SPDX-License-Identifier: BSD-2-Clause-Patent
##
import unittest
from edk2toolext.invocables.edk2_coverage import Edk2Coverage
import sys
import shutil
import os
import logging
from importlib import reload
from edk2toolext.environment import shell_environment
from edk2toolext.tests.uefi_tree import uefi_tree
from edk2toolext.environment import self_describing_environment
from edk2toolext.environment import version_aggregator


class TestEdk2CiSetup(unittest.TestCase):

    minimalTree = None

    def setUp(self):
        TestEdk2CiSetup.restart_logging()
        tree = uefi_tree()
        self.minimalTree = tree.get_workspace()
        print(self.minimalTree)
        pass

    def tearDown(self):
        shell_environment.GetEnvironment().restore_initial_checkpoint()
        TestEdk2CiSetup.restart_logging()
        buildFolder = os.path.join(self.minimalTree, "Build")
        shutil.rmtree(buildFolder, ignore_errors=True)
        self_describing_environment.DestroyEnvironment()
        version_aggregator.ResetVersionAggregator()
        pass

    @classmethod
    def restart_logging(cls):
        '''
        We restart logging as logging is closed at the end of edk2 invocables.
        We also initialize it at the start.
        Reloading is the easiest way to get fresh state
        '''
        logging.shutdown()
        reload(logging)

    @classmethod
    def setUpClass(cls):
        pass

    @classmethod
    def tearDownClass(cls):
        pass

    def test_init(self):
        builder = Edk2Coverage()
        self.assertIsNotNone(builder)

    def test_coverage(self):
        builder = Edk2Coverage()
        settings_file = os.path.join(self.minimalTree, "settings.py")
        out_dir = os.path.join(self.minimalTree, "coverage", "")

        for coverage_subdir in ["linux", "windows"]:
            input_coverage = os.path.join(os.path.dirname(__file__), "testdata",
                                          "coverage", coverage_subdir, "*coverage.xml")

            sys.argv = ["stuart_coverage", "-c", settings_file,
                        "--coverage-files", input_coverage, "--output-dir", out_dir]
            try:
                builder.Invoke()
            except SystemExit as e:
                self.assertEqual(e.code, 0, "We should have a non zero error code")
                pass
