# @file test_edk2_setup.py
# This contains unit tests for the edk2_ci_setup
##
# Copyright (c) Microsoft Corporation
#
# SPDX-License-Identifier: BSD-2-Clause-Patent
##
import unittest
from edk2toolext.invocables.edk2_setup import Edk2PlatformSetup
import sys
import os
import logging
import shutil
from importlib import reload
from edk2toolext.environment import shell_environment
from edk2toolext.tests.uefi_tree import uefi_tree
from edk2toolext.environment import self_describing_environment
from edk2toolext.environment import version_aggregator


class TestEdk2Setup(unittest.TestCase):

    minimalTree = None

    def setUp(self):
        TestEdk2Setup.restart_logging()
        tree = uefi_tree()
        self.minimalTree = tree.get_workspace()
        pass

    def tearDown(self):
        shell_environment.GetEnvironment().restore_initial_checkpoint()
        buildFolder = os.path.join(self.minimalTree, "Build")
        shutil.rmtree(buildFolder, ignore_errors=True)
        TestEdk2Setup.restart_logging()
        # we need to make sure to tear down the version aggregator and the SDE
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
        builder = Edk2PlatformSetup()
        self.assertIsNotNone(builder)

    def test_ci_setup(self):
        builder = Edk2PlatformSetup()
        settings_file = os.path.join(self.minimalTree, "settings.py")
        sys.argv = ["stuart_setup", "-c", settings_file]
        try:
            builder.Invoke()
        except SystemExit as e:
            self.assertEqual(e.code, 0, "We should have a non zero error code")
            pass

    def test_setup_bad_omnicache_path(self):
        builder = Edk2PlatformSetup()
        settings_file = os.path.join(self.minimalTree, "settings.py")
        sys.argv = ["stuart_setup", "-c", settings_file, "-v", "--omnicache", "does_not_exist"]
        try:
            builder.Invoke()
        except SystemExit as e:
            self.assertEqual(e.code, 0, "We should have a non zero error code")
            pass

    def test_parse_command_line_options_pass(self):
        builder = Edk2PlatformSetup()
        settings_file = os.path.join(self.minimalTree, "settings.py")
        sys.argv = ["stuart_setup",
                    "-c", settings_file,
                    "BLD_*_VAR",
                    "VAR",
                    "BLD_DEBUG_VAR2",
                    "BLD_RELEASE_VAR2",
                    "TEST_VAR=TEST",
                    "BLD_*_TEST_VAR2=TEST"]

        try:
            builder.Invoke()
        except SystemExit as e:
            self.assertEqual(e.code, 0)

        env = shell_environment.GetBuildVars()
        self.assertIsNotNone(env.GetValue("BLD_*_VAR"))
        self.assertIsNotNone(env.GetValue("VAR"))
        self.assertIsNotNone(env.GetValue("BLD_DEBUG_VAR2"))
        self.assertIsNotNone(env.GetValue("BLD_RELEASE_VAR2"))
        self.assertEqual(env.GetValue("TEST_VAR"), "TEST")
        self.assertEqual(env.GetValue("BLD_*_TEST_VAR2"), "TEST")

    def test_parse_command_line_options_fail(self):

        for arg in ["BLD_*_VAR=5=10", "BLD_DEBUG_VAR2=5=5", "BLD_RELEASE_VAR3=5=5", "VAR=10=10"]:
            builder = Edk2PlatformSetup()
            settings_file = os.path.join(self.minimalTree, "settings.py")
            sys.argv = ["stuart_setup",
                        "-c", settings_file,
                        arg]
            try:
                builder.Invoke()
            except RuntimeError as e:
                self.assertTrue(str(e).startswith(f"Unknown variable passed in via CLI: {arg}"))

    def test_conf_file(self):
        builder = Edk2PlatformSetup()
        settings_file = os.path.join(self.minimalTree, "settings.py")
        with open(os.path.join(self.minimalTree, 'BuildConfig.conf'), 'x') as f:
            f.writelines([
                "BLD_*_VAR",
                "\nVAR",
                "\nBLD_DEBUG_VAR2",
                "\nBLD_RELEASE_VAR2",
                "\nTEST_VAR=TEST",
                "\nBLD_*_TEST_VAR2=TEST"
            ])

        sys.argv = ["stuart_setup", "-c", settings_file]

        try:
            builder.Invoke()
        except SystemExit as e:
            self.assertEqual(e.code, 0)

        env = shell_environment.GetBuildVars()
        self.assertIsNotNone(env.GetValue("BLD_*_VAR"))
        self.assertIsNotNone(env.GetValue("VAR"))
        self.assertIsNotNone(env.GetValue("BLD_DEBUG_VAR2"))
        self.assertIsNotNone(env.GetValue("BLD_RELEASE_VAR2"))
        self.assertEqual(env.GetValue("TEST_VAR"), "TEST")
        self.assertEqual(env.GetValue("BLD_*_TEST_VAR2"), "TEST")