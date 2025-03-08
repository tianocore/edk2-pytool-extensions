# @file test_edk2_ci_setup.py
# This contains unit tests for the edk2_ci_setup
##
# Copyright (c) Microsoft Corporation
#
# SPDX-License-Identifier: BSD-2-Clause-Patent
##
"""Unit test for the Edk2CiBuildSetup module."""

import logging
import os
import shutil
import sys
import unittest
from importlib import reload

from edk2toolext.environment import self_describing_environment, shell_environment, version_aggregator
from edk2toolext.invocables.edk2_ci_setup import Edk2CiBuildSetup
from uefi_tree import uefi_tree


class TestEdk2CiSetup(unittest.TestCase):
    """Unit test for the Edk2CiBuildSetup class."""

    minimalTree = None

    def setUp(self) -> None:
        """Set up the test environment."""
        TestEdk2CiSetup.restart_logging()
        tree = uefi_tree()
        self.minimalTree = tree.get_workspace()
        print(self.minimalTree)

    def tearDown(self) -> None:
        """Restore the initial checkpoint."""
        shell_environment.GetEnvironment().restore_initial_checkpoint()
        TestEdk2CiSetup.restart_logging()
        buildFolder = os.path.join(self.minimalTree, "Build")
        shutil.rmtree(buildFolder, ignore_errors=True)
        self_describing_environment.DestroyEnvironment()
        version_aggregator.ResetVersionAggregator()

    @classmethod
    def restart_logging(cls) -> None:
        """We restart logging as logging is closed at the end of edk2 invocables.

        We also initialize it at the start.
        Reloading is the easiest way to get fresh state
        """
        logging.shutdown()
        reload(logging)

    def test_init(self) -> None:
        """Test that the Edk2CiBuildSetup can be initialized."""
        builder = Edk2CiBuildSetup()
        self.assertIsNotNone(builder)

    def test_ci_setup(self) -> None:
        """Test that the CI setup function works."""
        builder = Edk2CiBuildSetup()
        settings_file = os.path.join(self.minimalTree, "settings.py")
        sys.argv = ["stuart_ci_setup", "-c", settings_file, "-v"]
        try:
            builder.Invoke()
        except SystemExit as e:
            self.assertEqual(e.code, 0, "We should have a non zero error code")

    def test_ci_setup_bad_omnicache_path(self) -> None:
        """Test that the CI setup function works."""
        builder = Edk2CiBuildSetup()
        settings_file = os.path.join(self.minimalTree, "settings.py")
        sys.argv = ["stuart_ci_setup", "-c", settings_file, "-v", "--omnicache", "does_not_exist"]
        try:
            builder.Invoke()
        except SystemExit as e:
            self.assertEqual(e.code, 0, "We should have a non zero error code")
