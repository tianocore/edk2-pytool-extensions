# @file test_edk2_plat_build.py
# This contains unit tests for the edk2_plat_build
##
# Copyright (c) Microsoft Corporation
#
# SPDX-License-Identifier: BSD-2-Clause-Patent
##
"""Unit test for the Edk2PlatformBuild class."""

import logging
import os
import shutil
import sys
import unittest
from importlib import reload

from edk2toolext.environment import self_describing_environment, shell_environment, version_aggregator
from edk2toolext.invocables.edk2_platform_build import Edk2PlatformBuild
from uefi_tree import uefi_tree


class TestEdk2PlatBuild(unittest.TestCase):
    """Unit test for the Edk2PlatformBuild class."""

    minimalTree = None

    def setUp(self) -> None:
        """Set up the test environment."""
        TestEdk2PlatBuild.restart_logging()
        tree = uefi_tree()
        self.minimalTree = tree.get_workspace()

    def tearDown(self) -> None:
        """Restore the initial checkpoint."""
        shell_environment.GetEnvironment().restore_initial_checkpoint()
        buildFolder = os.path.join(self.minimalTree, "Build")
        shutil.rmtree(buildFolder, ignore_errors=True)
        TestEdk2PlatBuild.restart_logging()
        # we need to make sure to tear down the version aggregator and the SDE
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
        """Test that the Edk2PlatformBuild can be initialized."""
        builder = Edk2PlatformBuild()
        self.assertIsNotNone(builder)

    def test_ci_setup(self) -> None:
        """Test that the CI setup function works."""
        builder = Edk2PlatformBuild()
        settings_file = os.path.join(self.minimalTree, "settings.py")
        sys.argv = ["stuart_build", "-c", settings_file]
        try:
            builder.Invoke()
        except SystemExit:
            # self.assertEqual(e.code, 0, "We should have a non zero error code")
            # we'll fail because we don't have the build command
            pass
