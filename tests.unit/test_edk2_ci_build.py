# @file test_edk2_ci_build.py
# This contains unit tests for the edk2_ci_build
##
# Copyright (c) Microsoft Corporation
#
# SPDX-License-Identifier: BSD-2-Clause-Patent
##
"""Unit test for the Edk2CiBuild class."""

import logging
import os
import shutil
import sys
import unittest
from importlib import reload

from edk2toolext.environment import self_describing_environment, shell_environment, version_aggregator
from edk2toolext.invocables.edk2_ci_build import Edk2CiBuild
from uefi_tree import uefi_tree


class TestEdk2CiBuild(unittest.TestCase):
    """Unit test for the Edk2CiBuild class."""

    minimalTree = None

    def setUp(self) -> None:
        """Set up the test environment."""
        TestEdk2CiBuild.restart_logging()
        tree = uefi_tree()
        self.minimalTree = tree.get_workspace()
        print(self.minimalTree)

    def tearDown(self) -> None:
        """Restore the initial checkpoint."""
        shell_environment.GetEnvironment().restore_initial_checkpoint()
        buildFolder = os.path.join(self.minimalTree, "Build")
        shutil.rmtree(buildFolder, ignore_errors=True)
        TestEdk2CiBuild.restart_logging()
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
        """Test that the Edk2CiBuild can be initialized."""
        builder = Edk2CiBuild()
        self.assertIsNotNone(builder)

    def test_ci_build(self) -> None:
        """Test that the CI build function works."""
        builder = Edk2CiBuild()
        settings_file = os.path.join(self.minimalTree, "settings.py")
        sys.argv = ["stuart_ci_build", "-c", settings_file]
        try:
            builder.Invoke()
        except SystemExit as e:
            self.assertEqual(e.code, 0, "We should have a non zero error code")
        self.assertTrue(os.path.exists(os.path.join(self.minimalTree, "Build")))

    def test_merge_config(self) -> None:
        """Test that the merge_config function works."""
        descriptor = {
            "descriptor_file": "C:\\MyRepo\\.pytool\\Plugin\\MyPlugin1\\MyPlugin1_plug_in.yaml",
            "module": "MyPlugin1",
            "name": "My Plugin 1",
            "scope": "cibuild",
        }

        global_config = {
            "MyPlugin1": {
                "MySetting1": "global value 1",
                "MySetting2": "global value 2",
            },
            "MyPlugin2": {"MySetting2": "global value 2"},
        }
        package_config = {
            "MyPlugin1": {"MySetting1": "package value 1", "MySetting3": "package value 3"},
            "MyPlugin3": {"MySetting3": "package value 3"},
        }
        merged_config = {
            "MySetting1": "package value 1",
            "MySetting2": "global value 2",
            "MySetting3": "package value 3",
        }

        self.assertDictEqual(Edk2CiBuild.merge_config(global_config, {}, descriptor), global_config["MyPlugin1"])
        self.assertDictEqual(Edk2CiBuild.merge_config({}, package_config, descriptor), package_config["MyPlugin1"])
        self.assertDictEqual(Edk2CiBuild.merge_config(global_config, package_config, descriptor), merged_config)
