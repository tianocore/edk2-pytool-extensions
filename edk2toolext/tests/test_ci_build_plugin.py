# @file test_ci_build_plugin.py
# Unit test for the ci build plugin class
#
##
# Copyright (c) Microsoft Corporation
#
# SPDX-License-Identifier: BSD-2-Clause-Patent
##
import unittest
import logging
import os
from edk2toolext.environment.plugintypes.ci_build_plugin import ICiBuildPlugin


class TestICiBuildPlugin(unittest.TestCase):

    def test_basic_api(self):
        plugin = ICiBuildPlugin()
        self.assertIsNone(plugin.GetTestName("", ""))
        self.assertIsNone(plugin.RunBuildPlugin("", "", "", "", "", "", "", ""))
        self.assertIn("NO-TARGET", plugin.RunsOnTargetList())

    def test_invalid_parameters_WalkDirectoryForExtension(self):
        plugin = ICiBuildPlugin()

        with self.assertRaises(TypeError) as context:
            plugin.WalkDirectoryForExtension("", "", "")
        self.assertTrue("extensionlist must be a list" in str(context.exception))

        with self.assertRaises(TypeError) as context:
            plugin.WalkDirectoryForExtension(["test"], None, "")
        self.assertTrue("directory is None" in str(context.exception))

        with self.assertRaises(ValueError) as context:
            plugin.WalkDirectoryForExtension(["test"], "a/b/c", "")
        self.assertTrue("directory is not an absolute path" in str(context.exception))

        with self.assertRaises(ValueError) as context:
            plugin.WalkDirectoryForExtension(["test"], os.path.join(os.getcwd(), "junkdir", "junk"), "")
        self.assertTrue("directory is not a valid directory path" in str(context.exception))

        with self.assertRaises(TypeError) as context:
            plugin.WalkDirectoryForExtension([".py"], os.getcwd(), "")
        self.assertTrue("ignorelist must be a list" in str(context.exception))

    def test_valid_parameters_WalkDirectoryForExtension(self):
        plugin = ICiBuildPlugin()

        result = plugin.WalkDirectoryForExtension([".invalid"], os.getcwd())
        self.assertEqual(len(result), 0)


