# @file test_ci_build_plugin.py
# Unit test for the ci build plugin class
#
##
# Copyright (c) Microsoft Corporation
#
# SPDX-License-Identifier: BSD-2-Clause-Patent
##
"""Unit test for the ICiBuildPlugin class."""

import os
import shutil
import tempfile
import unittest

from edk2toolext.environment.plugintypes.ci_build_plugin import ICiBuildPlugin


class TestICiBuildPlugin(unittest.TestCase):
    """Unit test for the ICiBuildPlugin class."""

    def __init__(self, *args, **kwargs) -> None:  # noqa: ANN002, ANN003
        """Initialize the TestICiBuildPlugin class."""
        self.test_dir = None
        super().__init__(*args, **kwargs)

    def prep_workspace(self) -> None:
        """Prepare a temporary workspace."""
        self.clean_workspace()
        self.test_dir = tempfile.mkdtemp()

    def clean_workspace(self) -> None:
        """Clean up the workspace."""
        if self.test_dir is None:
            return
        if os.path.isdir(self.test_dir):
            shutil.rmtree(self.test_dir)
            self.test_dir = None

    def setUp(self) -> None:
        """Create a temporary workspace."""
        self.prep_workspace()

    def tearDown(self) -> None:
        """Restore the initial checkpoint."""
        self.clean_workspace()

    def test_basic_api(self) -> None:
        """Test that the ICiBuildPlugin class has the expected API."""
        plugin = ICiBuildPlugin()
        self.assertIsNone(plugin.GetTestName("", ""))
        self.assertIsNone(plugin.RunBuildPlugin("", "", "", "", "", "", "", ""))
        self.assertIn("NO-TARGET", plugin.RunsOnTargetList())

    def test_invalid_parameters_WalkDirectoryForExtension(self) -> None:
        """Test that the WalkDirectoryForExtension function can handle invalid parameters."""
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
            plugin.WalkDirectoryForExtension(["test"], os.path.join(self.test_dir, "junkdir", "junk"), "")
        self.assertTrue("directory is not a valid directory path" in str(context.exception))

        with self.assertRaises(TypeError) as context:
            plugin.WalkDirectoryForExtension([".py"], self.test_dir, "")
        self.assertTrue("ignorelist must be a list" in str(context.exception))

    def test_valid_parameters_WalkDirectoryForExtension(self) -> None:
        """Test that the WalkDirectoryForExtension function can find files."""
        plugin = ICiBuildPlugin()

        with open(os.path.join(self.test_dir, "junk.txt"), "w") as the_file:
            the_file.write("Hello")

        nestedfolder = os.path.join(self.test_dir, "the_dir")
        os.makedirs(nestedfolder)
        with open(os.path.join(nestedfolder, "file2.py"), "w") as the_file:
            the_file.write("hello 2")

        # no files of this filetype found
        result = plugin.WalkDirectoryForExtension([".c"], self.test_dir)
        self.assertEqual(len(result), 0)

        # 1 txt file found
        result = plugin.WalkDirectoryForExtension([".txt"], self.test_dir)
        self.assertEqual(len(result), 1)

        # 1 txt and 1 py file found
        result = plugin.WalkDirectoryForExtension([".txt", ".py"], self.test_dir, [])
        self.assertEqual(len(result), 2)

        # case insensitive file extension
        result = plugin.WalkDirectoryForExtension([".tXt", ".PY"], self.test_dir)
        self.assertEqual(len(result), 2)

    def test_valid_parameters_ignore_WalkDirectoryForExtension(self) -> None:
        """Test that the WalkDirectoryForExtension function can ignore files."""
        plugin = ICiBuildPlugin()

        # setup test dir with a few files
        with open(os.path.join(self.test_dir, "junk.txt"), "w") as the_file:
            the_file.write("Hello")

        nestedfolder = os.path.join(self.test_dir, "the_dir")
        os.makedirs(nestedfolder)
        with open(os.path.join(nestedfolder, "file2.py"), "w") as the_file:
            the_file.write("hello 2")

        result = plugin.WalkDirectoryForExtension([".txt", ".py"], self.test_dir, ["junk"])
        self.assertEqual(len(result), 1)

        result = plugin.WalkDirectoryForExtension([".txt", ".py"], self.test_dir, ["file2"])
        self.assertEqual(len(result), 1)

        result = plugin.WalkDirectoryForExtension([".txt", ".py"], self.test_dir, ["junk", "file2"])
        self.assertEqual(len(result), 0)

    def test_valid_parameters_ignore_caseinsensitive_WalkDirectoryForExtension(self) -> None:
        """Test that the WalkDirectoryForExtension function can ignore files in a case insensitive manner."""
        plugin = ICiBuildPlugin()

        # setup test dir with a few files
        with open(os.path.join(self.test_dir, "junk.txt"), "w") as the_file:
            the_file.write("Hello")

        nestedfolder = os.path.join(self.test_dir, "the_dir")
        os.makedirs(nestedfolder)
        with open(os.path.join(nestedfolder, "file2.py"), "w") as the_file:
            the_file.write("hello 2")

        # case insensitive
        result = plugin.WalkDirectoryForExtension([".txt", ".py"], self.test_dir, ["JUNK"])
        self.assertEqual(len(result), 1)

        # case insensitive + partial match
        result = plugin.WalkDirectoryForExtension([".txt", ".py"], self.test_dir, ["FILE"])
        self.assertEqual(len(result), 1)

        # case insensitive + all match including extension
        result = plugin.WalkDirectoryForExtension([".txt", ".py"], self.test_dir, ["FILE2.py"])
        self.assertEqual(len(result), 1)
