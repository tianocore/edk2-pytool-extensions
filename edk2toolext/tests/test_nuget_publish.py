# @file test_nuget_publish.py
# Unit test suite for the NugetSupport class.
#
##
# Copyright (c) Microsoft Corporation
#
# SPDX-License-Identifier: BSD-2-Clause-Patent
##
import unittest
from edk2toolext import nuget_publishing
import sys
import os
import tempfile


class test_nuget_publish(unittest.TestCase):
    def setUp(self):
        pass

    def tearDown(self):
        pass

    @classmethod
    def setUpClass(cls):
        pass

    @classmethod
    def tearDownClass(cls):
        pass

    def test_init(self):
        nuget = nuget_publishing.NugetSupport("test")
        self.assertIsNotNone(nuget)
        # make sure we raise if we don't pass in anything
        with self.assertRaises(ValueError):
            nuget_publishing.NugetSupport()
        # write the config to file so we can read it into a new nuget support
        _, tempfile_path = tempfile.mkstemp(text=True)
        nuget.ConfigChanged = True
        nuget.ToConfigFile(tempfile_path)
        # read in a config file
        nuget2 = nuget_publishing.NugetSupport(ConfigFile=tempfile_path)
        self.assertIsNotNone(nuget2)

    def test_go_new(self):
        args = sys.argv
        sys.argv = [""]
        try:
            nuget_publishing.go()
        except SystemExit:
            # we'll fail because we don't pass in any arguments
            pass
        sys.argv = args

    def test_main_new(self):
        args = sys.argv
        tempfolder = tempfile.mkdtemp()
        sys.argv = ["", "--Operation", "New", "--Name", "Test", "--Author", "test", "--ProjectUrl", "https://github.com",
                    "--Description", "test", "--FeedUrl", " https://github.com", "--ConfigFileFolderPath", tempfolder, "--LicenseType", "BSD2"]
        ret = nuget_publishing.main()
        self.assertEqual(ret, 0)
        sys.argv = args

    # TODO: finish unit test


if __name__ == '__main__':
    unittest.main()
