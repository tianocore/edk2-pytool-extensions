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
import tempfile
import os


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

    @classmethod
    def write_to_file(cls, path, contents, close=True):
        f = open(path, "w")
        f.writelines(contents)
        if close:
            f.close()

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

    def test_print(self):
        nuget = nuget_publishing.NugetSupport("test")
        nuget.Print()

    def test_empty_pack(self):
        nuget = nuget_publishing.NugetSupport("test")
        version = "1.1"
        nuget.SetBasicData("EDK2", "https://BSD2", "https://project_url", "descr", "server", "copyright")
        tempfolder_in = tempfile.mkdtemp()
        tempfolder_out = tempfile.mkdtemp()
        # this should fail because we don't have anything to pack
        ret = nuget.Pack(version, tempfolder_out, tempfolder_in)
        self.assertEqual(ret, 1)

    def test_change_copyright(self):
        nuget = nuget_publishing.NugetSupport("test")
        nuget.UpdateCopyright("ALL RIGHTS RESERVED.")
        self.assertTrue(nuget.ConfigChanged)

    def test_change_tags(self):
        nuget = nuget_publishing.NugetSupport("test")
        nuget.UpdateTags(["TAG1", "TAG2"])
        self.assertTrue(nuget.ConfigChanged)

    def test_push_without_spec(self):
        nuget = nuget_publishing.NugetSupport("test")
        tempfolder_out = tempfile.mkdtemp()
        spec = os.path.join(tempfolder_out, "test.nuspec")
        with self.assertRaises(Exception):
            ret = nuget.Push(spec, "")
            self.assertEqual(ret, 1)

    def test_push(self):
        nuget = nuget_publishing.NugetSupport("test")
        nuget.SetBasicData("EDK2", "https://BSD2", "https://project_url", "descr", "https://server", "copyright")
        tempfolder_out = tempfile.mkdtemp()
        spec = os.path.join(tempfolder_out, "test.nuspec")
        test_nuget_publish.write_to_file(spec, ["This is a legit nuget file lol", ])
        ret = nuget.Push(spec, "")
        self.assertEqual(ret, 1)

    def test_pack(self):
        nuget = nuget_publishing.NugetSupport("test")
        version = "1.1.1"
        nuget.SetBasicData("EDK2", "https://BSD2", "https://project_url", "description", "server", "copyright")
        tempfolder_in = tempfile.mkdtemp()
        tempfolder_out = tempfile.mkdtemp()
        outfile = os.path.join(tempfolder_in, "readme.txt")
        # Create a very long release notes
        release_notes = ""
        while len(release_notes) <= nuget_publishing.NugetSupport.RELEASE_NOTE_SHORT_STRING_MAX_LENGTH:
            release_notes += f"This is now {len(release_notes)} characters long. "
        # write a file that can be packaged by nuget
        test_nuget_publish.write_to_file(outfile, [release_notes, ])
        ret = nuget.Pack(version, tempfolder_out, tempfolder_in, release_notes)
        self.assertEqual(ret, 0)
        spec = os.path.join(tempfolder_out, "test.nuspec")
        self.assertTrue(os.path.exists(spec))
        # test that we clean up the files we aren't using
        nuget.CleanUp()
        self.assertFalse(os.path.exists(spec))

    def test_main_new(self):
        args = sys.argv
        tempfolder = tempfile.mkdtemp()
        sys.argv = ["",
                    "--Operation",
                    "New",
                    "--Name",
                    "Test",
                    "--Author",
                    "test",
                    "--ProjectUrl",
                    "https://github.com",
                    "--Description",
                    "test",
                    "--FeedUrl",
                    " https://github.com",
                    "--ConfigFileFolderPath",
                    tempfolder,
                    "--LicenseType",
                    "BSD2"]
        ret = nuget_publishing.main()
        self.assertEqual(ret, 0)
        sys.argv = args

    # TODO: finish unit test


if __name__ == '__main__':
    unittest.main()
