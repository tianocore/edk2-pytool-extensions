# @file test_nuget_publish.py
# Unit test suite for the NugetSupport class.
#
##
# Copyright (c) Microsoft Corporation
#
# SPDX-License-Identifier: BSD-2-Clause-Patent
##
"""Unit test suite for the NugetSupport class."""

import glob
import os
import sys
import tempfile
import unittest

from edk2toolext import nuget_publishing
from edk2toollib.utility_functions import RemoveTree


class test_nuget_publish(unittest.TestCase):
    """Unit test for the NugetSupport class."""

    base_dir = None

    def setUp(self) -> None:
        """Create a temporary workspace."""
        self.temp = tempfile.mkdtemp()
        os.chdir(self.temp)

    def tearDown(self) -> None:
        """Remove the temp folder."""
        os.chdir(self.base_dir)
        RemoveTree(self.temp)

    @classmethod
    def setUpClass(cls) -> None:
        """Set the base directory to the current working directory."""
        test_nuget_publish.base_dir = os.getcwd()

    @classmethod
    def tearDownClass(cls) -> None:
        """Remove all the nupkg files and temp folders."""
        for path in glob.glob("*.nupkg"):
            os.remove(path)
        for path in glob.glob("_TEMP_*"):
            RemoveTree(path)

    @classmethod
    def write_to_file(cls, path: str, contents: str, close: bool = True) -> None:
        """Write contents to a file."""
        f = open(path, "w")
        f.writelines(contents)
        if close:
            f.close()

    def test_init(self) -> None:
        """Test that we can initialize the nuget support object."""
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

    def test_go_new(self) -> None:
        """Test that we can create a new nuget package."""
        args = sys.argv
        sys.argv = [""]
        try:
            nuget_publishing.go()
        except SystemExit:
            # we'll fail because we don't pass in any arguments
            pass
        sys.argv = args

    def test_print(self) -> None:
        """Test that we can print the nuget support object."""
        nuget = nuget_publishing.NugetSupport("test")
        nuget.Print()

    def test_empty_pack(self) -> None:
        """Test that we can't pack an empty folder."""
        nuget = nuget_publishing.NugetSupport("test")
        version = "1.1"
        nuget.SetBasicData("EDK2", "https://BSD2", "https://project_url", "descr", "server", "copyright")
        tempfolder_in = tempfile.mkdtemp()
        tempfolder_out = tempfile.mkdtemp()
        # this should fail because we don't have anything to pack
        ret = nuget.Pack(version, tempfolder_out, tempfolder_in)
        self.assertEqual(ret, 1)

    def test_change_copyright(self) -> None:
        """Test that we can change the copyright."""
        nuget = nuget_publishing.NugetSupport("test")
        nuget.UpdateCopyright("ALL RIGHTS RESERVED.")
        self.assertTrue(nuget.ConfigChanged)

    def test_change_tags(self) -> None:
        """Test that we can change the tags."""
        nuget = nuget_publishing.NugetSupport("test")
        nuget.UpdateTags(["TAG1", "TAG2"])
        self.assertTrue(nuget.ConfigChanged)

    def test_push_without_spec(self) -> None:
        """Test that we raise an exception if we try to push without a spec file."""
        nuget = nuget_publishing.NugetSupport("test")
        tempfolder_out = tempfile.mkdtemp()
        spec = os.path.join(tempfolder_out, "test.nuspec")
        with self.assertRaises(Exception):
            ret = nuget.Push(spec, "")
            self.assertEqual(ret, 1)

    def test_push(self) -> None:
        """Test that we can push a nuget package."""
        nuget = nuget_publishing.NugetSupport("test")
        nuget.SetBasicData("EDK2", "BSD-2-Clause", "https://project_url", "descr", "https://server", "copyright")
        tempfolder_out = tempfile.mkdtemp()
        spec = os.path.join(tempfolder_out, "test.nuspec")
        test_nuget_publish.write_to_file(
            spec,
            [
                "This is a legit nuget file lol",
            ],
        )
        ret = nuget.Push(spec, "")
        self.assertEqual(ret, 1)

    def test_pack_license_espression_invalid(self) -> None:
        """Test that the pack function raises an error with an invalid license expression."""
        nuget = nuget_publishing.NugetSupport("test")
        version = "1.1.1"
        nuget.SetBasicData("EDK2", "BSD-2-Clause", "https://project_url", "description", "server", "copyright")
        tempfolder_in = tempfile.mkdtemp()
        tempfolder_out = tempfile.mkdtemp()
        outfile = os.path.join(tempfolder_in, "readme.txt")
        # Create a very long release notes
        release_notes = ""
        while len(release_notes) <= nuget_publishing.NugetSupport.RELEASE_NOTE_SHORT_STRING_MAX_LENGTH:
            release_notes += f"This is now {len(release_notes)} characters long. "
        # write a file that can be packaged by nuget
        test_nuget_publish.write_to_file(
            outfile,
            [
                release_notes,
            ],
        )
        ret = nuget.Pack(version, tempfolder_out, tempfolder_in, release_notes)
        self.assertEqual(ret, 0)
        spec = os.path.join(tempfolder_out, "test.nuspec")
        self.assertTrue(os.path.exists(spec))
        # test that we clean up the files we aren't using
        nuget.CleanUp()
        self.assertFalse(os.path.exists(spec))

    def test_main_new_and_pack_LicenseIdentifier(self) -> None:
        """Test that the main function can create a new nuget package and pack it with a license identifier."""
        args = sys.argv
        tempfolder = tempfile.mkdtemp()
        sys.argv = [
            "",
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
            "--LicenseIdentifier",
            "BSD2",
        ]

        ret = nuget_publishing.main()
        self.assertEqual(ret, 0)

        sys.argv = [
            "",
            "--Operation",
            "Pack",
            "--ConfigFilePath",
            os.path.join(tempfolder, "Test.config.yaml"),
            "--Version",
            "1.0.0",
            "--InputFolderPath",
            tempfolder,
        ]

        ret = nuget_publishing.main()
        self.assertEqual(ret, 0)
        sys.argv = args

    def test_main_new_and_pack_CustomLicense_valid(self) -> None:
        """Test that the main function can create a new nuget package and pack it with a custom license."""
        args = sys.argv
        tempfolder = tempfile.mkdtemp()
        open(os.path.join(tempfolder, "license.txt"), "w")
        sys.argv = [
            "",
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
        ]
        ret = nuget_publishing.main()
        self.assertEqual(ret, 0)

        sys.argv = [
            "",
            "--Operation",
            "Pack",
            "--ConfigFilePath",
            os.path.join(tempfolder, "Test.config.yaml"),
            "--Version",
            "1.0.0",
            "--Copyright",
            "2023",
            "--InputFolderPath",
            tempfolder,
            "--CustomLicensePath",
            os.path.join(tempfolder, "license.txt"),
        ]

        ret = nuget_publishing.main()
        self.assertEqual(ret, 0)
        sys.argv = args

    def test_main_new_and_pack_no_CustomLicense(self) -> None:
        """Test that the main function can create a new nuget package and pack it without a custom license."""
        args = sys.argv
        tempfolder = tempfile.mkdtemp()
        sys.argv = [
            "",
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
        ]
        ret = nuget_publishing.main()
        self.assertEqual(ret, 0)
        sys.argv = [
            "",
            "--Operation",
            "Pack",
            "--ConfigFilePath",
            os.path.join(tempfolder, "Test.config.yaml"),
            "--Version",
            "1.0.0",
            "--InputFolderPath",
            tempfolder,
        ]

        self.assertRaises(Exception, nuget_publishing.main)
        sys.argv = args

    def test_main_new_and_pack_CustomLicense_invalid_path(self) -> None:
        """Test that the main function fails with an invalid custom license path."""
        args = sys.argv
        tempfolder = tempfile.mkdtemp()
        sys.argv = [
            "",
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
        ]
        ret = nuget_publishing.main()
        self.assertEqual(ret, 0)
        sys.argv = [
            "",
            "--Operation",
            "Pack",
            "--ConfigFilePath",
            os.path.join(tempfolder, "Test.config.yaml"),
            "--Version",
            "1.0.0",
            "--InputFolderPath",
            tempfolder,
            "--CustomLicensePath",
            "/bad/path/license.txt",
        ]

        self.assertRaises(Exception, nuget_publishing.main)
        sys.argv = args

    def test_main_new_and_pack_CustomLicense_invalid_license_name(self) -> None:
        """Test that we can create a new nuget package with an invalid license name and pack it."""
        args = sys.argv
        tempfolder = tempfile.mkdtemp()
        open(os.path.join(tempfolder, "license2.txt"), "w")
        sys.argv = [
            "",
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
        ]
        ret = nuget_publishing.main()
        self.assertEqual(ret, 0)
        sys.argv = [
            "",
            "--Operation",
            "Pack",
            "--ConfigFilePath",
            os.path.join(tempfolder, "Test.config.yaml"),
            "--Version",
            "1.0.0",
            "--InputFolderPath",
            tempfolder,
            "--CustomLicensePath",
            os.path.join(tempfolder, "license2.txt"),
        ]

        self.assertRaises(Exception, nuget_publishing.main)
        sys.argv = args

    def test_main_new_RepositoryType_and_pack(self) -> None:
        """Test that we can create a new nuget package with a repository type and pack it."""
        args = sys.argv
        tempfolder = tempfile.mkdtemp()
        sys.argv = [
            "",
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
            "--LicenseIdentifier",
            "BSD2",
            "--RepositoryType",
            "git",
        ]

        ret = nuget_publishing.main()
        self.assertEqual(ret, 0)

        sys.argv = [
            "",
            "--Operation",
            "Pack",
            "--ConfigFilePath",
            os.path.join(tempfolder, "Test.config.yaml"),
            "--Version",
            "1.0.0",
            "--InputFolderPath",
            tempfolder,
        ]

        ret = nuget_publishing.main()
        self.assertEqual(ret, 0)
        sys.argv = args

    def test_main_new_RepositoryUrl_and_pack(self) -> None:
        """Test that we can create a new nuget package with a repository URL and pack it."""
        args = sys.argv
        tempfolder = tempfile.mkdtemp()
        sys.argv = [
            "",
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
            "--LicenseIdentifier",
            "BSD2",
            "--RepositoryUrl",
            "https://github.com/microsoft/mu_basecore",
        ]

        ret = nuget_publishing.main()
        self.assertEqual(ret, 0)

        sys.argv = [
            "",
            "--Operation",
            "Pack",
            "--ConfigFilePath",
            os.path.join(tempfolder, "Test.config.yaml"),
            "--Version",
            "1.0.0",
            "--InputFolderPath",
            tempfolder,
        ]

        ret = nuget_publishing.main()
        self.assertEqual(ret, 0)
        sys.argv = args

    def test_main_new_RepositoryBranch_and_pack(self) -> None:
        """Test that we can create a new nuget package with a repository branch and pack it."""
        args = sys.argv
        tempfolder = tempfile.mkdtemp()
        sys.argv = [
            "",
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
            "--LicenseIdentifier",
            "BSD2",
            "--RepositoryBranch",
            "main",
        ]

        ret = nuget_publishing.main()
        self.assertEqual(ret, 0)

        sys.argv = [
            "",
            "--Operation",
            "Pack",
            "--ConfigFilePath",
            os.path.join(tempfolder, "Test.config.yaml"),
            "--Version",
            "1.0.0",
            "--InputFolderPath",
            tempfolder,
        ]

        ret = nuget_publishing.main()
        self.assertEqual(ret, 0)
        sys.argv = args

    def test_main_new_RepositoryCommit_and_pack(self) -> None:
        """Test that we can create a new nuget package with a repository commit."""
        args = sys.argv
        tempfolder = tempfile.mkdtemp()
        sys.argv = [
            "",
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
            "--LicenseIdentifier",
            "BSD2",
            "--RepositoryCommit",
            "cd845afd5c3c838a9f7af7dad238452ae9a17146",
        ]

        ret = nuget_publishing.main()
        self.assertEqual(ret, 0)

        sys.argv = [
            "",
            "--Operation",
            "Pack",
            "--ConfigFilePath",
            os.path.join(tempfolder, "Test.config.yaml"),
            "--Version",
            "1.0.0",
            "--InputFolderPath",
            tempfolder,
        ]

        ret = nuget_publishing.main()
        self.assertEqual(ret, 0)
        sys.argv = args

    def test_main_new_RepositoryAll_and_pack(self) -> None:
        """Test that we can create a new nuget package with all repository options and pack it."""
        args = sys.argv
        tempfolder = tempfile.mkdtemp()
        sys.argv = [
            "",
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
            "--LicenseIdentifier",
            "BSD2",
            "--RepositoryType",
            "git",
            "--RepositoryUrl",
            "https://github.com/microsoft/mu_plus",
            "--RepositoryBranch",
            "master",
            "--RepositoryCommit",
            "06df12360d561b2007e03503491510c36426d860",
        ]

        ret = nuget_publishing.main()
        self.assertEqual(ret, 0)

        sys.argv = [
            "",
            "--Operation",
            "Pack",
            "--ConfigFilePath",
            os.path.join(tempfolder, "Test.config.yaml"),
            "--Version",
            "1.0.0",
            "--InputFolderPath",
            tempfolder,
        ]

        ret = nuget_publishing.main()
        self.assertEqual(ret, 0)
        sys.argv = args

    def test_main_new_and_pack_RepositoryType(self) -> None:
        """Test that the main function can create a new nuget package and pack it with a repository type."""
        args = sys.argv
        tempfolder = tempfile.mkdtemp()
        sys.argv = [
            "",
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
            "--LicenseIdentifier",
            "BSD2",
        ]

        ret = nuget_publishing.main()
        self.assertEqual(ret, 0)

        sys.argv = [
            "",
            "--Operation",
            "Pack",
            "--ConfigFilePath",
            os.path.join(tempfolder, "Test.config.yaml"),
            "--Version",
            "1.0.0",
            "--InputFolderPath",
            tempfolder,
            "--RepositoryType",
            "git",
        ]

        ret = nuget_publishing.main()
        self.assertEqual(ret, 0)
        sys.argv = args

    def test_main_new_and_pack_RepositoryUrl(self) -> None:
        """Test that the main function can create a new nuget package and pack it with a repository URL."""
        args = sys.argv
        tempfolder = tempfile.mkdtemp()
        sys.argv = [
            "",
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
            "--LicenseIdentifier",
            "BSD2",
        ]

        ret = nuget_publishing.main()
        self.assertEqual(ret, 0)

        sys.argv = [
            "",
            "--Operation",
            "Pack",
            "--ConfigFilePath",
            os.path.join(tempfolder, "Test.config.yaml"),
            "--Version",
            "1.0.0",
            "--InputFolderPath",
            tempfolder,
            "--RepositoryUrl",
            "https://github.com/microsoft/mu_basecore",
        ]

        ret = nuget_publishing.main()
        self.assertEqual(ret, 0)
        sys.argv = args

    def test_main_new_and_pack_RepositoryBranch(self) -> None:
        """Test that the main function can create a new nuget package and pack it with a repository branch."""
        args = sys.argv
        tempfolder = tempfile.mkdtemp()
        sys.argv = [
            "",
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
            "--LicenseIdentifier",
            "BSD2",
        ]

        ret = nuget_publishing.main()
        self.assertEqual(ret, 0)

        sys.argv = [
            "",
            "--Operation",
            "Pack",
            "--ConfigFilePath",
            os.path.join(tempfolder, "Test.config.yaml"),
            "--Version",
            "1.0.0",
            "--InputFolderPath",
            tempfolder,
            "--RepositoryBranch",
            "main",
        ]

        ret = nuget_publishing.main()
        self.assertEqual(ret, 0)
        sys.argv = args

    def test_main_new_and_pack_RepositoryCommit(self) -> None:
        """Test that we can create a new nuget package and pack it with a commit."""
        args = sys.argv
        tempfolder = tempfile.mkdtemp()
        sys.argv = [
            "",
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
            "--LicenseIdentifier",
            "BSD2",
        ]

        ret = nuget_publishing.main()
        self.assertEqual(ret, 0)

        sys.argv = [
            "",
            "--Operation",
            "Pack",
            "--ConfigFilePath",
            os.path.join(tempfolder, "Test.config.yaml"),
            "--Version",
            "1.0.0",
            "--InputFolderPath",
            tempfolder,
            "--RepositoryCommit",
            "cd845afd5c3c838a9f7af7dad238452ae9a17146",
        ]

        ret = nuget_publishing.main()
        self.assertEqual(ret, 0)
        sys.argv = args

    def test_main_new_and_pack_RepositoryAll(self) -> None:
        """Test that we can create a new nuget package and pack it with all repository information."""
        args = sys.argv
        tempfolder = tempfile.mkdtemp()
        sys.argv = [
            "",
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
            "--LicenseIdentifier",
            "BSD2",
        ]

        ret = nuget_publishing.main()
        self.assertEqual(ret, 0)

        sys.argv = [
            "",
            "--Operation",
            "Pack",
            "--ConfigFilePath",
            os.path.join(tempfolder, "Test.config.yaml"),
            "--Version",
            "1.0.0",
            "--InputFolderPath",
            tempfolder,
            "--RepositoryType",
            "git",
            "--RepositoryUrl",
            "https://github.com/microsoft/mu_plus",
            "--RepositoryBranch",
            "master",
            "--RepositoryCommit",
            "06df12360d561b2007e03503491510c36426d860",
        ]

        ret = nuget_publishing.main()
        self.assertEqual(ret, 0)
        sys.argv = args

    # TODO: finish unit test


if __name__ == "__main__":
    unittest.main()
