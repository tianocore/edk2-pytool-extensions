# @file test_az_cli_universal_dependency.py
# Unit test suite for the Azure CLI Artifacts Universal Packages Dependency class.
#
# NOTE: To run most of this test you must specify a valid PAT that can read packages from
# tianocore devops (https://dev.azure.com/tianocore) in your environment as PAT_FOR_UNIVERSAL_ORG_TIANOCORE
#
# Universal Packages do not support anonymous access (even in public feeds) and therefore this unit test can not run
# in a GitHub PR flow because it would need secrets.
# https://docs.microsoft.com/en-us/azure/devops/artifacts/concepts/feeds?view=azure-devops#public-feeds
#
##
# Copyright (c) Microsoft Corporation
#
# SPDX-License-Identifier: BSD-2-Clause-Patent
##
"""Unit test for the Azure CLI Artifacts Universal Packages Dependency class."""

import logging
import os
import tempfile
import unittest
from unittest.mock import MagicMock, patch

from edk2toolext.environment import environment_descriptor_files as EDF
from edk2toolext.environment import version_aggregator
from edk2toolext.environment.extdeptypes.az_cli_universal_dependency import AzureCliUniversalDependency
from edk2toollib.utility_functions import RemoveTree

test_dir = None

single_file_json_template = """
{
  "scope": "global",
  "type": "az-universal",
  "name": "hello-world-file",
  "source": "https://dev.azure.com/tianocore",
  "project": "edk2-pytool-extensions",
  "version": "%s",
  "feed": "ext_dep_unit_test_feed",
  "pat_var": "PAT_FOR_UNIVERSAL_ORG_TIANOCORE"
}
"""

folders_json_template = """
{
  "scope": "global",
  "type": "az-universal",
  "name": "hello-world-folders",
  "source": "https://dev.azure.com/tianocore",
  "project": "edk2-pytool-extensions",
  "version": "%s",
  "feed": "ext_dep_unit_test_feed",
  "pat_var": "PAT_FOR_UNIVERSAL_ORG_TIANOCORE"
}
"""

file_filter_json_template = """
{
  "scope": "global",
  "type": "az-universal",
  "name": "hello-world-folders",
  "source": "https://dev.azure.com/tianocore",
  "project": "edk2-pytool-extensions",
  "version": "0.2.1",
  "feed": "ext_dep_unit_test_feed",
  "file-filter": "folder2/*.txt",
  "pat_var": "PAT_FOR_UNIVERSAL_ORG_TIANOCORE"
}
"""

zip_json_template = """
{
  "scope": "global",
  "type": "az-universal",
  "name": "hello-world-zip",
  "source": "https://dev.azure.com/tianocore",
  "project": "edk2-pytool-extensions",
  "version": "%s",
  "feed": "ext_dep_unit_test_feed",
  "compression_type": "zip",
  "internal_path": "hello-world-zip",
  "pat_var": "PAT_FOR_UNIVERSAL_ORG_TIANOCORE"
}
"""

zip_json_template2 = """
{
  "scope": "global",
  "type": "az-universal",
  "name": "hello-world-zip",
  "source": "https://dev.azure.com/tianocore",
  "project": "edk2-pytool-extensions",
  "version": "%s",
  "feed": "ext_dep_unit_test_feed",
  "compression_type": "zip",
  "internal_path": "/",
  "pat_var": "PAT_FOR_UNIVERSAL_ORG_TIANOCORE"
}
"""


def prep_workspace() -> None:
    """Prepare the workspace."""
    global test_dir
    # if test temp dir doesn't exist
    if test_dir is None or not os.path.isdir(test_dir):
        test_dir = tempfile.mkdtemp()
        logging.debug("temp dir is: %s" % test_dir)
    else:
        clean_workspace()
        test_dir = tempfile.mkdtemp()


def clean_workspace() -> None:
    """Clean up the workspace."""
    global test_dir
    if test_dir is None:
        return

    if os.path.isdir(test_dir):
        RemoveTree(test_dir)
        test_dir = None


class MockRunCmd(MagicMock):
    """Mock of RunCmd that allows testcases to simulate output in the outstream."""

    out_string = ""

    @staticmethod
    def mock_RunCmd_outstream(
        cmd: str,
        parameters: str,
        capture: bool = True,
        workingdir: str = None,
        outfile: str | None = None,
        outstream: str | None = None,
        environ: dict | None = None,
        logging_level: int = logging.INFO,
        raise_exception_on_nonzero: bool = False,
        encodingErrors: str = "strict",
        close_fds: bool = True,
    ) -> int:
        """Mock of RunCmd that allows testcases to simulate output in the outstream."""
        outstream.write(MockRunCmd.out_string)
        return 0


class TestAzCliUniversalDependency(unittest.TestCase):
    """Unit test for the Azure CLI Artifacts Universal Packages Dependency class."""

    def setUp(self) -> None:
        """Set up the test environment."""
        prep_workspace()

    @classmethod
    def setUpClass(cls) -> None:
        """Set up the test environment."""
        logger = logging.getLogger("")
        logger.addHandler(logging.NullHandler())
        unittest.installHandler()

    @classmethod
    def tearDownClass(cls) -> None:
        """Clean up the workspace."""
        clean_workspace()

    def tearDown(self) -> None:
        """Clean up the workspace."""
        # we need to reset the version aggregator each time
        version_aggregator.GetVersionAggregator().Reset()

    # good case
    @unittest.skipIf(
        "PAT_FOR_UNIVERSAL_ORG_TIANOCORE" not in os.environ.keys(),
        "PAT not defined therefore universal packages tests will fail",
    )
    def test_download_good_universal_dependency_single_file(self) -> None:
        """Test that the Azure CLI is installed."""
        version = "0.0.1"
        ext_dep_file_path = os.path.join(test_dir, "unit_test_ext_dep.json")
        with open(ext_dep_file_path, "w+") as ext_dep_file:
            ext_dep_file.write(single_file_json_template % version)

        ext_dep_descriptor = EDF.ExternDepDescriptor(ext_dep_file_path).descriptor_contents
        ext_dep = AzureCliUniversalDependency(ext_dep_descriptor)
        ext_dep.fetch()
        self.assertTrue(ext_dep.verify())
        self.assertEqual(ext_dep.version, version)
        # make sure we clean up after ourselves
        ext_dep.clean()

    # good case
    @unittest.skipIf(
        "PAT_FOR_UNIVERSAL_ORG_TIANOCORE" not in os.environ.keys(),
        "PAT not defined therefore universal packages tests will fail",
    )
    def test_download_good_universal_dependency_folders_pinned_old_version(self) -> None:
        """Test that the Azure CLI is installed."""
        version = "0.2.0"
        ext_dep_file_path = os.path.join(test_dir, "unit_test_ext_dep.json")
        with open(ext_dep_file_path, "w+") as ext_dep_file:
            ext_dep_file.write(folders_json_template % version)

        ext_dep_descriptor = EDF.ExternDepDescriptor(ext_dep_file_path).descriptor_contents
        ext_dep = AzureCliUniversalDependency(ext_dep_descriptor)
        ext_dep.fetch()
        self.assertTrue(ext_dep.verify())
        self.assertEqual(ext_dep.version, version)
        # make sure we clean up after ourselves
        ext_dep.clean()

    # good case
    @unittest.skipIf(
        "PAT_FOR_UNIVERSAL_ORG_TIANOCORE" not in os.environ.keys(),
        "PAT not defined therefore universal packages tests will fail",
    )
    def test_download_good_universal_dependency_folders_newer_version(self) -> None:
        """Test that the Azure CLI is installed."""
        version = "0.2.1"
        ext_dep_file_path = os.path.join(test_dir, "unit_test_ext_dep.json")
        with open(ext_dep_file_path, "w+") as ext_dep_file:
            ext_dep_file.write(folders_json_template % version)

        ext_dep_descriptor = EDF.ExternDepDescriptor(ext_dep_file_path).descriptor_contents
        ext_dep = AzureCliUniversalDependency(ext_dep_descriptor)
        ext_dep.fetch()
        self.assertTrue(ext_dep.verify())
        self.assertEqual(ext_dep.version, version)
        # make sure we clean up after ourselves
        ext_dep.clean()

    # good case
    @unittest.skipIf(
        "PAT_FOR_UNIVERSAL_ORG_TIANOCORE" not in os.environ.keys(),
        "PAT not defined therefore universal packages tests will fail",
    )
    def test_download_good_universal_dependency_folders_file_filter(self) -> None:
        """Test that the Azure CLI is installed."""
        version = "0.2.1"
        ext_dep_file_path = os.path.join(test_dir, "unit_test_ext_dep.json")
        with open(ext_dep_file_path, "w+") as ext_dep_file:
            ext_dep_file.write(file_filter_json_template)

        ext_dep_descriptor = EDF.ExternDepDescriptor(ext_dep_file_path).descriptor_contents
        ext_dep = AzureCliUniversalDependency(ext_dep_descriptor)
        ext_dep.fetch()
        self.assertTrue(ext_dep.verify())
        self.assertEqual(ext_dep.version, version)

        # make sure we have 1 folder and 2 file (ext_Dep state file plus our 1 file from package)

        files = 0
        folders = 0

        for dirpath, dirs, file_names in os.walk(ext_dep.contents_dir):
            files += len(file_names)
            folders += len(dirs)

        self.assertEqual(folders, 1)
        self.assertEqual(files, 2)

        # make sure we clean up after ourselves
        ext_dep.clean()

    # bad case
    # note: similar to `test_download_bad_universal_dependency()` but more
    #       generally tests the non-zero return from `RunCmd()` behavior
    #       without depending on a PAT or other assumptions about the feed.
    @patch("edk2toolext.environment.extdeptypes.az_cli_universal_dependency.RunCmd", return_value=1)
    def test_cmd_run_non_zero(self, mock_run_cmd: MagicMock) -> None:
        """Test that the Azure CLI is installed."""
        version = "0.0.1"
        ext_dep_file_path = os.path.join(test_dir, "unit_test_ext_dep.json")
        with open(ext_dep_file_path, "w+") as ext_dep_file:
            ext_dep_file.write(single_file_json_template % version)

        ext_dep_descriptor = EDF.ExternDepDescriptor(ext_dep_file_path).descriptor_contents
        ext_dep = AzureCliUniversalDependency(ext_dep_descriptor)
        with self.assertRaises(Exception):
            ext_dep.fetch()

    # bad case
    @unittest.skipIf(
        "PAT_FOR_UNIVERSAL_ORG_TIANOCORE" not in os.environ.keys(),
        "PAT not defined therefore universal packages tests will fail",
    )
    def test_download_bad_universal_dependency(self) -> None:
        """Test that the Azure CLI is installed."""
        non_existing_version = "0.1.0"
        ext_dep_file_path = os.path.join(test_dir, "unit_test_ext_dep.json")
        with open(ext_dep_file_path, "w+") as ext_dep_file:
            ext_dep_file.write(single_file_json_template % non_existing_version)

        ext_dep_descriptor = EDF.ExternDepDescriptor(ext_dep_file_path).descriptor_contents
        ext_dep = AzureCliUniversalDependency(ext_dep_descriptor)
        with self.assertRaises(Exception):
            ext_dep.fetch()
        self.assertFalse(ext_dep.verify())

    @patch("edk2toolext.environment.extdeptypes.az_cli_universal_dependency.RunCmd", MockRunCmd.mock_RunCmd_outstream)
    def test_download_bad_results(self) -> None:
        """Test that the Azure CLI is installed."""
        version = "0.0.1"
        ext_dep_file_path = os.path.join(test_dir, "unit_test_ext_dep.json")
        with open(ext_dep_file_path, "w+") as ext_dep_file:
            ext_dep_file.write(single_file_json_template % version)
        ext_dep_descriptor = EDF.ExternDepDescriptor(ext_dep_file_path).descriptor_contents
        ext_dep = AzureCliUniversalDependency(ext_dep_descriptor)

        MockRunCmd.out_string = 'Properly handle this output!\n{"Version":"0.0.1"}'
        ext_dep._attempt_universal_install(ext_dep.get_temp_dir())
        # make sure we clean up after ourselves
        ext_dep.clean()

        MockRunCmd.out_string = "TEST! No json data here!"
        with self.assertRaises(ValueError):
            ext_dep._attempt_universal_install(ext_dep.get_temp_dir())
        # make sure we clean up after ourselves
        ext_dep.clean()

    @unittest.skipIf(
        "PAT_FOR_UNIVERSAL_ORG_TIANOCORE" not in os.environ.keys(),
        "PAT not defined therefore universal packages tests will fail",
    )
    def test_download_and_unzip(self) -> None:
        """Test that the Azure CLI is installed."""
        version = "0.0.1"
        ext_dep_file_path = os.path.join(test_dir, "unit_test_ext_dep.json")
        with open(ext_dep_file_path, "w+") as ext_dep_file:
            ext_dep_file.write(zip_json_template % version)

        ext_dep_descriptor = EDF.ExternDepDescriptor(ext_dep_file_path).descriptor_contents
        ext_dep = AzureCliUniversalDependency(ext_dep_descriptor)
        ext_dep.fetch()
        self.assertTrue(ext_dep.verify())
        self.assertEqual(ext_dep.version, version)

        files = 0
        folders = 0
        for _, dirs, file_names in os.walk(ext_dep.contents_dir):
            for file in file_names:
                assert file in ["extdep_state.yaml", "helloworld.txt"]

            files += len(file_names)
            folders += len(dirs)

        self.assertEqual(files, 2)  # yaml file and moved files.
        self.assertEqual(folders, 0)

        ext_dep.clean()

    @unittest.skipIf(
        "PAT_FOR_UNIVERSAL_ORG_TIANOCORE" not in os.environ.keys(),
        "PAT not defined therefore universal packages tests will fail",
    )
    def test_download_and_unzip2(self) -> None:
        """Test that the Azure CLI is installed."""
        version = "0.0.1"
        ext_dep_file_path = os.path.join(test_dir, "unit_test_ext_dep.json")
        with open(ext_dep_file_path, "w+") as ext_dep_file:
            ext_dep_file.write(zip_json_template2 % version)

        ext_dep_descriptor = EDF.ExternDepDescriptor(ext_dep_file_path).descriptor_contents
        ext_dep = AzureCliUniversalDependency(ext_dep_descriptor)
        ext_dep.fetch()
        self.assertTrue(ext_dep.verify())
        self.assertEqual(ext_dep.version, version)

        files = 0
        folders = 0
        for _, dirs, file_names in os.walk(ext_dep.contents_dir):
            for file in file_names:
                assert file in ["extdep_state.yaml", "helloworld.txt"]
            files += len(file_names)
            folders += len(dirs)

        self.assertEqual(files, 2)  # yaml file and moved files.
        self.assertEqual(folders, 1)  # helloworld.txt is in a folder, because the internal path is "/"

        ext_dep.clean()

    def test_az_tool_environment(self) -> None:
        """Test that the Azure CLI is installed."""
        AzureCliUniversalDependency.VerifyToolDependencies()


if __name__ == "__main__":
    unittest.main()
