## @file test_git_dependency.py
# Unit test suite for the GitDependency class.
#
##
# Copyright (c) Microsoft Corporation
#
# SPDX-License-Identifier: BSD-2-Clause-Patent
##
"""Unit test suite for the GitDependency class."""

import copy
import logging
import os
import tempfile
import unittest

from edk2toolext.environment import environment_descriptor_files as EDF
from edk2toolext.environment import shell_environment
from edk2toolext.environment.extdeptypes.git_dependency import GitDependency
from edk2toolext.environment.repo_resolver import clear_folder

test_dir = None
uptodate_version = "7fd1a60b01f91b314f59955a4e4d4e80d8edf11d"
behind_one_version = "762941318ee16e59dabbacb1b4049eec22f0d303"
invalid_version = "762941318ee16e59d123456789049eec22f0d303"
short_version = "7fd1a60"
short_upper_version = "7FD1A60"

hw_json_template = """
{
  "scope": "global",
  "type": "git",
  "name": "HelloWorld",
  "source": "https://github.com/octocat/Hello-World.git",
  "version": "%s",
  "flags": [],
  "Recurse": True,
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
        clear_folder(test_dir)
        test_dir = None


class TestGitDependency(unittest.TestCase):
    """Unit test suite for the GitDependency class."""

    def setUp(self) -> None:
        """Set up the test environment."""
        prep_workspace()

    @classmethod
    def setUpClass(cls) -> None:
        """Set up the test class."""
        logger = logging.getLogger("")
        logger.addHandler(logging.NullHandler())
        unittest.installHandler()

    @classmethod
    def tearDownClass(cls) -> None:
        """Restore the environment to its original state."""
        clean_workspace()

    # good case
    def test_fetch_verify_good_repo_at_top_of_tree(self) -> None:
        """Test that the fetch and verify functions work with a good repo at the top of the tree."""
        ext_dep_file_path = os.path.join(test_dir, "hw_ext_dep.json")
        with open(ext_dep_file_path, "w+") as ext_dep_file:
            ext_dep_file.write(hw_json_template % uptodate_version)

        ext_dep_descriptor = EDF.ExternDepDescriptor(ext_dep_file_path).descriptor_contents
        ext_dep = GitDependency(ext_dep_descriptor)
        ext_dep.fetch()
        self.assertTrue(ext_dep.verify())
        self.assertEqual(ext_dep.version, uptodate_version)

    def test_fetch_verify_short_commit_hash(self) -> None:
        """Test that a short commit hash is accepted."""
        ext_dep_file_path = os.path.join(test_dir, "hw_ext_dep.json")
        with open(ext_dep_file_path, "w+") as ext_dep_file:
            ext_dep_file.write(hw_json_template % short_version)
        ext_dep_descriptor = EDF.ExternDepDescriptor(ext_dep_file_path).descriptor_contents
        ext_dep = GitDependency(ext_dep_descriptor)
        ext_dep.fetch()
        self.assertTrue(ext_dep.verify())
        self.assertEqual(ext_dep.version, short_version)

    def test_fetch_verify_short_upper_commit_hash(self) -> None:
        """Test that the short upper commit hash is verified."""
        ext_dep_file_path = os.path.join(test_dir, "hw_ext_dep.json")
        with open(ext_dep_file_path, "w+") as ext_dep_file:
            ext_dep_file.write(hw_json_template % short_upper_version)
        ext_dep_descriptor = EDF.ExternDepDescriptor(ext_dep_file_path).descriptor_contents
        ext_dep = GitDependency(ext_dep_descriptor)
        ext_dep.fetch()
        self.assertTrue(ext_dep.verify())
        self.assertEqual(ext_dep.version, short_upper_version)

    def test_fetch_verify_good_repo_at_not_top_of_tree(self) -> None:
        """Test that the fetch and verify functions work with a repo that is not at the top of the tree."""
        ext_dep_file_path = os.path.join(test_dir, "hw_ext_dep.json")
        with open(ext_dep_file_path, "w+") as ext_dep_file:
            ext_dep_file.write(hw_json_template % behind_one_version)

        ext_dep_descriptor = EDF.ExternDepDescriptor(ext_dep_file_path).descriptor_contents
        ext_dep = GitDependency(ext_dep_descriptor)
        ext_dep.fetch()
        self.assertTrue(ext_dep.verify())
        self.assertEqual(ext_dep.version, behind_one_version)

    def test_fetch_verify_non_existant_repo_commit_hash(self) -> None:
        """Test that the fetch function works with a non-existent repo."""
        ext_dep_file_path = os.path.join(test_dir, "hw_ext_dep.json")
        with open(ext_dep_file_path, "w+") as ext_dep_file:
            ext_dep_file.write(hw_json_template % invalid_version)

        ext_dep_descriptor = EDF.ExternDepDescriptor(ext_dep_file_path).descriptor_contents
        ext_dep = GitDependency(ext_dep_descriptor)
        ext_dep.fetch()
        self.assertEqual(ext_dep.version, invalid_version)
        self.assertFalse(ext_dep.verify(), "Should not verify")

    def test_verify_no_directory(self) -> None:
        """Test that the verify function works with no directory."""
        ext_dep_file_path = os.path.join(test_dir, "hw_ext_dep.json")
        with open(ext_dep_file_path, "w+") as ext_dep_file:
            ext_dep_file.write(hw_json_template % invalid_version)

        ext_dep_descriptor = EDF.ExternDepDescriptor(ext_dep_file_path).descriptor_contents
        ext_dep = GitDependency(ext_dep_descriptor)
        self.assertFalse(ext_dep.verify())

    def test_verify_empty_repo_dir(self) -> None:
        """Test that an empty repo directory is not verified."""
        ext_dep_file_path = os.path.join(test_dir, "hw_ext_dep.json")
        with open(ext_dep_file_path, "w+") as ext_dep_file:
            ext_dep_file.write(hw_json_template % invalid_version)

        ext_dep_descriptor = EDF.ExternDepDescriptor(ext_dep_file_path).descriptor_contents
        ext_dep = GitDependency(ext_dep_descriptor)
        os.makedirs(ext_dep._local_repo_root_path, exist_ok=True)
        self.assertFalse(ext_dep.verify())

    def test_verify_invalid_git_repo(self) -> None:
        """Test that an invalid git repo is not verified."""
        ext_dep_file_path = os.path.join(test_dir, "hw_ext_dep.json")
        with open(ext_dep_file_path, "w+") as ext_dep_file:
            ext_dep_file.write(hw_json_template % invalid_version)

        ext_dep_descriptor = EDF.ExternDepDescriptor(ext_dep_file_path).descriptor_contents
        ext_dep = GitDependency(ext_dep_descriptor)
        os.makedirs(ext_dep._local_repo_root_path, exist_ok=True)
        with open(os.path.join(ext_dep._local_repo_root_path, "testfile.txt"), "a") as my_file:
            my_file.write("Test code\n")
        self.assertFalse(ext_dep.verify())

    def test_verify_dirty_git_repo(self) -> None:
        """Test that a dirty git repo is not verified."""
        ext_dep_file_path = os.path.join(test_dir, "hw_ext_dep.json")
        with open(ext_dep_file_path, "w+") as ext_dep_file:
            ext_dep_file.write(hw_json_template % uptodate_version)

        ext_dep_descriptor = EDF.ExternDepDescriptor(ext_dep_file_path).descriptor_contents
        ext_dep = GitDependency(ext_dep_descriptor)
        ext_dep.fetch()
        # now write a new file
        with open(os.path.join(ext_dep._local_repo_root_path, "testfile.txt"), "a") as my_file:
            my_file.write("Test code to make repo dirty\n")
        self.assertFalse(ext_dep.verify())

    def test_verify_up_to_date(self) -> None:
        """Test that the verify function returns True when the repo is up to date."""
        ext_dep_file_path = os.path.join(test_dir, "hw_ext_dep.json")
        with open(ext_dep_file_path, "w+") as ext_dep_file:
            ext_dep_file.write(hw_json_template % uptodate_version)

        ext_dep_descriptor = EDF.ExternDepDescriptor(ext_dep_file_path).descriptor_contents
        ext_dep = GitDependency(ext_dep_descriptor)
        ext_dep.fetch()
        self.assertTrue(ext_dep.verify())

    def test_verify_down_level_repo(self) -> None:
        """Test that the verify function works with a repo that is one commit behind."""
        ext_dep_file_path = os.path.join(test_dir, "hw_ext_dep.json")
        with open(ext_dep_file_path, "w+") as ext_dep_file:
            ext_dep_file.write(hw_json_template % behind_one_version)

        ext_dep_descriptor = EDF.ExternDepDescriptor(ext_dep_file_path).descriptor_contents
        ext_dep = GitDependency(ext_dep_descriptor)
        ext_dep.fetch()
        self.assertTrue(ext_dep.verify(), "Confirm valid ext_dep at one commit behind")

        with open(ext_dep_file_path, "w+") as ext_dep_file:
            ext_dep_file.write(hw_json_template % uptodate_version)

        ext_dep_descriptor = EDF.ExternDepDescriptor(ext_dep_file_path).descriptor_contents
        ext_dep = GitDependency(ext_dep_descriptor)
        self.assertFalse(ext_dep.verify(), "Confirm downlevel repo fails to verify")
        ext_dep.fetch()
        self.assertTrue(ext_dep.verify(), "Confirm repo can be updated")

    # CLEAN TESTS

    def test_clean_no_directory(self) -> None:
        """Test that the clean function works with no directory."""
        ext_dep_file_path = os.path.join(test_dir, "hw_ext_dep.json")
        with open(ext_dep_file_path, "w+") as ext_dep_file:
            ext_dep_file.write(hw_json_template % uptodate_version)

        ext_dep_descriptor = EDF.ExternDepDescriptor(ext_dep_file_path).descriptor_contents
        ext_dep = GitDependency(ext_dep_descriptor)
        self.assertFalse(os.path.isdir(ext_dep.contents_dir), "Confirm not ext dep directory before cleaning")
        ext_dep.clean()
        self.assertFalse(os.path.isdir(ext_dep.contents_dir))

    def test_clean_dir_but_not_git_repo(self) -> None:
        """Test that the clean function works with a directory that is not a git repo."""
        ext_dep_file_path = os.path.join(test_dir, "hw_ext_dep.json")
        with open(ext_dep_file_path, "w+") as ext_dep_file:
            ext_dep_file.write(hw_json_template % invalid_version)

        ext_dep_descriptor = EDF.ExternDepDescriptor(ext_dep_file_path).descriptor_contents
        ext_dep = GitDependency(ext_dep_descriptor)
        os.makedirs(ext_dep._local_repo_root_path, exist_ok=True)
        with open(os.path.join(ext_dep._local_repo_root_path, "testfile.txt"), "a") as my_file:
            my_file.write("Test code\n")
        ext_dep.clean()
        self.assertFalse(os.path.isdir(ext_dep.contents_dir))

    def test_clean_dirty_git_repo(self) -> None:
        """Test that the clean function works with a dirty repo."""
        ext_dep_file_path = os.path.join(test_dir, "hw_ext_dep.json")
        with open(ext_dep_file_path, "w+") as ext_dep_file:
            ext_dep_file.write(hw_json_template % uptodate_version)

        ext_dep_descriptor = EDF.ExternDepDescriptor(ext_dep_file_path).descriptor_contents
        ext_dep = GitDependency(ext_dep_descriptor)
        ext_dep.fetch()
        self.assertTrue(ext_dep.verify(), "Confirm repo is valid")
        # now write a new file
        with open(os.path.join(ext_dep._local_repo_root_path, "testfile.txt"), "a") as my_file:
            my_file.write("Test code to make repo dirty\n")
        self.assertFalse(ext_dep.verify(), "Confirm repo is dirty")
        ext_dep.clean()
        self.assertFalse(os.path.isdir(ext_dep.contents_dir))

    def test_clean_clean_repo(self) -> None:
        """Test that the clean function works with a clean repo."""
        ext_dep_file_path = os.path.join(test_dir, "hw_ext_dep.json")
        with open(ext_dep_file_path, "w+") as ext_dep_file:
            ext_dep_file.write(hw_json_template % uptodate_version)

        ext_dep_descriptor = EDF.ExternDepDescriptor(ext_dep_file_path).descriptor_contents
        ext_dep = GitDependency(ext_dep_descriptor)
        ext_dep.fetch()
        self.assertTrue(ext_dep.verify(), "Confirm repo is valid and clean")
        ext_dep.clean()
        self.assertFalse(os.path.isdir(ext_dep.contents_dir))


class TestGitDependencyUrlPatching(unittest.TestCase):
    """Unit test suite for the GitDependency class."""

    TEST_DESCRIPTOR = {
        "descriptor_file": os.path.abspath(__file__),
        "scope": "global",
        "type": "git",
        "name": "HelloWorld",
        "source": "https://github.com/octocat/Hello-World.git",
        "version": "7fd1a60b01f91b314f59955a4e4d4e80d8edf11d",
        "flags": [],
        "Recurse": True,
    }

    def tearDown(self) -> None:
        """Restore the environment to its original state."""
        env = shell_environment.GetEnvironment()
        env.restore_checkpoint(TestGitDependencyUrlPatching.env_checkpoint)

    @classmethod
    def setUpClass(cls) -> None:
        """Set up the test class."""
        env = shell_environment.GetEnvironment()
        cls.env_checkpoint = env.checkpoint()

    #
    # URL FORMATTING TESTS
    #
    def test_url_should_not_be_modified_without_env(self) -> None:
        """Test that the URL is not modified if the creds are not supplied."""
        my_test_descriptor = copy.copy(TestGitDependencyUrlPatching.TEST_DESCRIPTOR)
        # Add the indicator for patching.
        my_test_descriptor["url_creds_var"] = "test_creds_var"

        # Initialize the GitDependency object.
        git_dep = GitDependency(my_test_descriptor)

        # Assert that the URL is identical.
        self.assertEqual(git_dep.source, my_test_descriptor["source"])

    def test_url_should_not_be_modified_without_descriptor_field(self) -> None:
        """Test that the URL is not modified if the creds are indicated but not supplied."""
        my_test_descriptor = copy.copy(TestGitDependencyUrlPatching.TEST_DESCRIPTOR)

        env = shell_environment.GetEnvironment()
        # Add the var to the environment.
        env.set_shell_var("test_creds_var", "my_stuff")

        # Initialize the GitDependency object.
        git_dep = GitDependency(my_test_descriptor)

        # Assert that the URL is identical.
        self.assertEqual(git_dep.source, my_test_descriptor["source"])

    def test_url_should_be_modified_if_creds_are_indicated_and_supplied(self) -> None:
        """Test that the URL is modified if the creds are indicated and supplied."""
        my_test_descriptor = copy.copy(TestGitDependencyUrlPatching.TEST_DESCRIPTOR)
        # Add the indicator for patching.
        my_test_descriptor["url_creds_var"] = "test_creds_var"

        env = shell_environment.GetEnvironment()
        # Add the var to the environment.
        env.set_shell_var("test_creds_var", "my_stuff")

        # Initialize the GitDependency object.
        git_dep = GitDependency(my_test_descriptor)

        # Assert that the URL is identical.
        self.assertEqual(git_dep.source, "https://my_stuff@github.com/octocat/Hello-World.git")


if __name__ == "__main__":
    unittest.main()
