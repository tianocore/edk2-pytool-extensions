# @file test_repo_resolver.py
# This contains unit tests for repo resolver
#
##
# Copyright (c) Microsoft Corporation
#
# SPDX-License-Identifier: BSD-2-Clause-Patent
##
"""Unit test for the repo_resolver class."""

import logging
import os
import pathlib
import tempfile
import unittest
from typing import Optional
from unittest.mock import MagicMock, patch

import pytest
from edk2toolext.environment import repo_resolver
from edk2toollib.utility_functions import RemoveTree

branch_dependency = {
    "Url": "https://github.com/microsoft/mu",
    "Path": "test_repo",
    "Branch": "master",
    "Recurse": True,
}

sub_branch_dependency = {
    "Url": "https://github.com/microsoft/mu",
    "Path": "test_repo",
    "Branch": "gh-pages",
    "Recurse": True,
}

commit_dependency = {
    "Url": "https://github.com/microsoft/mu",
    "Path": "test_repo",
    "Commit": "b1e35a5d2bf05fb7f58f5b641a702c70d6b32a98",
    "Recurse": True,
}

short_commit_dependency = {
    "Url": "https://github.com/microsoft/mu",
    "Path": "test_repo",
    "Commit": "b1e35a5",
    "Recurse": True,
}

commit_later_dependency = {
    "Url": "https://github.com/microsoft/mu",
    "Path": "test_repo",
    "Commit": "e28910950c52256eb620e35d111945cdf5d002d1",
    "Recurse": True,
}

microsoft_commit_dependency = {
    "Url": "https://github.com/Microsoft/microsoft.github.io",
    "Path": "test_repo",
    "Commit": "e9153e69c82068b45609359f86554a93569d76f1",
    "Recurse": True,
}
microsoft_branch_dependency = {
    "Url": "https://github.com/Microsoft/microsoft.github.io",
    "Path": "test_repo",
    "Commit": "e9153e69c82068b45609359f86554a93569d76f1",
    "Recurse": True,
}

test_dir = None


def prep_workspace() -> None:
    """Prepare the workspace."""
    global test_dir
    # if test temp dir doesn't exist
    if test_dir is None or not os.path.isdir(test_dir):
        test_dir = tempfile.mkdtemp()
        logging.debug("temp dir is: %s" % test_dir)
    else:
        repo_resolver.clear_folder(test_dir)
        test_dir = tempfile.mkdtemp()


def clean_workspace() -> None:
    """Clean up the workspace."""
    global test_dir
    if test_dir is None:
        return

    if os.path.isdir(test_dir):
        repo_resolver.clear_folder(test_dir)
        test_dir = None


def get_first_file(folder: str) -> Optional[str]:
    """Get the first file in a folder."""
    folder_list = os.listdir(folder)
    for file_path in folder_list:
        path = os.path.join(folder, file_path)
        if os.path.isfile(path):
            return path
    return None


class test_repo_resolver(unittest.TestCase):
    """Unit test for the repo_resolver class."""

    def setUp(self) -> None:
        """Set up the workspace."""
        prep_workspace()

    @classmethod
    def setUpClass(cls) -> None:
        """Set up the workspace."""
        logger = logging.getLogger("")
        logger.setLevel(logging.DEBUG)
        logger.addHandler(logging.NullHandler())
        unittest.installHandler()

    @classmethod
    def tearDown(cls) -> None:
        """Clean up the workspace."""
        clean_workspace()

    # check to make sure that we can clone a branch correctly
    def test_clone_branch_repo(self) -> None:
        """Test that we can clone a branch."""
        # create an empty directory- and set that as the workspace
        repo_resolver.resolve(test_dir, branch_dependency)
        folder_path = os.path.join(test_dir, branch_dependency["Path"])
        details = repo_resolver.repo_details(folder_path)
        self.assertEqual(details["Url"], branch_dependency["Url"])
        self.assertEqual(details["Branch"], branch_dependency["Branch"])

    def test_clone_branch_existing_folder(self) -> None:
        """Test that we can clone a branch into an existing folder."""
        # Resolve when folder exists but is empty
        folder_path = os.path.join(test_dir, branch_dependency["Path"])
        os.makedirs(folder_path)
        repo_resolver.resolve(test_dir, branch_dependency)
        details = repo_resolver.repo_details(folder_path)
        self.assertEqual(details["Url"], branch_dependency["Url"])
        self.assertEqual(details["Branch"], branch_dependency["Branch"])

    # don't create a git repo, create the folder, add a file, try to clone in the folder, it should throw an exception
    def test_wont_delete_files(self) -> None:
        """Test that we can't delete files."""
        folder_path = os.path.join(test_dir, commit_dependency["Path"])
        os.makedirs(folder_path)
        file_path = os.path.join(folder_path, "test.txt")
        file_path = os.path.join(test_dir, branch_dependency["Path"], "test.txt")
        out_file = open(file_path, "w+")
        out_file.write("Make sure we don't delete this")
        out_file.close()
        self.assertTrue(os.path.isfile(file_path))
        with self.assertRaises(Exception):
            repo_resolver.resolve(test_dir, branch_dependency)
            self.fail("We shouldn't make it here")
        self.assertTrue(os.path.isfile(file_path))

    # don't create a git repo, create the folder, add a file, try to clone in the folder, will force it to happen
    def test_will_delete_files(self) -> None:
        """Test that we can delete files."""
        folder_path = os.path.join(test_dir, commit_dependency["Path"])
        os.makedirs(folder_path)
        file_path = os.path.join(folder_path, "test.txt")
        out_file = open(file_path, "w+")
        out_file.write("Make sure we don't delete this")
        out_file.close()
        self.assertTrue(os.path.exists(file_path))
        try:
            repo_resolver.resolve(test_dir, commit_dependency, force=True)
        except Exception:
            self.fail("We shouldn't fail when we are forcing")
        details = repo_resolver.repo_details(folder_path)
        self.assertEqual(details["Url"], commit_dependency["Url"])

    # don't create a git repo, create the folder, add a file, try to clone in the folder, will ignore it.
    def test_will_ignore_files(self) -> None:
        """Test that we can ignore files."""
        folder_path = os.path.join(test_dir, commit_dependency["Path"])
        os.makedirs(folder_path)
        file_path = os.path.join(folder_path, "test.txt")
        out_file = open(file_path, "w+")
        out_file.write("Make sure we don't delete this")
        out_file.close()
        self.assertTrue(os.path.exists(file_path))
        repo_resolver.resolve(test_dir, commit_dependency, ignore=True)

    def test_wont_delete_dirty_repo(self) -> None:
        """Test that we can't delete a dirty repo."""
        repo_resolver.resolve(test_dir, commit_dependency)

        folder_path = os.path.join(test_dir, commit_dependency["Path"])
        file_path = get_first_file(folder_path)
        # make sure the file already exists
        self.assertTrue(os.path.isfile(file_path))
        out_file = open(file_path, "a+")
        out_file.write("Make sure we don't delete this")
        out_file.close()
        self.assertTrue(os.path.exists(file_path))

        with self.assertRaises(Exception):
            repo_resolver.resolve(test_dir, commit_dependency, update_ok=True)

        # Get passed this with ignore=true
        repo_resolver.resolve(test_dir, commit_dependency, ignore=True)

    def test_will_delete_dirty_repo(self) -> None:
        """Test that we can delete a dirty repo."""
        repo_resolver.resolve(test_dir, commit_dependency)
        folder_path = os.path.join(test_dir, commit_dependency["Path"])
        file_path = get_first_file(folder_path)
        # make sure the file already exists
        self.assertTrue(os.path.isfile(file_path))
        out_file = open(file_path, "a+")
        out_file.write("Make sure we don't delete this")
        out_file.close()
        self.assertTrue(os.path.exists(file_path))

        try:
            repo_resolver.resolve(test_dir, commit_later_dependency, force=True)
        except Exception:
            self.fail("We shouldn't fail when we are forcing")

    # check to make sure we can clone a commit correctly
    def test_clone_commit_repo(self) -> None:
        """Test that we can clone a commit."""
        # create an empty directory- and set that as the workspace
        repo_resolver.resolve(test_dir, commit_dependency)
        folder_path = os.path.join(test_dir, commit_dependency["Path"])
        details = repo_resolver.repo_details(folder_path)

        self.assertEqual(details["Url"], commit_dependency["Url"])
        self.assertEqual(details["Head"]["HexSha"], commit_dependency["Commit"])

    # check to make sure we support short commits
    def test_clone_short_commit_repo(self) -> None:
        """Test that we can clone a short commit."""
        repo_resolver.resolve(test_dir, short_commit_dependency)
        folder_path = os.path.join(test_dir, short_commit_dependency["Path"])
        details = repo_resolver.repo_details(folder_path)

        self.assertEqual(details["Url"], short_commit_dependency["Url"])
        self.assertEqual(details["Head"]["HexShaShort"], short_commit_dependency["Commit"])
        # Resolve again, making sure we don't fail if repo already exists.
        repo_resolver.resolve(test_dir, short_commit_dependency)

    # check to make sure we can clone a commit correctly
    def test_fail_update(self) -> None:
        """Test that we can't update a repo."""
        # create an empty directory- and set that as the workspace
        repo_resolver.resolve(test_dir, commit_dependency)
        folder_path = os.path.join(test_dir, commit_dependency["Path"])
        details = repo_resolver.repo_details(folder_path)

        self.assertEqual(details["Url"], commit_dependency["Url"])
        self.assertEqual(details["Head"]["HexSha"], commit_dependency["Commit"])
        # first we checkout
        with self.assertRaises(Exception):
            repo_resolver.resolve(test_dir, commit_later_dependency)

        details = repo_resolver.repo_details(folder_path)
        self.assertEqual(details["Url"], commit_dependency["Url"])
        self.assertEqual(details["Head"]["HexSha"], commit_dependency["Commit"])

    def test_does_update(self) -> None:
        """Test that we can update a repo."""
        # create an empty directory- and set that as the workspace
        logging.info(f"Resolving at {test_dir}")
        repo_resolver.resolve(test_dir, commit_dependency)
        folder_path = os.path.join(test_dir, commit_dependency["Path"])
        logging.info(f"Getting details at {folder_path}")
        details = repo_resolver.repo_details(folder_path)

        self.assertEqual(details["Url"], commit_dependency["Url"])
        self.assertEqual(details["Head"]["HexSha"], commit_dependency["Commit"])
        # next we checkout and go to the later commit
        try:
            repo_resolver.resolve(test_dir, commit_later_dependency, update_ok=True)
        except Exception:
            self.fail("We are not supposed to throw an exception")
        details = repo_resolver.repo_details(folder_path)
        logging.info(f"Checking {folder_path} for current git commit")

        self.assertEqual(details["Url"], commit_later_dependency["Url"])
        self.assertEqual(details["Head"]["HexSha"], commit_later_dependency["Commit"])

    def test_cant_switch_urls(self) -> None:
        """Test that we can't switch urls."""
        # create an empty directory- and set that as the workspace
        repo_resolver.resolve(test_dir, branch_dependency)
        folder_path = os.path.join(test_dir, branch_dependency["Path"])

        details = repo_resolver.repo_details(folder_path)

        self.assertEqual(details["Url"], branch_dependency["Url"])
        # first we checkout
        with self.assertRaises(Exception):
            repo_resolver.resolve(test_dir, microsoft_branch_dependency)

        details = repo_resolver.repo_details(folder_path)
        self.assertEqual(details["Url"], branch_dependency["Url"])

    def test_ignore(self) -> None:
        """Test that we can ignore a repo."""
        # create an empty directory- and set that as the workspace
        repo_resolver.resolve(test_dir, branch_dependency)
        folder_path = os.path.join(test_dir, branch_dependency["Path"])

        details = repo_resolver.repo_details(folder_path)

        self.assertEqual(details["Url"], branch_dependency["Url"])
        # first we checkout

        repo_resolver.resolve(test_dir, microsoft_branch_dependency, ignore=True)

        details = repo_resolver.repo_details(folder_path)
        self.assertEqual(details["Url"], branch_dependency["Url"])

    def test_will_switch_urls(self) -> None:
        """Test that we can switch urls."""
        # create an empty directory- and set that as the workspace
        repo_resolver.resolve(test_dir, branch_dependency)

        folder_path = os.path.join(test_dir, branch_dependency["Path"])

        details = repo_resolver.repo_details(folder_path)

        self.assertEqual(details["Url"], branch_dependency["Url"])
        # first we checkout
        try:
            repo_resolver.resolve(test_dir, microsoft_branch_dependency, force=True)
        except Exception:
            self.fail("We shouldn't fail when we are forcing")

        details = repo_resolver.repo_details(folder_path)
        self.assertEqual(details["Url"], microsoft_branch_dependency["Url"])

    def test_will_switch_branches(self) -> None:
        """Test that we can switch branches."""
        repo_resolver.resolve(test_dir, branch_dependency)
        folder_path = os.path.join(test_dir, branch_dependency["Path"])
        repo_resolver.resolve(test_dir, sub_branch_dependency, force=True)
        details = repo_resolver.repo_details(folder_path)
        self.assertEqual(details["Url"], branch_dependency["Url"])
        self.assertEqual(details["Branch"], sub_branch_dependency["Branch"])

    @patch("git.Repo.is_dirty")
    def test_repo_details_is_dirty(self, mock_is_dirty: MagicMock) -> None:
        """Test that we can get details from a dirty repo that fails then succeeds."""
        _RAISE_GIT_EXCEPTION_COUNT = 3
        _side_effect_call_count = 0

        def _side_effect(*_args: str, **_kwargs: dict[str, any]) -> bool:
            nonlocal _side_effect_call_count
            if _side_effect_call_count < _RAISE_GIT_EXCEPTION_COUNT:
                _side_effect_call_count += 1
                raise repo_resolver.GitCommandError("mock_cmd", 128, "stderr_value", "stdout_value")
            else:
                return False

        mock_is_dirty.side_effect = _side_effect

        repo_resolver.resolve(test_dir, branch_dependency)
        folder_path = os.path.join(test_dir, branch_dependency["Path"])
        try:
            details = repo_resolver.repo_details(folder_path)
            self.assertEqual(details["Url"], branch_dependency["Url"])
            self.assertEqual(details["Branch"], branch_dependency["Branch"])
        except repo_resolver.GitCommandError:
            self.fail("GitCommandError was raised")

    def test_submodule(self) -> None:
        """Test that we can resolve a submodule."""

        class Submodule:
            def __init__(self, path: str, recursive: bool) -> None:
                """Inits Submodule."""
                self.path = path
                self.recursive = recursive

        temp_folder = tempfile.mkdtemp()
        submodule_path = "Common/MU"
        deps = {
            "Url": "https://github.com/microsoft/mu_tiano_platforms",
            "Recurse": True,
        }
        repo_resolver.clone_repo(temp_folder, deps)

        os.mkdir(os.path.join(temp_folder, "Build"))
        tmp_file = os.path.join(temp_folder, "Build", "tempfile.txt")
        with open(tmp_file, "x") as f:
            f.write("Temp edit")
            self.assertTrue(os.path.isfile(tmp_file))

            repo_resolver.clean(temp_folder, ignore_files=["Build/tempfile.txt"])
            self.assertTrue(os.path.isfile(tmp_file))

        repo_resolver.clean(temp_folder)
        self.assertFalse(os.path.isfile(tmp_file))

        repo_resolver.submodule_resolve(temp_folder, Submodule(submodule_path, True))

        RemoveTree(temp_folder)


def test_resolve_all(tmpdir: pathlib.Path) -> None:
    """Test that we can resolve multiple dependencies."""
    deps = [
        {
            "Url": "https://github.com/octocat/Spoon-Knife",
            "Path": "repo1",
            "Commit": "a30c19e3f13765a3b48829788bc1cb8b4e95cee4",
            "Recurse": True,
        },
        {
            "Url": "https://github.com/octocat/Spoon-Knife",
            "Path": "repo2",
            "Commit": "bb4cc8d3b2e14b3af5df699876dd4ff3acd00b7f",
            "Recurse": True,
        },
        {
            "Url": "https://github.com/octocat/Spoon-Knife",
            "Path": "repo3",
            "Commit": "d0dd1f61b33d64e29d8bc1372a94ef6a2fee76a9",
            "Recurse": False,
        },
    ]

    repos = repo_resolver.resolve_all(tmpdir, deps, force=True)

    for repo in repos:
        assert len(list(pathlib.Path(repo).iterdir())) > 0


def test_clone_from_with_reference(tmpdir: pathlib.Path) -> None:
    """Test that we can clone a repo from a reference repo."""
    # Clone the reference repo
    ref_path = pathlib.Path(tmpdir / "ref")
    dep = {
        "Url": "https://github.com/octocat/Spoon-Knife",
        "Recurse": True,
    }
    repo_resolver.clone_repo(ref_path, dep)
    assert len(list(ref_path.iterdir())) > 0

    # Clone the repo from the reference
    repo_path1 = pathlib.Path(tmpdir / "repo1")
    dep = {
        "Url": "https://github.com/octocat/Spoon-Knife",
        "ReferencePath": ref_path,
        "Recurse": True,
    }
    repo_resolver.clone_repo(repo_path1, dep)
    assert len(list(repo_path1.iterdir())) > 0

    # Clone the repo from a bad reference
    repo_path2 = pathlib.Path(tmpdir / "repo2")
    bad_repo_path = pathlib.Path(tmpdir / "bad_repo")
    dep = {
        "Url": "https://github.com/octocat/Spoon-Knife",
        "ReferencePath": bad_repo_path,
        "Recurse": True,
    }
    repo_resolver.clone_repo(repo_path2, dep)
    assert len(list(repo_path2.iterdir())) > 0


def test_checkout_branch(tmpdir: pathlib.Path) -> None:
    """Test that we can checkout a branch."""
    # Clone the repo
    dep = {
        "Url": "https://github.com/octocat/Spoon-Knife",
        "Path": tmpdir,
        "Branch": "main",
        "Recurse": True,
    }
    repo_resolver.clone_repo(tmpdir, dep)
    details = repo_resolver.repo_details(tmpdir)
    assert details["Branch"] == "main"

    # Checkout same branch
    repo_resolver.checkout(tmpdir, dep)
    details = repo_resolver.repo_details(tmpdir)
    assert details["Branch"] == "main"

    # Dep for the rest of the tests
    dep = {
        "Url": "https://github.com/octocat/Spoon-Knife",
        "Path": tmpdir,
        "Branch": "test-branch",
        "Recurse": True,
    }

    # Checkout different branch with ignore_dep_state_mismatch
    repo_resolver.checkout(tmpdir, dep, ignore_dep_state_mismatch=True)
    details = repo_resolver.repo_details(tmpdir)
    assert details["Branch"] == "main"

    # Checkout different branch without force
    with pytest.raises(Exception):
        repo_resolver.checkout(tmpdir, dep)

    # Checkout different branch with force
    repo_resolver.checkout(tmpdir, dep, force=True)
    details = repo_resolver.repo_details(tmpdir)
    assert details["Branch"] == "test-branch"


def test_checkout_bad_branch(tmpdir: pathlib.Path) -> None:
    """Test that the checkout function works with bad branches."""
    # Clone the repo
    dep = {
        "Url": "https://github.com/octocat/Spoon-Knife",
        "Path": tmpdir,
        "Branch": "main",
        "Recurse": True,
    }
    repo_resolver.clone_repo(tmpdir, dep)
    details = repo_resolver.repo_details(tmpdir)
    assert details["Branch"] == "main"

    # Checkout bad branch without forcing
    dep = {
        "Url": "https://github.com/octocat/Spoon-Knife",
        "Path": tmpdir,
        "Branch": "does not exist",
        "Recurse": True,
    }
    with pytest.raises(Exception):
        repo_resolver.checkout(tmpdir, dep)

    # Checkout bad branch with forcing
    with pytest.raises(repo_resolver.GitCommandError):
        repo_resolver.checkout(tmpdir, dep, force=True)
