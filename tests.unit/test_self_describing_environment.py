# @file test_self_describing_environment.py
# This contains unit tests for the SDE
#
##
# Copyright (c) Microsoft Corporation
#
# SPDX-License-Identifier: BSD-2-Clause-Patent
##
"""Unit test for the self_describing_environment class."""

import pathlib
import tempfile
import unittest

import git
from edk2toolext.environment import self_describing_environment, version_aggregator
from uefi_tree import uefi_tree


class Testself_describing_environment(unittest.TestCase):
    """Unit test for the self_describing_environment class."""

    def setUp(self) -> None:
        """Create a temporary workspace and reset the version aggregator."""
        self.workspace = pathlib.Path(tempfile.mkdtemp()).resolve()
        # we need to make sure to tear down the version aggregator and the SDE
        self_describing_environment.DestroyEnvironment()
        version_aggregator.ResetVersionAggregator()

    def test_null_init(self) -> None:
        """Make sure the SDE can be initialized with no args."""
        sde = self_describing_environment.self_describing_environment(self.workspace)
        self.assertIsNotNone(sde)

    def test_unique_scopes_required(self) -> None:
        """Make sure the sde will throw exception if duplicate scopes are specified."""
        scopes = ("corebuild", "corebuild", "testing", "CoreBuild")
        with self.assertRaises(ValueError):
            self_describing_environment.self_describing_environment(self.workspace, scopes)

    def test_collect_path_env(self) -> None:
        """Makes sure the SDE can collect path env."""
        scopes = ("global",)
        tree = uefi_tree(self.workspace, create_platform=False)
        tree.create_path_env(
            "testing_corebuild",
            var_name="hey",
            flags=[
                "set_path",
            ],
        )
        tree.create_path_env(
            "testing_corebuild2",
            var_name="hey",
            flags=[
                "set_pypath",
            ],
        )
        tree.create_path_env(
            "testing_corebuild3",
            var_name="hey",
            flags=[
                "set_build_var",
            ],
        )
        tree.create_path_env(
            "testing_corebuild4",
            var_name="hey",
            flags=[
                "set_shell_var",
            ],
        )
        build_env, shell_env = self_describing_environment.BootstrapEnvironment(self.workspace, scopes)
        self.assertEqual(len(build_env.paths), 4)

    def test_collect_path_env_scoped(self) -> None:
        """Makes sure the SDE can collect path env with the right scopes."""
        scopes = ("global", "testing")
        tree = uefi_tree(self.workspace, create_platform=False)
        tree.create_path_env("testing_corebuild", scope="testing")
        tree.create_path_env("testing_corebuild2", scope="not_valid")
        build_env, shell_env = self_describing_environment.BootstrapEnvironment(self.workspace, scopes)
        self.assertEqual(len(build_env.paths), 1)

    def test_override_path_env(self) -> None:
        """Checks the SDE descriptor override system."""
        custom_scope = "global"
        scopes = (custom_scope,)
        tree = uefi_tree(self.workspace, create_platform=False)
        tree.create_path_env("testing_corebuild", var_name="hey", dir_path="test1", scope=custom_scope)
        tree.create_path_env(
            "testing_corebuild2", var_name="jokes", scope=custom_scope, extra_data={"override_id": "testing_corebuild"}
        )
        build_env, shell_env = self_describing_environment.BootstrapEnvironment(self.workspace, scopes)
        self.assertEqual(len(build_env.paths), 1)

    def test_multiple_override_path_env(self) -> None:
        """Checks the SDE descriptor override system will throw an error on multiple overrides."""
        custom_scope = "global"
        scopes = (custom_scope,)
        tree = uefi_tree(self.workspace, create_platform=False)
        tree.create_path_env("testing_corebuild", var_name="hey", dir_path="test1", scope=custom_scope)
        tree.create_path_env(
            "testing_corebuild2", var_name="jokes", scope=custom_scope, extra_data={"override_id": "testing_corebuild"}
        )
        tree.create_path_env(
            "testing_corebuild3", var_name="laughs", scope=custom_scope, extra_data={"override_id": "testing_corebuild"}
        )
        # we should get an exception because we have two overrides
        with self.assertRaises(RuntimeError):
            build_env, shell_env = self_describing_environment.BootstrapEnvironment(self.workspace, scopes)
            self.fail()

    def test_override_path_env_swapped_order(self) -> None:
        """Checks the SDE descriptor override system with reversed paths so they are discovered in opposite order."""
        custom_scope = "global"
        scopes = (custom_scope,)
        tree = uefi_tree(self.workspace, create_platform=False)
        tree.create_path_env("testing_corebuild", var_name="hey", scope=custom_scope)
        tree.create_path_env(
            var_name="jokes", dir_path="test1", scope=custom_scope, extra_data={"override_id": "testing_corebuild"}
        )
        build_env, shell_env = self_describing_environment.BootstrapEnvironment(self.workspace, scopes)
        self.assertEqual(len(build_env.paths), 1)

    def test_duplicate_id_path_env(self) -> None:
        """Check that the SDE will throw an exception if path_env have duplicate id's."""
        custom_scope = "global"
        scopes = (custom_scope,)
        tree = uefi_tree(self.workspace, create_platform=False)
        tree.create_path_env("testing_corebuild", dir_path="test1")
        tree.create_path_env("testing_corebuild")
        with self.assertRaises(RuntimeError):
            self_describing_environment.BootstrapEnvironment(self.workspace, scopes)
            self.fail()

    def test_duplicate_id_path_env_2(self) -> None:
        """Check that the SDE will throw an exception if path env have duplicate id's.

        Since id is not a required member of path env make sure it can handle case where one of the path
        env files doesn't define an id
        """
        custom_scope = "global"
        scopes = (custom_scope,)
        tree = uefi_tree(self.workspace, create_platform=False)
        tree.create_path_env("testing_corebuild", dir_path="test1")
        tree.create_path_env("testing_corebuild")
        tree.create_path_env()
        with self.assertRaises(RuntimeError):
            self_describing_environment.BootstrapEnvironment(self.workspace, scopes)
            self.fail()

    def test_git_worktree(self) -> None:
        """Test that the SDE can handle a git worktree."""
        repo = git.Repo.init(self.workspace)
        repo.create_remote("origin", "https://github.com/username/repo.git")

        repo_tree = uefi_tree(self.workspace, create_platform=True)
        self.assertIsNotNone(repo_tree)

        files = []
        files.append(repo_tree.create_ext_dep("nuget", "NuGet.CommandLine", "5.2.0"))
        files.append(repo_tree.create_ext_dep("nuget", "NuGet.LibraryModel", "5.6.0"))

        repo.index.add(files)
        self.assertEqual(len(repo.branches), 0)
        actor = git.Actor("John Doe", "john.doe@example.com")
        repo.index.commit("A Commit", author=actor, committer=actor)
        self.assertEqual(len(repo.branches), 1)

        repo.git.worktree("add", "my_worktree")
        self_describing_environment.BootstrapEnvironment(self.workspace, ("global",))


if __name__ == "__main__":
    unittest.main()
