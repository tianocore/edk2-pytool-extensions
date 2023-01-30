# @file test_self_describing_environment.py
# This contains unit tests for the SDE
#
##
# Copyright (c) Microsoft Corporation
#
# SPDX-License-Identifier: BSD-2-Clause-Patent
##
import os
import pygit2
import unittest
import tempfile
import yaml
from edk2toolext.environment import self_describing_environment
from edk2toolext.tests.uefi_tree import uefi_tree
from edk2toolext.environment import version_aggregator


class Testself_describing_environment(unittest.TestCase):

    def setUp(self):
        self.workspace = os.path.abspath(tempfile.mkdtemp())
        # we need to make sure to tear down the version aggregator and the SDE
        self_describing_environment.DestroyEnvironment()
        version_aggregator.ResetVersionAggregator()

    def test_null_init(self):
        sde = self_describing_environment.self_describing_environment(self.workspace)
        self.assertIsNotNone(sde)

    def test_unique_scopes_required(self):
        ''' make sure the sde will throw exception if duplicate scopes are specified '''
        scopes = ("corebuild", "corebuild", "testing", "CoreBuild")
        with self.assertRaises(ValueError):
            self_describing_environment.self_describing_environment(self.workspace, scopes)

    def test_collect_path_env(self):
        ''' makes sure the SDE can collect path env '''
        scopes = ("global",)
        tree = uefi_tree(self.workspace, create_platform=False)
        tree.create_path_env("testing_corebuild", var_name="hey", flags=["set_path", ])
        tree.create_path_env("testing_corebuild2", var_name="hey", flags=["set_pypath", ])
        tree.create_path_env("testing_corebuild3", var_name="hey", flags=["set_build_var", ])
        tree.create_path_env("testing_corebuild4", var_name="hey", flags=["set_shell_var", ])
        build_env, shell_env = self_describing_environment.BootstrapEnvironment(self.workspace, scopes)
        self.assertEqual(len(build_env.paths), 4)

    def test_collect_path_env_scoped(self):
        ''' makes sure the SDE can collect path env with the right scopes '''
        scopes = ("global", "testing")
        tree = uefi_tree(self.workspace, create_platform=False)
        tree.create_path_env("testing_corebuild", scope="testing")
        tree.create_path_env("testing_corebuild2", scope="not_valid")
        build_env, shell_env = self_describing_environment.BootstrapEnvironment(self.workspace, scopes)
        self.assertEqual(len(build_env.paths), 1)

    def test_override_path_env(self):
        ''' checks the SDE descriptor override system '''
        custom_scope = "global"
        scopes = (custom_scope,)
        tree = uefi_tree(self.workspace, create_platform=False)
        tree.create_path_env("testing_corebuild", var_name="hey", dir_path="test1", scope=custom_scope)
        tree.create_path_env("testing_corebuild2", var_name="jokes", scope=custom_scope,
                             extra_data={"override_id": "testing_corebuild"})
        build_env, shell_env = self_describing_environment.BootstrapEnvironment(self.workspace, scopes)
        self.assertEqual(len(build_env.paths), 1)

    def test_multiple_override_path_env(self):
        ''' checks the SDE descriptor override system will throw an error on multiple overrides'''
        custom_scope = "global"
        scopes = (custom_scope,)
        tree = uefi_tree(self.workspace, create_platform=False)
        tree.create_path_env("testing_corebuild", var_name="hey", dir_path="test1", scope=custom_scope)
        tree.create_path_env("testing_corebuild2", var_name="jokes", scope=custom_scope,
                             extra_data={"override_id": "testing_corebuild"})
        tree.create_path_env("testing_corebuild3", var_name="laughs", scope=custom_scope,
                             extra_data={"override_id": "testing_corebuild"})
        # we should get an exception because we have two overrides
        with self.assertRaises(RuntimeError):
            build_env, shell_env = self_describing_environment.BootstrapEnvironment(self.workspace, scopes)
            self.fail()

    def test_override_path_env_swapped_order(self):
        ''' checks the SDE descriptor override system with reversed paths so they are discovered in opposite order'''
        custom_scope = "global"
        scopes = (custom_scope,)
        tree = uefi_tree(self.workspace, create_platform=False)
        tree.create_path_env("testing_corebuild", var_name="hey", scope=custom_scope)
        tree.create_path_env(var_name="jokes", dir_path="test1", scope=custom_scope,
                             extra_data={"override_id": "testing_corebuild"})
        build_env, shell_env = self_describing_environment.BootstrapEnvironment(self.workspace, scopes)
        self.assertEqual(len(build_env.paths), 1)

    def test_duplicate_id_path_env(self):
        ''' check that the SDE will throw an exception if path_env have duplicate id's '''
        custom_scope = "global"
        scopes = (custom_scope,)
        tree = uefi_tree(self.workspace, create_platform=False)
        tree.create_path_env("testing_corebuild", dir_path="test1")
        tree.create_path_env("testing_corebuild")
        with self.assertRaises(RuntimeError):
            self_describing_environment.BootstrapEnvironment(self.workspace, scopes)
            self.fail()

    def test_duplicate_id_path_env_2(self):
        ''' check that the SDE will throw an exception if path env have duplicate id's.
        Since id is not a required member of path env make sure it can handle case where one of the path
        env files doesn't define an id'''
        custom_scope = "global"
        scopes = (custom_scope,)
        tree = uefi_tree(self.workspace, create_platform=False)
        tree.create_path_env("testing_corebuild", dir_path="test1")
        tree.create_path_env("testing_corebuild")
        tree.create_path_env()
        with self.assertRaises(RuntimeError):
            self_describing_environment.BootstrapEnvironment(self.workspace, scopes)
            self.fail()

    def test_git_worktree(self):
        """Check that the SDE will recognize a git worktree.

        Specifically verifies duplicate external dependencies in the git
        worktree are ignored that are discovered during SDE initialization.
        """
        # The workspace should not contain a git repo yet
        repo_path = pygit2.discover_repository(self.workspace)
        self.assertIsNone(repo_path)

        # Init a git repo in the workspace
        pygit2.init_repository(self.workspace, initial_head='master')
        repo_path = pygit2.discover_repository(self.workspace)
        self.assertIsNotNone(repo_path)

        repo = pygit2.Repository(self.workspace)

        # Create a UEFI tree
        repo_tree = uefi_tree(self.workspace, create_platform=True)
        self.assertIsNotNone(repo_tree)

        # Add ext deps to the tree
        repo_tree.create_ext_dep("nuget", "NuGet.CommandLine", "5.2.0")
        repo_tree.create_ext_dep("nuget", "NuGet.LibraryModel", "5.6.0")

        # Commit the UEFI tree to the master branch
        self.assertNotIn('master', repo.branches)
        index = repo.index
        index.add_all()
        index.write()
        author = pygit2.Signature('SDE Unit Test', 'uefibot@microsoft.com')
        message = "Add initial platform UEFI worktree"
        tree = index.write_tree()
        parents = []
        repo.create_commit('HEAD', author, author, message, tree, parents)
        self.assertIn('master', repo.branches)

        # Create the worktree branch
        worktree_branch = repo.branches.local.create('worktree_branch', commit=repo[repo.head.target])
        self.assertIn('worktree_branch', repo.branches)

        # Create a worktree on the worktree branch in the git repo
        self.assertFalse(repo.list_worktrees())
        repo.add_worktree('test_workspace', os.path.join(self.workspace, '.trees'), worktree_branch)
        worktrees = repo.list_worktrees()
        self.assertIn('test_workspace', worktrees)

        # Because this is a subtree, the duplicate ext_deps should be ignored
        # that are present in the worktree
        self_describing_environment.BootstrapEnvironment(self.workspace, ('global',))

    def test_no_verify_extdep(self):
        tree = uefi_tree(self.workspace, create_platform=False)
        tree.create_ext_dep(dep_type="git",
                            scope="global",
                            name="HelloWorld",
                            source="https://github.com/octocat/Hello-World.git",
                            version="7fd1a60b01f91b314f59955a4e4d4e80d8edf11d")

        # Bootstrap the environment
        self_describing_environment.BootstrapEnvironment(self.workspace, ("global",))
        self_describing_environment.UpdateDependencies(self.workspace, scopes=("global",))
        self_describing_environment.VerifyEnvironment(self.workspace, scopes=("global",))

        # Delete the readme to make the repo dirty then verify it fails
        readme = os.path.join(tree.get_workspace(), "HelloWorld_extdep", "HelloWorld", "README")
        os.remove(readme)
        self.assertFalse(self_describing_environment.VerifyEnvironment(self.workspace, scopes=("global",)))

        # Update the state file to not verify the specific external dependency then verify it passes
        state_file = os.path.join(tree.get_workspace(), "HelloWorld_extdep", "extdep_state.yaml")
        with open(state_file, 'r+') as f:
            content = yaml.safe_load(f)
            f.seek(0)
            content["verify"] = False
            yaml.safe_dump(content, f)
        self.assertTrue(self_describing_environment.VerifyEnvironment(self.workspace, scopes=("global",)))


if __name__ == '__main__':
    unittest.main()
