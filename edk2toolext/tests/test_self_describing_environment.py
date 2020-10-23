# @file test_self_describing_environment.py
# This contains unit tests for the SDE
#
##
# Copyright (c) Microsoft Corporation
#
# SPDX-License-Identifier: BSD-2-Clause-Patent
##
import os
import unittest
import tempfile
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


if __name__ == '__main__':
    unittest.main()
