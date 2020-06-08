# @file test_edk2_update.py
# This contains unit tests for the edk2_update
##
# Copyright (c) Microsoft Corporation
#
# SPDX-License-Identifier: BSD-2-Clause-Patent
##
import unittest
from edk2toolext.invocables.edk2_update import Edk2Update
import tempfile
import sys
import os
import logging
from importlib import reload
from edk2toolext.environment import shell_environment
from edk2toolext.tests.uefi_tree import uefi_tree
from edk2toolext.environment import self_describing_environment
from edk2toolext.environment import version_aggregator


class TestEdk2Update(unittest.TestCase):

    temp_folders = []

    def tearDown(self):
        shell_environment.GetEnvironment().restore_initial_checkpoint()
        for temp_folder in TestEdk2Update.temp_folders:
            logging.info(f"Cleaning up {temp_folder}")
            # shutil.rmtree(os.path.abspath(temp_folder), ignore_errors=True)
        TestEdk2Update.restart_logging()
        # we need to make sure to tear down the version aggregator and the SDE
        self_describing_environment.DestroyEnvironment()
        version_aggregator.ResetVersionAggregator()

    @classmethod
    def restart_logging(cls):
        logging.shutdown()
        reload(logging)

    @classmethod
    def updateClass(cls):
        pass

    @classmethod
    def tearDownClass(cls):
        pass

    @classmethod
    def get_temp_folder(cls):
        temp_folder = os.path.abspath(tempfile.mkdtemp())
        TestEdk2Update.temp_folders.append(temp_folder)
        return os.path.abspath(temp_folder)

    def invoke_update(self, settings_filepath, args=[], failure_expected=False):
        sys.argv = ["stuart_update", "-c", settings_filepath]
        sys.argv.extend(args)
        builder = Edk2Update()
        try:
            builder.Invoke()
        except SystemExit as e:
            if failure_expected:
                self.assertIsNot(e.code, 0, "We should have a non zero error code")
            else:
                self.assertIs(e.code, 0, "We should have a zero error code")
        return builder

    #######################################
    # Test methods
    def test_init(self):
        WORKSPACE = self.get_temp_folder()
        tree = uefi_tree(WORKSPACE)
        settings_filepath = tree.get_settings_provider_path()
        sys.argv = ["stuart_update", "-c", settings_filepath]
        builder = Edk2Update()
        self.assertIsNotNone(builder)

    def test_one_level_recursive(self):
        ''' makes sure we can do a recursive update '''
        WORKSPACE = self.get_temp_folder()
        tree = uefi_tree(WORKSPACE)
        logging.getLogger().setLevel(logging.WARNING)
        tree.create_Edk2TestUpdate_ext_dep()
        # Do the update
        updater = self.invoke_update(tree.get_settings_provider_path())
        # make sure it worked
        self.assertTrue(os.path.exists(os.path.join(WORKSPACE, "Edk2TestUpdate_extdep",
                                                    "NuGet.CommandLine_extdep", "extdep_state.json")))
        build_env, shell_env, failure = updater.PerformUpdate()
        # we should have no failures
        self.assertEqual(failure, 0)
        # we should have found two ext deps
        self.assertEqual(len(build_env.extdeps), 2)

    def test_multiple_extdeps(self):
        ''' makes sure we can do multiple ext_deps at the same time '''
        WORKSPACE = self.get_temp_folder()
        tree = uefi_tree(WORKSPACE)
        num_of_ext_deps = 5
        logging.getLogger().setLevel(logging.WARNING)
        tree.create_ext_dep("nuget", "NuGet.CommandLine", "5.2.0")
        tree.create_ext_dep("nuget", "NuGet.LibraryModel", "5.6.0")
        tree.create_ext_dep("nuget", "NuGet.Versioning", "5.6.0")
        tree.create_ext_dep("nuget", "NuGet.Packaging.Core", "5.6.0")
        tree.create_ext_dep("nuget", "NuGet.RuntimeModel", "4.2.0")
        # Do the update
        updater = self.invoke_update(tree.get_settings_provider_path())
        build_env, shell_env, failure = updater.PerformUpdate()
        # we should have no failures
        self.assertEqual(failure, 0)
        # we should have found two ext deps
        self.assertEqual(len(build_env.extdeps), num_of_ext_deps)

    def test_bad_ext_dep(self):
        ''' makes sure we can do an update that will fail '''
        WORKSPACE = self.get_temp_folder()
        tree = uefi_tree(WORKSPACE)
        logging.getLogger().setLevel(logging.WARNING)
        # we know this version is bad
        tree.create_Edk2TestUpdate_ext_dep("0.0.0")
        # Do the update
        updater = self.invoke_update(tree.get_settings_provider_path(), failure_expected=True)
        build_env, shell_env, failure = updater.PerformUpdate()
        # we should have no failures
        self.assertEqual(failure, 1)
