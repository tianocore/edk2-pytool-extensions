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
from edk2toollib.utility_functions import RunCmd
from edk2toolext.environment import shell_environment
from edk2toolext.edk2_git import Repo
from edk2toolext.environment import self_describing_environment
from edk2toolext.tests.minimal_uefi_tree.uefi_tree import uefi_tree


class TestEdk2Update(unittest.TestCase):

    def update(self):
        TestEdk2Update.restart_logging()
        pass

    def tearDown(self):
        shell_environment.GetEnvironment().restore_initial_checkpoint()
        for temp_folder in TestEdk2Update.temp_folders:
            logging.info(f"Cleaning up {temp_folder}")
            # shutil.rmtree(os.path.abspath(temp_folder), ignore_errors=True)
        TestEdk2Update.restart_logging()
        pass

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
        builder = Edk2Update()
        sys.argv = ["stuart_update", "-c", settings_filepath]
        sys.argv.extend(args)
        try:
            builder.Invoke()
        except SystemExit as e:
            if failure_expected:
                self.assertIs(e.code, 0, "We should have a non zero error code")
            else:
                self.assertIs(e.code, 0, "We should have a zero error code")
        return builder

    #######################################
    # Test methods
    def test_init(self):
        builder = Edk2Update()
        self.assertIsNotNone(builder)

    def test_one_level_recursive(self):
        ''' makes sure we can do a recursive update '''
        WORKSPACE = self.get_temp_folder()
        tree = uefi_tree(WORKSPACE)
        logging.getLogger().setLevel(logging.WARNING)
        tree.create_ext_dep("nuget", "Edk2TestUpdate", "0.0.1")
        # Do the update
        self.invoke_update(tree.get_settings_provider_path())
        # make sure it worked
        # we're going to request two packages from nuget -> the first contains an extdep for the second
        # Edk2TestUpdate_extdep
        # Edk2TestUpdate_extdep\NuGet.CommandLine_extdep
        self.assertTrue(os.path.exists(os.path.join(WORKSPACE, "Edk2TestUpdate_extdep",
                                                    "NuGet.CommandLine_extdep", "extdep_state.json")))
