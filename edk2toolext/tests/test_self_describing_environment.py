# @file test_self_describing_environment.py
# This contains unit tests for the SDE
#
##
# Copyright (c) Microsoft Corporation
#
# SPDX-License-Identifier: BSD-2-Clause-Patent
##
import os
import stat
import shutil
import logging
import unittest
import tempfile
from edk2toolext.environment import self_describing_environment


def do_update(directory, scopes):
    (build_env, shell_env) = self_describing_environment.BootstrapEnvironment(
        directory, scopes)
    self_describing_environment.UpdateDependencies(directory, scopes)
    return (build_env, shell_env)


class Testself_describing_environment(unittest.TestCase):
    def setUp(self):
        self.workspace = os.path.abspath(tempfile.mkdtemp())

    @classmethod
    def setUpClass(cls):
        logger = logging.getLogger('')
        logger.addHandler(logging.NullHandler())
        unittest.installHandler()

    def test_null_init(self):
        sde = self_describing_environment.self_describing_environment(self.workspace)
        self.assertIsNotNone(sde)

    def test_unique_scopes_required(self):
        scopes = ("corebuild", "corebuild", "testing", "CoreBuild")
        with self.assertRaises(ValueError):
            sde = self_describing_environment.self_describing_environment(self.workspace, scopes)

    # Test the assertion that two identical code trees should generate
    # the same self_describing_environment.
    def test_identical_environments(self):
        scopes = ("corebuild", "project_mu")


if __name__ == '__main__':
    unittest.main()
