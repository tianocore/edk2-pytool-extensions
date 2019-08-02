## @file test_self_describing_environment.py
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
from edk2toolext.invocables.edk2_update import build_env_changed
from edk2toolext.environment import repo_resolver
from edk2toolext.environment import self_describing_environment

mu_basecore_dependency = {
    "Url": "https://github.com/microsoft/mu_basecore",
    "Path": None,
    "Branch": "master"
}

test_dir = None


def prep_workspace():
    global test_dir
    # if test temp dir doesn't exist
    if test_dir is None or not os.path.isdir(test_dir):
        test_dir = tempfile.mkdtemp()
        logging.debug("temp dir is: %s" % test_dir)
    else:
        clean_workspace()
        test_dir = tempfile.mkdtemp()


def clean_workspace():
    global test_dir
    if test_dir is None:
        return

    if os.path.isdir(test_dir):

        def dorw(action, name, exc):
            os.chmod(name, stat.S_IWRITE)
            if(os.path.isdir(name)):
                os.rmdir(name)
            else:
                os.remove(name)

        shutil.rmtree(test_dir, onerror=dorw)
        test_dir = None


def do_update(directory, scopes):
    (build_env, shell_env) = self_describing_environment.BootstrapEnvironment(
        directory, scopes)
    self_describing_environment.UpdateDependencies(directory, scopes)
    return (build_env, shell_env)


class Testself_describing_environment(unittest.TestCase):
    def setUp(self):
        prep_workspace()

    @classmethod
    def setUpClass(cls):
        logger = logging.getLogger('')
        logger.addHandler(logging.NullHandler())
        unittest.installHandler()

    @classmethod
    def tearDownClass(cls):
        clean_workspace()

    # Test the assertion that two identical code trees should generate
    # the same self_describing_environment.
    def test_identical_environments(self):
        scopes = ("corebuild", "project_mu")

        mu_basecore_dependency_1 = mu_basecore_dependency.copy()
        mu_basecore_dependency_2 = mu_basecore_dependency.copy()

        basecore_1_dir = "basecore_1"
        basecore_2_dir = "basecore_2"

        mu_basecore_dependency_1["Path"] = basecore_1_dir
        mu_basecore_dependency_2["Path"] = basecore_2_dir

        repo_resolver.resolve(test_dir, mu_basecore_dependency_1)
        repo_resolver.resolve(test_dir, mu_basecore_dependency_2)

        (build_env_1, shell_env_1) = do_update(os.path.normpath(basecore_1_dir), scopes)
        (build_env_2, shell_env_2) = do_update(os.path.normpath(basecore_2_dir), scopes)

        self.assertFalse(build_env_changed(build_env_1, build_env_2))


if __name__ == '__main__':
    unittest.main()
