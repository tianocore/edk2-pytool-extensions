# @file test_git_dependency.py
# Unit test suite for the GitDependency class.
#
##
# Copyright (c) Microsoft Corporation
#
# SPDX-License-Identifier: BSD-2-Clause-Patent
##
import os
import unittest
import logging
import tempfile
import copy
from edk2toollib.utility_functions import RemoveTree
from edk2toolext.environment.external_dependency import ExternalDependency as ExtDep

TEST_DIR = None
GOOD_VERSION = "5.2.0"
BAD_VERSION = "5.2.13.1.2"
MISSING_VERSION = "5.200.13"

NUGET_TEMPLATE = {
    "scope": "global",
    "type": "nuget",
    "name": "NuGet.CommandLine",
    "source": "https://api.nuget.org/v3/index.json",
}

WEB_TEMPLATE = {
    "scope": "global",
    "type": "web",
    "name": "NuGet.CommandLine",
    "source": "https://example.com/some_other_site",
}


def prep_workspace():
    global TEST_DIR
    # if test temp dir doesn't exist
    if TEST_DIR is None or not os.path.isdir(TEST_DIR):
        TEST_DIR = tempfile.mkdtemp()
        logging.debug("temp dir is: %s" % TEST_DIR)
    else:
        clean_workspace()
        TEST_DIR = tempfile.mkdtemp()


def clean_workspace():
    global TEST_DIR
    if TEST_DIR is None:
        return

    if os.path.isdir(TEST_DIR):
        RemoveTree(TEST_DIR)
        TEST_DIR = None


class TestExternalDependency(unittest.TestCase):
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

    def test_determine_cache_path(self):
        nuget_desc = copy.copy(NUGET_TEMPLATE)
        nuget_desc['version'] = GOOD_VERSION
        nuget_desc['descriptor_file'] = os.path.join(TEST_DIR, 'non_file.yaml')
        ext_dep = ExtDep(nuget_desc)

        cache_path = os.path.join(TEST_DIR, 'stuart_cache')

        self.assertIsNone(ext_dep.determine_cache_path())

        ext_dep.set_global_cache_path(cache_path)
        self.assertIsNone(ext_dep.determine_cache_path())

        os.makedirs(cache_path)
        self.assertTrue(ext_dep.determine_cache_path().startswith(os.path.join(cache_path, 'nuget')))

        web_desc = copy.copy(WEB_TEMPLATE)
        web_desc['version'] = GOOD_VERSION
        web_desc['descriptor_file'] = os.path.join(TEST_DIR, 'non_file.yaml')
        ext_dep = ExtDep(web_desc)
        ext_dep.set_global_cache_path(cache_path)
        self.assertTrue(ext_dep.determine_cache_path().startswith(os.path.join(cache_path, 'web')))

    def test_different_versions_have_different_caches(self):
        cache_path = os.path.join(TEST_DIR, 'stuart_cache')
        os.makedirs(cache_path)

        nuget_desc1 = copy.copy(NUGET_TEMPLATE)
        nuget_desc1['version'] = GOOD_VERSION
        nuget_desc1['descriptor_file'] = os.path.join(TEST_DIR, 'non_file.yaml')
        ext_dep1 = ExtDep(nuget_desc1)

        nuget_desc2 = copy.copy(NUGET_TEMPLATE)
        nuget_desc2['version'] = "7.0.0"
        nuget_desc2['descriptor_file'] = os.path.join(TEST_DIR, 'non_file.yaml')
        ext_dep2 = ExtDep(nuget_desc2)

        ext_dep1.set_global_cache_path(cache_path)
        ext_dep2.set_global_cache_path(cache_path)

        self.assertNotEqual(ext_dep1.determine_cache_path(), ext_dep2.determine_cache_path())

    def test_different_sources_have_different_caches(self):
        cache_path = os.path.join(TEST_DIR, 'stuart_cache')
        os.makedirs(cache_path)

        nuget_desc1 = copy.copy(NUGET_TEMPLATE)
        nuget_desc1['version'] = GOOD_VERSION
        nuget_desc1['descriptor_file'] = os.path.join(TEST_DIR, 'non_file.yaml')
        ext_dep1 = ExtDep(nuget_desc1)

        nuget_desc2 = copy.copy(NUGET_TEMPLATE)
        nuget_desc2['version'] = GOOD_VERSION
        nuget_desc2['descriptor_file'] = os.path.join(TEST_DIR, 'non_file.yaml')
        nuget_desc2['source'] = "https://api.nuget.org/v3/different_index.json"
        ext_dep2 = ExtDep(nuget_desc2)

        ext_dep1.set_global_cache_path(cache_path)
        ext_dep2.set_global_cache_path(cache_path)

        self.assertNotEqual(ext_dep1.determine_cache_path(), ext_dep2.determine_cache_path())


if __name__ == '__main__':
    unittest.main()
