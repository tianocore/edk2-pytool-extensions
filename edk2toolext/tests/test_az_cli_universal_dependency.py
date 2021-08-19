# @file test_az_cli_universal_dependency.py
# Unit test suite for the Azure CLI Artifacts Universal Packages Dependency class.
#
##
# Copyright (c) Microsoft Corporation
#
# SPDX-License-Identifier: BSD-2-Clause-Patent
##
import os
import sys
import unittest
import logging
import shutil
import stat
import tempfile
import pkg_resources
from edk2toollib.utility_functions import RunCmd
from edk2toolext.environment import environment_descriptor_files as EDF
from edk2toolext.environment.extdeptypes.az_cli_universal_dependency import AzureCliUniversalDependency
from edk2toolext.environment import version_aggregator
from edk2toolext.bin import nuget

test_dir = None

single_file_json_template = '''
{
  "scope": "global",
  "type": "az-universal",
  "name": "hello-world-file",
  "source": "https://dev.azure.com/tianocore",
  "project": "edk2-pytool-extensions",
  "version": "%s",
  "feed": "ext_dep_unit_test_feed"
}
'''

folders_json_template = '''
{
  "scope": "global",
  "type": "az-universal",
  "name": "hello-world-folders",
  "source": "https://dev.azure.com/tianocore",
  "project": "edk2-pytool-extensions",
  "version": "%s",
  "feed": "ext_dep_unit_test_feed"
}
'''

file_filter_json_template = '''
{
  "scope": "global",
  "type": "az-universal",
  "name": "hello-world-folders",
  "source": "https://dev.azure.com/tianocore",
  "project": "edk2-pytool-extensions",
  "version": "0.2.1",
  "feed": "ext_dep_unit_test_feed",
  "file-filter": "folder2/*.txt"
}
'''

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

        # spell-checker:ignore dorw
        def dorw(action, name, exc):
            os.chmod(name, stat.S_IWRITE)
            if(os.path.isdir(name)):
                os.rmdir(name)
            else:
                os.remove(name)

        shutil.rmtree(test_dir, onerror=dorw)
        test_dir = None


class TestAzCliUniversalDependency(unittest.TestCase):
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

    def tearDown(self):
        # we need to reset the version aggregator each time
        version_aggregator.GetVersionAggregator().Reset()

    # good case
    def test_download_good_universal_dependency_single_file(self):
        version = "0.0.1"
        ext_dep_file_path = os.path.join(test_dir, "unit_test_ext_dep.json")
        with open(ext_dep_file_path, "w+") as ext_dep_file:
            ext_dep_file.write(single_file_json_template % version)

        ext_dep_descriptor = EDF.ExternDepDescriptor(ext_dep_file_path).descriptor_contents
        ext_dep = AzureCliUniversalDependency(ext_dep_descriptor)
        ext_dep.fetch()
        self.assertTrue(ext_dep.verify())
        self.assertEqual(ext_dep.version, version)
        # make sure we clean up after ourselves
        ext_dep.clean()

    # good case
    def test_download_good_universal_dependency_folders_pinned_old_version(self):
        version = "0.2.0"
        ext_dep_file_path = os.path.join(test_dir, "unit_test_ext_dep.json")
        with open(ext_dep_file_path, "w+") as ext_dep_file:
            ext_dep_file.write(folders_json_template % version)

        ext_dep_descriptor = EDF.ExternDepDescriptor(ext_dep_file_path).descriptor_contents
        ext_dep = AzureCliUniversalDependency(ext_dep_descriptor)
        ext_dep.fetch()
        self.assertTrue(ext_dep.verify())
        self.assertEqual(ext_dep.version, version)
        # make sure we clean up after ourselves
        ext_dep.clean()

    # good case
    def test_download_good_universal_dependency_folders_newer_version(self):
        version = "0.2.1"
        ext_dep_file_path = os.path.join(test_dir, "unit_test_ext_dep.json")
        with open(ext_dep_file_path, "w+") as ext_dep_file:
            ext_dep_file.write(folders_json_template % version)

        ext_dep_descriptor = EDF.ExternDepDescriptor(ext_dep_file_path).descriptor_contents
        ext_dep = AzureCliUniversalDependency(ext_dep_descriptor)
        ext_dep.fetch()
        self.assertTrue(ext_dep.verify())
        self.assertEqual(ext_dep.version, version)
        # make sure we clean up after ourselves
        ext_dep.clean()

    # good case
    def test_download_good_universal_dependency_folders_file_filter(self):
        version = "0.2.1"
        ext_dep_file_path = os.path.join(test_dir, "unit_test_ext_dep.json")
        with open(ext_dep_file_path, "w+") as ext_dep_file:
            ext_dep_file.write(file_filter_json_template)

        ext_dep_descriptor = EDF.ExternDepDescriptor(ext_dep_file_path).descriptor_contents
        ext_dep = AzureCliUniversalDependency(ext_dep_descriptor)
        ext_dep.fetch()
        self.assertTrue(ext_dep.verify())
        self.assertEqual(ext_dep.version, version)

        #make sure we have 1 folder and 2 file (ext_Dep state file plus our 1 file from package)
      
        files=0
        folders=0

        for (dirpath, dirs, file_names) in os.walk(ext_dep.contents_dir):
            files += len(file_names)
            folders += len(dirs)
        
        self.assertEqual(folders, 1)
        self.assertEqual(files, 2)

        # make sure we clean up after ourselves
        ext_dep.clean()

    # bad case
    def test_download_bad_universal_dependency(self):
        non_existing_version = "0.1.0"
        ext_dep_file_path = os.path.join(test_dir, "unit_test_ext_dep.json")
        with open(ext_dep_file_path, "w+") as ext_dep_file:
            ext_dep_file.write(single_file_json_template % non_existing_version)

        ext_dep_descriptor = EDF.ExternDepDescriptor(ext_dep_file_path).descriptor_contents
        ext_dep = AzureCliUniversalDependency(ext_dep_descriptor)
        with self.assertRaises(Exception):
            ext_dep.fetch()
        self.assertFalse(ext_dep.verify())

if __name__ == '__main__':
    unittest.main()
