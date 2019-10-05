# @file test_git_dependency.py
# Unit test suite for the GitDependency class.
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
from edk2toollib.utility_functions import RunCmd
from edk2toolext.environment import environment_descriptor_files as EDF
from edk2toolext.environment.extdeptypes.nuget_dependency import NugetDependency
from edk2toolext.environment import version_aggregator

test_dir = None
good_version = "5.2.0"
bad_version = "5.2.13.1.2"
missing_version = "5.200.13"

hw_json_template = '''
{
  "scope": "global",
  "type": "nuget",
  "name": "NuGet.CommandLine",
  "source": "https://api.nuget.org/v3/index.json",
  "version": "%s"
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

        def dorw(action, name, exc):
            os.chmod(name, stat.S_IWRITE)
            if(os.path.isdir(name)):
                os.rmdir(name)
            else:
                os.remove(name)

        shutil.rmtree(test_dir, onerror=dorw)
        test_dir = None


class TestNugetDependency(unittest.TestCase):
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

    def test_can_get_nuget_path(self):
        nuget_cmd = NugetDependency.GetNugetCmd()
        nuget_cmd += ["locals", "global-packages", "-list"]
        ret = RunCmd(nuget_cmd[0], ' '.join(nuget_cmd[1:]), outstream=sys.stdout)
        self.assertEqual(ret, 0)  # make sure we have a zero return code

    # good case
    def test_download_good_nuget(self):
        ext_dep_file_path = os.path.join(test_dir, "hw_ext_dep.json")
        with open(ext_dep_file_path, "w+") as ext_dep_file:
            ext_dep_file.write(hw_json_template % good_version)

        ext_dep_descriptor = EDF.ExternDepDescriptor(ext_dep_file_path).descriptor_contents
        ext_dep = NugetDependency(ext_dep_descriptor)
        ext_dep.fetch()
        self.assertTrue(ext_dep.verify())
        self.assertEqual(ext_dep.version, good_version)
        # make sure we clean up after ourselves
        ext_dep.clean()

    # bad case
    def test_download_bad_nuget(self):
        ext_dep_file_path = os.path.join(test_dir, "hw_ext_dep.json")
        with open(ext_dep_file_path, "w+") as ext_dep_file:
            ext_dep_file.write(hw_json_template % bad_version)

        ext_dep_descriptor = EDF.ExternDepDescriptor(ext_dep_file_path).descriptor_contents
        ext_dep = NugetDependency(ext_dep_descriptor)
        with self.assertRaises(RuntimeError):
            # we should throw an exception because we don't know how to parse the version
            ext_dep.fetch()
        self.assertFalse(ext_dep.verify())

    def test_normalize_version(self):
        version1 = "5.10.05.0"
        proper_version1 = "5.10.5"
        self.assertEqual(proper_version1, NugetDependency.normalize_version(version1))
        version2 = "6.10"
        proper_version2 = "6.10.0"
        self.assertEqual(proper_version2, NugetDependency.normalize_version(version2))
        version3 = "6"
        proper_version3 = "6.0.0"
        self.assertEqual(proper_version3, NugetDependency.normalize_version(version3))
        # try some bad cases
        version4 = "not a number"
        with self.assertRaises(ValueError):
            NugetDependency.normalize_version(version4)
        with self.assertRaises(ValueError):
            NugetDependency.normalize_version("")
        with self.assertRaises(ValueError):
            NugetDependency.normalize_version(bad_version)

    # missing case
    def test_download_missing_nuget(self):
        ext_dep_file_path = os.path.join(test_dir, "hw_ext_dep.json")
        with open(ext_dep_file_path, "w+") as ext_dep_file:
            ext_dep_file.write(hw_json_template % missing_version)

        ext_dep_descriptor = EDF.ExternDepDescriptor(ext_dep_file_path).descriptor_contents
        ext_dep = NugetDependency(ext_dep_descriptor)
        with self.assertRaises(RuntimeError):
            ext_dep.fetch()
        self.assertFalse(ext_dep.verify())
        self.assertEqual(ext_dep.version, missing_version)


if __name__ == '__main__':
    unittest.main()
