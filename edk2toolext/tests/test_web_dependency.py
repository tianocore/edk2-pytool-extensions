# @file test_web_dependency.py
# Unit test suite for the WebDependency class.
#
##
# Copyright (c) Microsoft Corporation
#
# SPDX-License-Identifier: BSD-2-Clause-Patent
##

import os
import unittest
import logging
import shutil
import tarfile
import zipfile
import tempfile
import json
import urllib.request
from edk2toolext.environment import environment_descriptor_files as EDF
from edk2toolext.environment.extdeptypes.web_dependency import WebDependency

test_dir = None
bad_json_file = '''
{
  "scope": "global",
  "type": "web",
  "name": "mu-pip",
  "source": "https://github.com/microsoft/mu_pip_environment/archive/0.tar.gz",
  "version": "7.2.1",
  "flags": ["set_path"],
  "internal_path": "/mu_pip_environment-0.3.7",
  "compression_type":"tar",
  "sha256":"68f2335344c3f7689f8d69125d182404a3515b8daa53a9c330f115739889f998"
}
'''
# JSON file that describes a single file to download from the internet
# bing.com was choosen as it's probably not going anywhere soon and it's small file to download
single_file_extdep = {
    "scope": "global",
    "type": "web",
    "name": "test",
    "source": "https://www.bing.com/",
    "version": "20190805",
    "flags": [],
    "internal_path": "test.txt"
}
# Use the github release
zip_directory_extdep = {
    "scope": "global",
    "type": "web",
    "name": "win-flexbison",
    "compression_type": "zip",
    "source": "https://github.com/lexxmark/winflexbison/releases/download/v2.4.7/win_flex_bison-2.4.7.zip",
    "version": "2.4.7",
    "sha256": "7553a2d6738c799e101ec38a6ad073885ead892826f87bc1a24e78bcd7ac2a8c",
    "internal_path": "/."
}
# Use the GNU FTP
tar_directory_extdep = {
    "scope": "global",
    "type": "web",
    "name": "unix-bison",
    "compression_type": "tar",
    "source": "https://ftp.gnu.org/gnu/bison/bison-3.7.tar.gz",
    "version": "3.7",
    "sha256": "492ad61202de893ca21a99b621d63fa5389da58804ad79d3f226b8d04b803998",
    "internal_path": "/bison-3.7",
}
# Download a valid file from CDN
jquery_json_file = {
    "scope": "global",
    "type": "web",
    "name": "jquery",
    "source": "https://code.jquery.com/jquery-3.4.1.js",
    "version": "3.4.1",
    "flags": [],
    "sha256": "5A93A88493AA32AAB228BF4571C01207D3B42B0002409A454D404B4D8395BD55",
    "internal_path": "jquery.js"
}


def prep_workspace():
    global test_dir
    # if test temp dir doesn't exist
    if test_dir is None or not os.path.isdir(test_dir):
        test_dir = tempfile.mkdtemp()
        logging.debug("temp dir is: %s" % test_dir)
    else:
        shutil.rmtree(test_dir)
        test_dir = tempfile.mkdtemp()


def clean_workspace():
    global test_dir
    if test_dir is None:
        return

    if os.path.isdir(test_dir):
        shutil.rmtree(test_dir)
        test_dir = None


class TestWebDependency(unittest.TestCase):
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

    # throw in a bad url and test that it throws an exception.
    def test_fail_with_bad_url(self):
        ext_dep_file_path = os.path.join(test_dir, "bad_ext_dep.json")
        with open(ext_dep_file_path, "w+") as ext_dep_file:
            ext_dep_file.write(bad_json_file)

        ext_dep_descriptor = EDF.ExternDepDescriptor(ext_dep_file_path).descriptor_contents
        ext_dep = WebDependency(ext_dep_descriptor)
        with self.assertRaises(urllib.error.HTTPError):
            ext_dep.fetch()
            self.fail("should have thrown an Exception")

    # try to download a single file from the internet
    def test_single_file(self):
        ext_dep_file_path = os.path.join(test_dir, "good_ext_dep.json")
        with open(ext_dep_file_path, "w+") as ext_dep_file:
            ext_dep_file.write(json.dumps(single_file_extdep))  # dump to a file

        ext_dep_descriptor = EDF.ExternDepDescriptor(ext_dep_file_path).descriptor_contents
        ext_dep = WebDependency(ext_dep_descriptor)
        ext_dep.fetch()

        ext_dep_name = single_file_extdep['name'] + "_extdep"
        file_path = os.path.join(test_dir, ext_dep_name, single_file_extdep['internal_path'])
        if not os.path.isfile(file_path):
            self.fail("The downloaded file isn't there")

    # try to download a whole zip directory and test sha256 comparison
    def test_sha256_whole_zip_directory(self):
        ext_dep_file_path = os.path.join(test_dir, "good_ext_dep.json")

        with open(ext_dep_file_path, "w+") as ext_dep_file:
            ext_dep_file.write(json.dumps(zip_directory_extdep))  # dump to a file

        ext_dep_descriptor = EDF.ExternDepDescriptor(ext_dep_file_path).descriptor_contents
        ext_dep = WebDependency(ext_dep_descriptor)
        ext_dep.fetch()

        ext_dep_name = zip_directory_extdep['name'] + "_extdep"
        folder_path = os.path.join(test_dir, ext_dep_name)
        if not os.path.exists(os.path.join(folder_path, "README.txt")):
            logging.warning(folder_path)
            self.fail()

    # try to download a whole zip directory and test sha256 comparison
    def test_sha256_whole_tar_directory(self):
        ext_dep_file_path = os.path.join(test_dir, "good_ext_dep.json")

        with open(ext_dep_file_path, "w+") as ext_dep_file:
            ext_dep_file.write(json.dumps(tar_directory_extdep))  # dump to a file

        ext_dep_descriptor = EDF.ExternDepDescriptor(ext_dep_file_path).descriptor_contents
        ext_dep = WebDependency(ext_dep_descriptor)
        ext_dep.fetch()

        ext_dep_name = tar_directory_extdep['name'] + "_extdep"
        folder_path = os.path.join(test_dir, ext_dep_name)
        if not os.path.exists(os.path.join(folder_path, "README")):
            logging.warning(folder_path)
            self.fail()

    # try to download a single file and test sha256 comparison
    def test_sha256_uppercase_single_file(self):
        ext_dep_file_path = os.path.join(test_dir, "good_ext_dep.json")
        # force hash to upper case
        jquery_json = jquery_json_file.copy()
        jquery_json["sha256"] = jquery_json["sha256"].upper()

        with open(ext_dep_file_path, "w+") as ext_dep_file:
            ext_dep_file.write(json.dumps(jquery_json))  # dump to a file

        ext_dep_descriptor = EDF.ExternDepDescriptor(ext_dep_file_path).descriptor_contents
        ext_dep = WebDependency(ext_dep_descriptor)
        ext_dep.fetch()

        ext_dep_name = jquery_json['name'] + "_extdep"
        file_path = os.path.join(test_dir, ext_dep_name, jquery_json['internal_path'])
        if not os.path.isfile(file_path):
            self.fail("The downloaded file isn't there")

    # try to download a single file and test sha256 comparison
    def test_sha256_lowercase_single_file(self):
        ext_dep_file_path = os.path.join(test_dir, "good_ext_dep.json")
        jquery_json = jquery_json_file.copy()
        jquery_json["sha256"] = jquery_json["sha256"].lower()
        with open(ext_dep_file_path, "w+") as ext_dep_file:
            ext_dep_file.write(json.dumps(jquery_json))  # dump to a file

        ext_dep_descriptor = EDF.ExternDepDescriptor(ext_dep_file_path).descriptor_contents
        ext_dep = WebDependency(ext_dep_descriptor)
        ext_dep.fetch()

        ext_dep_name = jquery_json['name'] + "_extdep"
        file_path = os.path.join(test_dir, ext_dep_name, jquery_json['internal_path'])
        if not os.path.isfile(file_path):
            self.fail("The downloaded file isn't there")

    # Test that get_internal_path_root works the way we expect with a flat directory structure.
    # test_dir\inner_dir - test_dir\inner_dir should be the root.
    def test_get_internal_path_root_flat(self):
        outer_dir = test_dir
        inner_dir_name = "inner_dir"
        inner_dir_path = os.path.join(outer_dir, inner_dir_name)
        self.assertEqual(WebDependency.get_internal_path_root(outer_dir, inner_dir_name), inner_dir_path)

    # Test that get_internal_path_root works the way we expect with a flat directory structure
    # test_dir\first_dir\second_dir - test_dir\first_dir should be the root
    def test_get_internal_path_root_with_subfolders(self):
        outer_dir = test_dir
        first_level_dir_name = "first_dir"
        second_level_dir_name = "second_dir"
        inner_dir_path = os.path.join(outer_dir, first_level_dir_name)
        inner_second_dir_path = os.path.join(first_level_dir_name, second_level_dir_name)
        self.assertEqual(WebDependency.get_internal_path_root(outer_dir, inner_second_dir_path), inner_dir_path)

    # Test that a single file zipped is able to be processed by unpack.
    def test_unpack_zip_file(self):
        compressed_file_path = os.path.join(test_dir, "bad_ext_dep_zip.zip")
        destination = test_dir
        internal_path = "bad_ext_dep.json"
        compression_type = "zip"

        file_path = os.path.join(test_dir, internal_path)

        with open(file_path, "w+") as ext_dep_file:
            ext_dep_file.write(bad_json_file)

        with zipfile.ZipFile(compressed_file_path, 'w') as _zip:
            _zip.write(file_path, arcname=os.path.basename(file_path))

        os.remove(file_path)
        self.assertFalse(os.path.isfile(file_path))

        WebDependency.unpack(compressed_file_path, destination, internal_path, compression_type)
        self.assertTrue(os.path.isfile(file_path))

    # Test that a single file tar volume is able to be processed by unpack.
    def test_unpack_tar_file(self):
        compressed_file_path = os.path.join(test_dir, "bad_ext_dep_zip.tar.gz")
        destination = test_dir
        internal_path = "bad_ext_dep.json"
        compression_type = "tar"

        file_path = os.path.join(test_dir, internal_path)

        with open(file_path, "w+") as ext_dep_file:
            ext_dep_file.write(bad_json_file)

        with tarfile.open(compressed_file_path, "w:gz") as _tar:
            _tar.add(file_path, arcname=os.path.basename(file_path))

        os.remove(file_path)
        self.assertFalse(os.path.isfile(file_path))

        WebDependency.unpack(compressed_file_path, destination, internal_path, compression_type)
        self.assertTrue(os.path.isfile(file_path))

    # Test that a zipped directory is processed correctly by unpack.
    # If internal_path is first_dir\second_dir...
    # Files in test_dir\first_dir\second_dir should be located.
    # Files in test_dir\first_dir should not be unpacked.
    def test_unpack_zip_directory(self):

        first_level_dir_name = "first_dir"
        second_level_dir_name = "second_dir"
        first_level_path = os.path.join(test_dir, first_level_dir_name)
        second_level_path = os.path.join(first_level_path, second_level_dir_name)
        os.makedirs(second_level_path)

        compressed_file_path = os.path.join(test_dir, "bad_ext_dep_zip.zip")
        destination = test_dir
        internal_path = os.path.join(first_level_dir_name, second_level_dir_name)
        compression_type = "zip"

        # only files inside internal_path should be there after unpack
        # (file path, is this file expected to be unpacked?)
        test_files = [(os.path.join(test_dir, internal_path, "bad_json_file.json"), True),
                      (os.path.join(test_dir, first_level_dir_name, "json_file.json"), False)]

        for test_file in test_files:
            with open(test_file[0], "w+") as ext_dep_file:
                ext_dep_file.write(bad_json_file)

        with zipfile.ZipFile(compressed_file_path, 'w') as _zip:
            for test_file in test_files:
                _zip.write(test_file[0], arcname=test_file[0].split(test_dir)[1])

        shutil.rmtree(first_level_path)
        self.assertFalse(os.path.isdir(first_level_path))

        WebDependency.unpack(compressed_file_path, destination, internal_path, compression_type)

        for test_file in test_files:
            if test_file[1]:
                self.assertTrue(os.path.isfile(test_file[0]))
            else:
                self.assertFalse(os.path.isfile(test_file[0]))

    # Test that a tar directory is processed correctly by unpack.
    # If internal_path is first_dir\second_dir...
    # Files in test_dir\first_dir\second_dir should be located.
    # Files in test_dir\first_dir should not be unpacked.
    def test_unpack_tar_directory(self):
        first_level_dir_name = "first_dir"
        second_level_dir_name = "second_dir"
        first_level_path = os.path.join(test_dir, first_level_dir_name)
        second_level_path = os.path.join(first_level_path, second_level_dir_name)
        os.makedirs(second_level_path)

        compressed_file_path = os.path.join(test_dir, "bad_ext_dep_zip.zip")
        destination = test_dir
        internal_path = os.path.join(first_level_dir_name, second_level_dir_name)
        compression_type = "tar"

        # only files inside internal_path should be there after unpack
        # (file path, is this file expected to be unpacked?)
        test_files = [(os.path.join(test_dir, internal_path, "bad_json_file.json"), True),
                      (os.path.join(test_dir, first_level_dir_name, "json_file.json"), False)]

        for test_file in test_files:
            with open(test_file[0], "w+") as ext_dep_file:
                ext_dep_file.write(bad_json_file)

        with tarfile.open(compressed_file_path, "w:gz") as _tar:
            for test_file in test_files:
                _tar.add(test_file[0], arcname=test_file[0].split(test_dir)[1])

        shutil.rmtree(first_level_path)
        self.assertFalse(os.path.isdir(first_level_path))

        WebDependency.unpack(compressed_file_path, destination, internal_path, compression_type)

        for test_file in test_files:
            if test_file[1]:
                self.assertTrue(os.path.isfile(test_file[0]))
            else:
                self.assertFalse(os.path.isfile(test_file[0]))

    # Test that three levels of internal path all work properly
    def test_multi_level_directory(self):
        global test_dir
        number_of_layers = 5
        directory_name = "test"
        file_name = "file"
        compression_type = "tar"
        internal_paths = [""]

        # Set up internal_paths list....
        # It will look like:
        # ["test", "test/testtest", "test/testtest/testtesttest"]
        # To describe the file structure:
        # test_dir/
        #   > test/
        #       >> testtest/
        #           >>> testtesttest/
        #            >>>> testtesttesttest/
        for i in range(1, number_of_layers):
            internal_path = (directory_name * i)
            if i - 1 > 0:
                internal_path = os.path.join(internal_paths[i - 1], internal_path)
            internal_paths.insert(i, internal_path)

        # We will pick internal_path each iteration and make sure
        # only the files INSIDE the internal_path were unpacked.
        # If the second level directory is the internal_path, the first level
        # file SHOULD NOT be unpacked because it is out of scope.
        for internal_path_level in range(1, number_of_layers):
            destination = test_dir
            compressed_file_path = os.path.join(test_dir, "bad_ext_dep_zip.tar")
            os.makedirs(os.path.join(test_dir, internal_paths[-1]))

            # create files in each folder
            files = [""]
            for file_list_counter in range(1, number_of_layers):
                files.insert(file_list_counter,
                             os.path.join(test_dir, internal_paths[file_list_counter], file_name * file_list_counter))
                with open(files[file_list_counter], "w+") as ext_dep_file:
                    ext_dep_file.write(bad_json_file)

            # zip up the whole thing
            with tarfile.open(compressed_file_path, "w:gz") as _tar:
                for file in files[1:]:
                    _tar.add(file, arcname=file.split(test_dir)[1])

            shutil.rmtree(os.path.join(test_dir, directory_name))
            self.assertFalse(os.path.isdir(os.path.join(test_dir, directory_name)))

            # The internal path moves down the directory structure each iteration
            internal_path = internal_paths[internal_path_level]

            WebDependency.unpack(compressed_file_path, destination, internal_path, compression_type)

            # the file should be unpacked if file_list_counter >= internal_path_level
            for file_list_counter in range(1, number_of_layers):
                if internal_path_level <= file_list_counter:
                    self.assertTrue(os.path.isfile(files[file_list_counter]))
                else:
                    self.assertFalse(os.path.isfile(files[file_list_counter]))

            clean_workspace()
            prep_workspace()

    # Test that zipfile uses / internally and not os.sep.
    # This is not exactly a test of WebDependency, more an assertion of an assumption
    # the code is making concerning the functionality of zipfile.
    def test_zip_uses_linux_path_sep(self):
        first_level_dir_name = "first_dir"
        second_level_dir_name = "second_dir"
        first_level_path = os.path.join(test_dir, first_level_dir_name)
        second_level_path = os.path.join(first_level_path, second_level_dir_name)
        os.makedirs(second_level_path)

        compressed_file_path = os.path.join(test_dir, "bad_ext_dep_zip.zip")
        internal_path = os.path.join(first_level_dir_name, second_level_dir_name)
        internal_path_win = "\\".join((first_level_dir_name, second_level_dir_name))

        test_file = os.path.join(test_dir, internal_path, "bad_json_file.json")

        with open(test_file, "w+") as ext_dep_file:
            ext_dep_file.write(bad_json_file)

        with zipfile.ZipFile(compressed_file_path, 'w') as _zip:
            _zip.write(test_file, arcname=test_file.split(test_dir)[1])

        with zipfile.ZipFile(compressed_file_path, 'r') as _zip:
            namelist = _zip.namelist()

        self.assertTrue(len(namelist) == 1)
        self.assertFalse(internal_path_win in namelist[0])
        self.assertTrue(WebDependency.linuxize_path(internal_path_win) in namelist[0])

    # Test that tarfile uses / internally and not os.sep.
    # This is not exactly a test of WebDependency, more an assertion of an assumption
    # the code is making concerning the functionality of tarfile.
    def test_tar_uses_linux_path_sep(self):
        first_level_dir_name = "first_dir"
        second_level_dir_name = "second_dir"
        first_level_path = os.path.join(test_dir, first_level_dir_name)
        second_level_path = os.path.join(first_level_path, second_level_dir_name)
        os.makedirs(second_level_path)

        compressed_file_path = os.path.join(test_dir, "bad_ext_dep_zip.zip")
        internal_path = os.path.join(first_level_dir_name, second_level_dir_name)
        internal_path_win = "\\".join((first_level_dir_name, second_level_dir_name))

        test_file = os.path.join(test_dir, internal_path, "bad_json_file.json")

        with open(test_file, "w+") as ext_dep_file:
            ext_dep_file.write(bad_json_file)

        with tarfile.open(compressed_file_path, "w:gz") as _tar:
            _tar.add(test_file, arcname=test_file.split(test_dir)[1])

        with tarfile.open(compressed_file_path, "r:*") as _tar:
            namelist = _tar.getnames()

        self.assertTrue(len(namelist) == 1)
        self.assertFalse(internal_path_win in namelist[0])
        self.assertTrue(WebDependency.linuxize_path(internal_path_win) in namelist[0])


if __name__ == '__main__':
    unittest.main()
