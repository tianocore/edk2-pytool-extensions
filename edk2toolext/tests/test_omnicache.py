## @file test_omnicache.py
# This contains unit tests for omnicache
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
import shutil
from io import StringIO
from edk2toolext import omnicache
from edk2toollib import utility_functions


test_dir = None
current_dir = None


def prep_workspace():
    global test_dir, current_dir
    # if test temp dir doesn't exist
    if test_dir is None or not os.path.isdir(test_dir):
        test_dir = tempfile.mkdtemp()
        logging.debug("temp dir is: %s" % test_dir)
    else:
        shutil.rmtree(test_dir)
        test_dir = tempfile.mkdtemp()
    current_dir = os.path.abspath(os.getcwd())


def clean_workspace():
    global test_dir, current_dir
    os.chdir(current_dir)
    if test_dir is None:
        return

    if os.path.isdir(test_dir):
        shutil.rmtree(test_dir)
        test_dir = None


class TestOmniCache(unittest.TestCase):
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

    def test_basic_init(self):
        valueabs = os.path.join(os.path.abspath(os.getcwd()), "test", "test2")
        result = omnicache.CommonFilePathHandler(valueabs)
        assert(result == valueabs)

    def test_commonfilepathhandler_real(self):
        valueabs = os.path.join(os.path.abspath(os.getcwd()), "test", "test2")
        result = omnicache.CommonFilePathHandler(os.path.join(valueabs, "..", "test2"))
        assert(result == valueabs)

    def test_commonfilepathhandler_relative(self):
        valueabs = os.path.join(os.path.abspath(os.getcwd()), "test", "test2")
        result = omnicache.CommonFilePathHandler(os.path.join("test", "test2"))
        assert(result == valueabs)

    def test_omnicache_init(self):
        testcache = os.path.join(os.path.abspath(os.getcwd()), test_dir, "testcache")
        testconfigs = [
            {
                "cfgfile": os.path.join(os.path.abspath(os.getcwd()), test_dir, "testcfg.yaml"),
                "name": "openssl",
                "url": "https://github.com/openssl/openssl.git",
                "tag": "true"
            },
            {
                "cfgfile": os.path.join(os.path.abspath(os.getcwd()), test_dir, "testcfg2.yaml"),
                "name": "openssl",
                "url": "https://foobar.com/openssl/openssl.git",
                "tag": "true"
            }
        ]

        for testconfig in testconfigs:
            currentdir = os.path.abspath(os.getcwd())
            with open(testconfig["cfgfile"], "w") as configyaml:
                configyaml.write("remotes:\n")
                configyaml.write("- name: {0}\n".format(testconfig["name"]))
                configyaml.write("  url: {0}\n".format(testconfig["url"]))
                configyaml.write("  tag: {0}\n".format(testconfig["tag"]))

            omnicache_config_file = os.path.join(testcache, omnicache.OMNICACHE_FILENAME)
            if(os.path.isdir(testcache)):
                if(os.path.isfile(omnicache_config_file)):
                    logging.debug("OMNICACHE already exists.  No need to initialize")
            else:
                omnicache.InitOmnicache(testcache)

            omnicache_config = omnicache.OmniCacheConfig(omnicache_config_file)
            os.chdir(testcache)

            (count, input_config_remotes) = omnicache.AddEntriesFromConfig(omnicache_config, testconfig["cfgfile"])

            assert(count == 1)
            assert(input_config_remotes is not None)
            assert(input_config_remotes[0]["name"] == testconfig["name"])
            assert(input_config_remotes[0]["url"] == testconfig["url"])

            omnicache_config.Save()

            # check that cache properly initialized/updated
            out = StringIO()
            param = "remote -v"
            gitret = utility_functions.RunCmd("git", param, outstream=out)
            assert(gitret == 0)

            lines = out.getvalue().split('\n')
            out.close()
            assert (len(lines) > 0)
            for line in lines:
                line = line.strip()
                if(len(line) == 0):
                    # empty line
                    continue
                git = line.split()
                assert(git[0] == input_config_remotes[0]["name"])
                assert(git[1] == input_config_remotes[0]["url"])

            os.chdir(currentdir)


if __name__ == '__main__':
    unittest.main()
