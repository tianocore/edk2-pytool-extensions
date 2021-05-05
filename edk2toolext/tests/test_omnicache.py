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
import yaml
import sys
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
        for _ in range(3):
            try:
                shutil.rmtree(test_dir)
            except OSError as err:
                logging.warning(f"Failed to fully remove {test_dir}: {err}")
            else:
                break
        test_dir = tempfile.mkdtemp()
    current_dir = os.path.abspath(os.getcwd())


def clean_workspace():
    global test_dir, current_dir
    os.chdir(current_dir)
    if test_dir is None:
        return

    if os.path.isdir(test_dir):
        for _ in range(3):
            try:
                shutil.rmtree(test_dir)
            except OSError as err:
                logging.warning(f"Failed to fully remove {test_dir}: {err}")
            else:
                break
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

    def test_omnicache_new(self):
        testcache = os.path.join(os.path.abspath(os.getcwd()), test_dir, "testcache")

        # create a new cache
        oc = omnicache.Omnicache(testcache, create=True, convert=False)

        # check that the new cache was created as a bare repo
        out = StringIO()
        gitret = utility_functions.RunCmd("git", "rev-parse --is-bare-repository", workingdir=testcache, outstream=out)
        assert(gitret == 0)
        assert(out.getvalue().strip().lower() == "true")

        # check that it has the right metadata
        out = StringIO()
        gitret = utility_functions.RunCmd("git",
                                          "config --local omnicache.metadata.version",
                                          workingdir=testcache,
                                          outstream=out)
        assert(gitret == 0)
        assert(out.getvalue().strip().lower() == omnicache.OMNICACHE_VERSION)

        # check that omnicache thinks it's valid
        (valid, _) = oc._ValidateOmnicache()
        assert(valid)

        # remove the metadata to simulate an older omnicache that is candidate for conversion
        gitret = utility_functions.RunCmd("git",
                                          "config --local --unset omnicache.metadata.version",
                                          workingdir=testcache)
        assert(gitret == 0)

        # check that omnicache thinks it's not valid but convertible.
        (valid, convertible) = oc._ValidateOmnicache()
        assert(not valid)
        assert(convertible)

        # attempt to create a new cache - test repo is valid git repo, but doesn't have the meta.
        with self.assertRaises(RuntimeError):
            oc = omnicache.Omnicache(testcache, create=False, convert=False)

        # set the metadata version to an unexpected value
        gitret = utility_functions.RunCmd(
            "git",
            "config --local omnicache.metadata.version {0}".format(omnicache.OMNICACHE_VERSION+"x"),
            workingdir=testcache)
        assert(gitret == 0)

        # check that omnicache thinks it's not valid but convertible.
        (valid, convertible) = oc._ValidateOmnicache()
        assert(not valid)
        assert(convertible)

        # attempt to create a new cache - test repo is valid git repo, but doesn't have the expected meta.
        with self.assertRaises(RuntimeError):
            oc = omnicache.Omnicache(testcache, create=False, convert=False)

        # now make it a non-bare (but technically valid) git repo
        gitret = utility_functions.RunCmd("git", "config --local core.bare false", workingdir=testcache)
        assert(gitret == 0)

        # check that omnicache thinks it's not valid and not convertible.
        (valid, convertible) = oc._ValidateOmnicache()
        assert(not valid)
        assert(not convertible)

        # attempt to create a new cache - test repo is valid non-bare git repo
        with self.assertRaises(RuntimeError):
            oc = omnicache.Omnicache(testcache, create=False, convert=False)

        # make it it a non-valid git repo
        os.remove(os.path.join(testcache, "HEAD"))

        # check that omnicache thinks it's not valid and not convertible.
        (valid, convertible) = oc._ValidateOmnicache()
        assert(not valid)
        assert(not convertible)

        # attempt to create a new cache - test repo is not valid git repo
        with self.assertRaises(RuntimeError):
            oc = omnicache.Omnicache(testcache, create=False, convert=False)

    def test_omnicache_convert(self):
        testcache = os.path.join(os.path.abspath(os.getcwd()), test_dir, "testcache")

        # create a new cache
        oc = omnicache.Omnicache(testcache, create=True, convert=False)

        (valid, _) = oc._ValidateOmnicache()
        assert(valid)

        # remove the metadata to simulate an older omnicache that is candidate for conversion
        gitret = utility_functions.RunCmd("git",
                                          "config --local --unset omnicache.metadata.version",
                                          workingdir=testcache)
        assert(gitret == 0)

        # add an empty file to simulate the old config yaml
        with open(os.path.join(testcache, omnicache.OMNICACHE_FILENAME), "w") as yf:
            yf.write("Not A Real YAML File")

        # confirm that _ValidateOmnicache correctly identifies cache state
        (valid, convertible) = oc._ValidateOmnicache()
        assert(not valid)
        assert(convertible)

        # add a traditionally-named remote to the cache to simulate an older omnicache
        gitret = utility_functions.RunCmd(
            "git",
            "remote add pytools-ext https://github.com/tianocore/edk2-pytool-extensions.git",
            workingdir=testcache)
        assert(gitret == 0)

        # add a second copy of the remote remote with a different name to the cache to simulate a duplicate
        gitret = utility_functions.RunCmd(
            "git",
            "remote add pytools-ext2 https://github.com/tianocore/edk2-pytool-extensions.git",
            workingdir=testcache)
        assert(gitret == 0)

        # fetch the remote and its tags to populate the cache for conversion.
        gitret = utility_functions.RunCmd("git", "fetch pytools-ext --tags", workingdir=testcache)
        assert(gitret == 0)

        # confirm that _ValidateOmnicache still correctly identifies cache state
        (valid, convertible) = oc._ValidateOmnicache()
        assert(not valid)
        assert(convertible)

        # re-create the omnicache object to trigger conversion
        oc = omnicache.Omnicache(testcache, create=False, convert=True)

        # validate converted cache
        (valid, _) = oc._ValidateOmnicache()
        assert(valid)

        # verify that old config file was deleted.
        assert(not os.path.exists(os.path.join(testcache, omnicache.OMNICACHE_FILENAME)))

        # verify that the traditionally-named remote is no longer in the cache (it should have been renamed with a UUID)
        remotes = omnicache.Omnicache.GetRemotes(testcache)
        assert("pytools-ext" not in remotes.keys())

        # verify that the URL still is in the cache
        assert("https://github.com/tianocore/edk2-pytool-extensions.git" in remotes.values())

        # verify that there is exactly one entry in the cache for this URL (duplicates should be removed)
        assert(sum(url == "https://github.com/tianocore/edk2-pytool-extensions.git" for url in remotes.values()) == 1)

        # verify that the former remote name is now the "omnicache display name"
        for (name, url) in remotes.items():
            if (url == "https://github.com/tianocore/edk2-pytool-extensions.git"):
                out = StringIO()
                gitret = utility_functions.RunCmd("git",
                                                  f"config --local omnicache.{name}.displayname",
                                                  workingdir=testcache,
                                                  outstream=out)
                assert(gitret == 0)
                displayname = out.getvalue().strip()
                # if there are duplicates, which displayname is chosen is arbitrary, so allow either.
                assert(displayname == "pytools-ext" or displayname == "pytools-ext2")

        # verify that there are no global tags in the root.
        out = StringIO()
        gitret = utility_functions.RunCmd("git", "tag -l", workingdir=testcache, outstream=out)
        assert(gitret == 0)
        assert(out.getvalue().strip() == "")

    def test_omnicache_add_remove(self):
        testcache = os.path.join(os.path.abspath(os.getcwd()), test_dir, "testcache")

        # create a new cache
        oc = omnicache.Omnicache(testcache, create=True, convert=False)

        (valid, _) = oc._ValidateOmnicache()
        assert(valid)

        # add a remote with display name
        ret = oc.AddRemote("https://github.com/tianocore/edk2-pytool-extensions.git", name="pytools-ext")
        assert(ret == 0)

        assert(len(omnicache.Omnicache.GetRemotes(testcache).keys()) == 1)
        assert("https://github.com/tianocore/edk2-pytool-extensions.git"
               in omnicache.Omnicache.GetRemotes(testcache).values())

        # get the remote UUID
        remoteName = oc._LookupRemoteForUrl("https://github.com/tianocore/edk2-pytool-extensions.git")
        assert(remoteName is not None)

        # confirm that remote data is as expected
        remoteData = oc.GetRemoteData()
        assert(len(remoteData.keys()) == 1)
        assert(remoteData[remoteName]["url"] == "https://github.com/tianocore/edk2-pytool-extensions.git")
        assert(remoteData[remoteName]["displayname"] == "pytools-ext")

        # remove the remote and make sure it is gone
        ret = oc.RemoveRemote("https://github.com/tianocore/edk2-pytool-extensions.git")
        assert(ret == 0)
        assert(len(omnicache.Omnicache.GetRemotes(testcache).keys()) == 0)
        assert("https://github.com/tianocore/edk2-pytool-extensions.git"
               not in omnicache.Omnicache.GetRemotes(testcache).values())

        # add a remote without display name
        ret = oc.AddRemote("https://github.com/tianocore/edk2-pytool-extensions.git")
        assert(ret == 0)

        assert(len(omnicache.Omnicache.GetRemotes(testcache).keys()) == 1)
        assert("https://github.com/tianocore/edk2-pytool-extensions.git"
               in omnicache.Omnicache.GetRemotes(testcache).values())

        # get the remote UUID
        remoteName = oc._LookupRemoteForUrl("https://github.com/tianocore/edk2-pytool-extensions.git")
        assert(remoteName is not None)

        # confirm that remote data is as expected
        remoteData = oc.GetRemoteData()
        assert(len(remoteData.keys()) == 1)
        assert(remoteData[remoteName]["url"] == "https://github.com/tianocore/edk2-pytool-extensions.git")
        assert("displayname" not in remoteData[remoteName])

        # add a remote that already exists (with new display name) and make sure it is treated as an update.
        ret = oc.AddRemote("https://github.com/tianocore/edk2-pytool-extensions.git", name="pytools-ext2")
        assert(ret == 0)

        assert(len(omnicache.Omnicache.GetRemotes(testcache).keys()) == 1)
        assert("https://github.com/tianocore/edk2-pytool-extensions.git"
               in omnicache.Omnicache.GetRemotes(testcache).values())

        # get the remote UUID
        remoteName = oc._LookupRemoteForUrl("https://github.com/tianocore/edk2-pytool-extensions.git")
        assert(remoteName is not None)

        # confirm that remote data is as expected
        remoteData = oc.GetRemoteData()
        assert(len(remoteData.keys()) == 1)
        assert(remoteData[remoteName]["url"] == "https://github.com/tianocore/edk2-pytool-extensions.git")
        assert(remoteData[remoteName]["displayname"] == "pytools-ext2")

        # attempt to remove a non-existent remote
        ret = oc.RemoveRemote("http://thisisnot.com/good.git")
        assert (ret != 0)

    def test_omnicache_update(self):
        testcache = os.path.join(os.path.abspath(os.getcwd()), test_dir, "testcache")

        # create a new cache
        oc = omnicache.Omnicache(testcache, create=True, convert=False)

        (valid, _) = oc._ValidateOmnicache()
        assert(valid)

        # add a remote with display name
        ret = oc.AddRemote("https://github.com/tianocore/edk2-pytool-extensions.git", name="pytools-ext")
        assert(ret == 0)

        assert(len(omnicache.Omnicache.GetRemotes(testcache).keys()) == 1)
        assert("https://github.com/tianocore/edk2-pytool-extensions.git"
               in omnicache.Omnicache.GetRemotes(testcache).values())

        # get the remote UUID
        remoteName = oc._LookupRemoteForUrl("https://github.com/tianocore/edk2-pytool-extensions.git")
        assert(remoteName is not None)

        # update the URL and displayname of the remote
        ret = oc.UpdateRemote(
            "https://github.com/tianocore/edk2-pytool-extensions.git",
            newUrl="https://github.com/tianocore/edk2-pytool-extensions2.git",
            newName="pytools-ext2")
        assert(ret == 0)

        assert(len(omnicache.Omnicache.GetRemotes(testcache).keys()) == 1)
        assert("https://github.com/tianocore/edk2-pytool-extensions2.git"
               in omnicache.Omnicache.GetRemotes(testcache).values())

        # make sure UUID didn't change
        assert(remoteName == oc._LookupRemoteForUrl("https://github.com/tianocore/edk2-pytool-extensions2.git"))

        # confirm that remote data is as expected
        remoteData = oc.GetRemoteData()
        assert(len(remoteData.keys()) == 1)
        assert(remoteData[remoteName]["url"] == "https://github.com/tianocore/edk2-pytool-extensions2.git")
        assert(remoteData[remoteName]["displayname"] == "pytools-ext2")

        # update a non-existent URL in the cache and confirm error is returned
        ret = oc.UpdateRemote("https://not.a.real.url.com/git")
        assert (ret != 0)

    def test_omnicache_fetch(self):
        testcache = os.path.join(os.path.abspath(os.getcwd()), test_dir, "testcache")

        # create a new cache
        oc = omnicache.Omnicache(testcache, create=True, convert=False)

        (valid, _) = oc._ValidateOmnicache()
        assert(valid)

        # add a remote with display name
        ret = oc.AddRemote("https://github.com/tianocore/edk2-pytool-extensions.git", name="pytools-ext")
        assert(ret == 0)

        # fetch the remote
        ret = oc.Fetch()
        assert (ret == 0)

        # get the remote UUID
        remoteName = oc._LookupRemoteForUrl("https://github.com/tianocore/edk2-pytool-extensions.git")
        assert(remoteName is not None)

        # verify that branches were fetched into the omnicache
        assert(len(os.listdir(os.path.join(testcache, "refs", "remotes", remoteName))) != 0)

        # verify that tags were fetched into the omnicache
        assert(len(os.listdir(os.path.join(testcache, "refs", "rtags", remoteName))) != 0)

    def test_omnicache_list(self):
        testcache = os.path.join(os.path.abspath(os.getcwd()), test_dir, "testcache")

        # create a new cache
        oc = omnicache.Omnicache(testcache, create=True, convert=False)

        (valid, _) = oc._ValidateOmnicache()
        assert(valid)

        oc.List()

        # add a remote with display name
        ret = oc.AddRemote("https://github.com/tianocore/edk2-pytool-extensions.git", name="pytools-ext")
        assert(ret == 0)

        oc.List()

    def test_config_files(self):
        testcache = os.path.join(os.path.abspath(os.getcwd()), test_dir, "testcache")
        testyaml = os.path.join(os.path.abspath(os.getcwd()), test_dir, "cfg.yaml")

        # create a new cache
        oc = omnicache.Omnicache(testcache, create=True, convert=False)

        (valid, _) = oc._ValidateOmnicache()
        assert(valid)

        # add a remote with display name
        ret = oc.AddRemote("https://github.com/tianocore/edk2-pytool-extensions.git", name="pytools-ext")
        assert(ret == 0)

        # add a remote with no display name
        ret = oc.AddRemote("https://github.com/tianocore/edk2-pytool-extensions2.git")
        assert(ret == 0)

        # export yaml cfg
        ret = omnicache.Export(oc, testyaml)
        assert(ret == 0)

        # inspect the yaml for correctness
        with open(testyaml) as yf:
            content = yaml.safe_load(yf)

        assert("remotes" in content)
        assert(len(content["remotes"]) == 2)
        for remote in content["remotes"]:
            if (remote["url"] == "https://github.com/tianocore/edk2-pytool-extensions.git"):
                assert (remote["name"] == "pytools-ext")
            elif (remote["url"] == "https://github.com/tianocore/edk2-pytool-extensions2.git"):
                assert (omnicache.Omnicache._IsValidUuid(remote["name"]))
                # remove the "display name" for input test below
                del remote["name"]
            else:
                # not one of the URLs we populated above = bad.
                assert(remote["url"] not in remote.values())

        # save the yaml file (since we removed one of the displaynames)
        with open(testyaml, "w") as yf:
            yaml.dump(content, yf)

        # remove the remotes
        ret = oc.RemoveRemote("https://github.com/tianocore/edk2-pytool-extensions.git")
        assert (ret == 0)
        ret = oc.RemoveRemote("https://github.com/tianocore/edk2-pytool-extensions2.git")
        assert (ret == 0)

        # confirm we have no remotes
        assert(len(oc.GetRemoteData()) == 0)

        # import yaml cfg
        ret = omnicache.ProcessInputConfig(oc, testyaml)
        assert(ret == 0)

        # check resulting omnicache config
        for remote in oc.GetRemoteData().values():
            if (remote["url"] == "https://github.com/tianocore/edk2-pytool-extensions.git"):
                assert (remote["displayname"] == "pytools-ext")
            elif (remote["url"] == "https://github.com/tianocore/edk2-pytool-extensions2.git"):
                assert ("displayname" not in remote)
            else:
                # not one of the URLs we populated above = bad.
                assert(remote["url"] not in remote.values())

    def test_omnicache_main(self):
        testcache = os.path.join(os.path.abspath(os.getcwd()), test_dir, "testcache")
        # shameless code coverage play
        oldargs = sys.argv
        sys.argv = ["omnicache", "--init", testcache]
        ret = omnicache.main()
        assert(ret == 0)
        sys.argv = ["omnicache", "--new", testcache]
        ret = omnicache.main()
        assert(ret != 0)
        sys.argv = ["omnicache", "--scan", testcache, testcache]
        ret = omnicache.main()
        assert(ret == 0)
        sys.argv = oldargs


if __name__ == '__main__':
    unittest.main()
