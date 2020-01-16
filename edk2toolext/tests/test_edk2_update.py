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

class_info = '''
from edk2toolext.invocables.edk2_update import UpdateSettingsManager
import os
class TestSettingsManager(UpdateSettingsManager):

    def GetActiveScopes(self):
        return []

    def GetWorkspaceRoot(self):
        return os.path.dirname(__file__)  # assume the workspace is in the parent directory

    def AddCommandLineOptions(self, parserObj):
        pass

    def RetrieveCommandLineOptions(self, args):
        pass

    def GetName(self):
        return "TestUpdate"

    def GetArchitecturesSupported(self):
        return []

    def GetPackagesSupported(self):
        return []

    def GetTargetsSupported(self):
        return []
'''

class TestEdk2Update(unittest.TestCase):

    def update(self):
        TestEdk2Update.restart_logging()
        pass

    def tearDown(self):
        shell_environment.GetEnvironment().restore_initial_checkpoint()
        for temp_folder in TestEdk2Update.temp_folders:
            logging.info(f"Cleaning up {temp_folder}")
            #shutil.rmtree(os.path.abspath(temp_folder), ignore_errors=True)
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

    @classmethod
    def write_to_file(cls, path, contents, close=True):
        f = open(path, "w")
        f.writelines(contents)
        if close:
            f.close()

    def create_local_git_repo(self, add_ignore=True):
        ''' creates a git repo and gives it to you '''
        git_dir = self.get_temp_folder()
        ret = RunCmd("git", "init", workingdir=git_dir)
        self.assertEqual(int(ret), 0, "We should not fail the git init")
        repo = Repo(git_dir)
        if add_ignore:
            TestEdk2Update.write_to_file(os.path.join(git_dir, ".gitignore"), "*_extdep/")
            self.commit_local_git_repo(repo)
        return repo

    def commit_local_git_repo(self, repo: Repo):
        ''' checks in a commit to a local git repo '''
        git_dir = repo.get_path()
        ret = RunCmd("git", "add .", workingdir=git_dir)
        self.assertEqual(int(ret), 0, "We should not fail the git add")
        ret = RunCmd("git", "commit -a -m TEST", workingdir=git_dir)
        self.assertEqual(int(ret), 0, "We should not fail the git commit")
        return repo._get_head().commit

    def invoke_update(self, settings_filepath, args = [], failure_expected=False):
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
        WORKSPACE = self.get_temp_folder()
        logging.getLogger().setLevel(logging.WARNING)
        settings_filepath = os.path.join(WORKSPACE, "settings.py")
        TestEdk2Update.write_to_file(settings_filepath, class_info)
        git_repo = self.create_local_git_repo()
        self.assertNotEqual(git_repo.get_path(), None)
        octocat_ext_dep = f'''
        {{
        "scope": "global",
        "type": "git",
        "name": "Octocat",
        "version": "d0dd1f61b33d64e29d8bc1372a94ef6a2fee76a9",
        "source": "https://github.com/octocat/Spoon-Knife.git",
        "flags": []
        }}
        '''
        TestEdk2Update.write_to_file(os.path.join(git_repo.get_path(), "octocat_ext_dep.json"), octocat_ext_dep)
        git_hash = self.commit_local_git_repo(git_repo)

        escaped_git_repo = git_repo.get_path().replace("\\","\\\\")
        print(git_hash)
        self.assertGreater(len(git_hash), 30)
        local_ext_dep = f'''
        {{
        "scope": "global",
        "type": "git",
        "name": "MYREPO",
        "version": "{git_hash}",
        "source": "{escaped_git_repo}",
        "flags": []
        }}
        '''
        # now add the ext_dep to the git repo
        TestEdk2Update.write_to_file(os.path.join(WORKSPACE, "myrepo_ext_dep.json"), local_ext_dep)

        # Do the update
        self.invoke_update(settings_filepath)

        # now we should check that our workspace is how we expect it
        (build_env, shell_env) = self_describing_environment.BootstrapEnvironment(WORKSPACE, [])
        # make sure we find more than 1 path
        self.assertNotEqual(build_env.extdeps, None)
        self.assertGreater(len(build_env.extdeps), 0)
        print(build_env.extdeps)
        self.assertTrue(os.path.exists(WORKSPACE, "MYREPO_extdep", "MYREPO", "Octocat_extdep", "Octocat"))