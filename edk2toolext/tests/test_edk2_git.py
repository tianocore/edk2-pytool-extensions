## @file test_edk2_git.py
# This contains unit tests for edk2_git
##
# Copyright (c) Microsoft Corporation
#
# SPDX-License-Identifier: BSD-2-Clause-Patent
##
import unittest
import tempfile
from pathlib import Path
from edk2toolext.edk2_git import Repo


class test_edk2_git(unittest.TestCase):

    def test_repo(self):
        repo_url = tempfile.mkdtemp()
        r = Repo.clone_from('https://github.com/tianocore/edk2-pytool-extensions', repo_url)

        self.assertEqual(r.active_branch, 'master')
        self.assertEqual(r.bare, False)
        self.assertEqual(r.dirty, False)
        self.assertEqual(r.remotes.origin.url, 'https://github.com/tianocore/edk2-pytool-extensions')
        self.assertEqual(r.url, 'https://github.com/tianocore/edk2-pytool-extensions')
        self.assertEqual(len(r.submodules), 0)

        self.assertTrue(r.checkout(commit='9e5ecb2aa7aae5a33ca57f7e2c95eb09c379295f'))
        self.assertEqual(r.active_branch, 'HEAD')
        self.assertEqual(r.head.commit, '9e5ecb2aa7aae5a33ca57f7e2c95eb09c379295f')
        self.assertEqual(r.head.short_commit, '9e5ecb2')

        self.assertTrue(r.checkout(commit='5e17bf6'))
        self.assertEqual(r.active_branch, 'HEAD')
        self.assertEqual(r.head.commit, '5e17bf6ad09d1b60236792008b576b348f74d940')
        self.assertEqual(r.head.short_commit, '5e17bf6')

        self.assertTrue(r.fetch(branch='master'))
        self.assertTrue(r.checkout('master'))
        self.assertTrue(r.pull())
        self.assertEqual(r.active_branch, 'master')
        r.delete()

        # Repo deleted, verify we get empty repo results
        self.assertEqual(r.exists, False)
        self.assertEqual(r.url, None)
        self.assertEqual(r.active_branch, None)
        self.assertEqual(r.bare, True)
        self.assertEqual(r.head, None)
        self.assertEqual(r.dirty, False)
        self.assertEqual(len(r.worktrees), 0)
        self.assertEqual(r.submodules, None)

        # Clone again, update the repo_url with str
        Repo.clone_from('https://github.com/tianocore/edk2-pytool-extensions', repo_url)
        r.path = repo_url

        self.assertEqual(r.active_branch, 'master')
        self.assertEqual(r.bare, False)
        self.assertEqual(r.dirty, False)
        self.assertEqual(r.remotes.origin.url, 'https://github.com/tianocore/edk2-pytool-extensions')
        self.assertEqual(r.url, 'https://github.com/tianocore/edk2-pytool-extensions')
        self.assertEqual(len(r.submodules), 0)

        r.delete()
        # Repo deleted, verify we get empty repo results
        self.assertEqual(r.exists, False)
        self.assertEqual(r.url, None)
        self.assertEqual(r.active_branch, None)
        self.assertEqual(r.bare, True)
        self.assertEqual(r.head, None)
        self.assertEqual(r.dirty, False)
        self.assertEqual(len(r.worktrees), 0)
        self.assertEqual(r.submodules, None)

        # Clone again, update the repo_url with Path object
        Repo.clone_from('https://github.com/tianocore/edk2-pytool-extensions', repo_url)
        r.path = Path(repo_url)

        self.assertEqual(r.active_branch, 'master')
        self.assertEqual(r.bare, False)
        self.assertEqual(r.dirty, False)
        self.assertEqual(r.remotes.origin.url, 'https://github.com/tianocore/edk2-pytool-extensions')
        self.assertEqual(r.url, 'https://github.com/tianocore/edk2-pytool-extensions')
        self.assertEqual(len(r.submodules), 0)

        r.delete()

    def test_empty_repo_path(self):
        repo_url = tempfile.mkdtemp()
        r = Repo(repo_url)

        self.assertEqual(r.exists, True)
        self.assertEqual(r.url, None)
        self.assertEqual(r.active_branch, None)
        self.assertEqual(r.bare, True)
        self.assertEqual(r.head, None)
        self.assertEqual(r.dirty, False)
        self.assertEqual(len(r.worktrees), 0)
        self.assertEqual(r.submodules, None)

        r.delete()

    def test_clone_from_bad_url(self):
        repo_url = tempfile.mkdtemp()
        repo = Repo.clone_from('https://bad', repo_url)
        self.assertEqual(repo, None)

        Repo(repo_url).delete()
