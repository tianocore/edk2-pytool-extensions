# @file edk2_git.py
# This module contains code that supports simple git operations.  This should
# not be used as an extensive git lib but as what is needed for CI/CD builds
#
##
# Copyright (c) Microsoft Corporation
#
# SPDX-License-Identifier: BSD-2-Clause-Patent
##
"""This module contains code that supports simple git operations.

This should not be used as an extensive git lib, but as what is needed for CI/CD builds.
"""
import os
import logging
from io import StringIO
from edk2toollib.utility_functions import RunCmd
import pygit2 as git
from pathlib import Path
from typing import Union  # Backwards compat for 3.9
from edk2toollib.utility_functions import RemoveTree


class ObjectDict(object):
    """A class representing an ObjectDict."""
    def __init__(self):
        """Inits an empty ObjectDict."""
        self.__values = list()

    def __setattr__(self, key, value):
        """Sets an attribute."""
        if not key.startswith("_"):
            self.__values.append(key)
        super().__setattr__(key, value)

    def __str__(self):
        """String representation of ObjectDict."""
        result = list()
        result.append("ObjectDict:")
        for value in self.__values:
            result.append(value + ":" + str(getattr(self, value)))
        return "\n".join(result)

    def set(self, key, value):
        """Sets a key value pair."""
        self.__setattr__(key, value)


class Repo(object):
    """A class representing a git repo.

    Public attributes are determined at run time by using pygit2 to parse the
    git object and reference database.

    !!! warning
        This class holds a reference to the git repository database making it
        difficult to delete the repo while this class is instantiated. To
        delete the repository, one can call the `free()` method and delete it
        manually; the `delete()` method to delete the repository; or
        deallocate the class, freeing the reference to the git repository
        database.

    Attributes:
        path (Path): path to the repo
        exists (bool): If the path is valid
        initialized (bool): If there is a git repo at the path
        bare (bool): If the repo is bare
        dirty (bool): If there are changes in the repo
        active_branch (str): Name of the active branch
        head (str): The head commit this repo is at
        remotes (obj): All remotes associated with the repo
        worktrees (list[ObjectDict]): A list of worktrees (attr path, name)
        url (str): The url of the origin remote associated with the repo
        submodules (list[str]): list of submodule paths

    """
    def __init__(self, path: Union[str, Path, None] = None):
        """Inits an empty Repo object."""
        self._logger = logging.getLogger("git.repo")
        self._repo = None
        self.path = path  # Refer to @path.setter

    def __del__(self):
        """Release the handle to the git database (.git).

        It is necessary to call free now to ensure git files are not locked
        and can be deleted if necessary. (Cleaning up, etc.)
        """
        self.free()

    @property
    def exists(self):
        """Property describing if the path associated with the repo is valid."""
        return os.path.isdir(self._path)

    @property
    def initialized(self):
        """Property describing if a repo is initialized at the associated path."""
        return os.path.isdir(os.path.join(self._path, ".git"))

    @property
    def bare(self):
        """Property describing if the repo is bare."""
        if not self._repo:
            return True
        return self._repo.is_bare

    @property
    def dirty(self):
        """Property describing if the repo is dirty."""
        if not self._repo:
            return False
        return len(self._repo.status()) != 0

    @property
    def active_branch(self):
        """Property describing the active branch name."""
        if not self._repo:
            return None
        return self._repo.head.shorthand

    @property
    def head(self):
        """Property describing the head commit."""
        if not self._repo:
            return None

        head = ObjectDict()
        commit_obj = self._repo.revparse("HEAD").from_object
        head.set('commit', str(commit_obj.id))
        head.set('short_commit', str(commit_obj.short_id))
        return head

    @property
    def url(self):
        """Property describing the origin remote url."""
        if not self._repo:
            return None

        return self.remotes.origin.url

    @property
    def remotes(self):
        """Property describing all remotes."""
        if not self._repo:
            return ObjectDict()

        remotes = ObjectDict()
        for remote in self._repo.remotes:
            url = ObjectDict()
            url.set("url", remote.url)
            setattr(remotes, remote.name, url)
        return remotes

    @property
    def worktrees(self):
        """Property describing a list of worktrees."""
        if not self._repo:
            return []

        worktrees = []

        for worktree in self._repo.list_worktrees():
            worktree = self._repo.lookup_worktree(worktree)

            worktree_dict = ObjectDict()
            worktree_dict.set("name", worktree.name)
            worktree_dict.set("path", Path(worktree.path))

            worktrees.append(worktree_dict)

        return worktrees

    @property
    def submodules(self):
        """Property describing a list of all submodules."""
        if not self._repo:
            return None

        return self._repo.listall_submodules()

    @property
    def path(self):
        """Property describing the path to the repo."""
        return self._path

    @path.setter
    def path(self, path: Union[str, Path, None]):
        """Sets the repo path and inits the repo if applicable."""
        if not path:
            self._path = None
        elif type(path) == str:
            self._path = Path(path)
        elif issubclass(type(path), Path):
            self._path = path
        else:
            raise TypeError(f'`path` parameter of unexpected type {type(path)}.')

        if self.path:
            try:
                self._repo = git.Repository(self._path)
            except Exception:
                pass

    def free(self):
        """Releases the handle on the git repository database.

        Call this method if you plan on manually manipulating files in the
        git repository as this class may keep a reference to some files,
        stopping one from manipulating (moving, editing, deleting) the file.
        """
        if self._repo:
            self._repo.free()

    def submodule(self, command, *args):
        """Performs a git command on a submodule."""
        self._logger.debug(
            "Calling command on submodule {0} with {1}".format(command, args))
        return_buffer = StringIO()
        flags = " ".join(args)
        params = "submodule {0} {1}".format(command, flags)

        ret = RunCmd("git", params, workingdir=self._path,
                     outstream=return_buffer)

        return_buffer.seek(0)
        p1 = return_buffer.getvalue().strip()
        if ret != 0:
            self._logger.error(p1)
            return False

        return True

    def fetch(self, remote="origin", branch=None):
        """Performs a git fetch."""
        return_buffer = StringIO()

        param_list = ["fetch", remote]
        if branch is not None:
            param_list.append(f"{branch}:{branch}")

        params = " ".join(param_list)

        ret = RunCmd("git", params, workingdir=self._path,
                     outstream=return_buffer)

        return_buffer.seek(0)
        p1 = return_buffer.getvalue().strip()
        if ret != 0:
            self._logger.error(p1)
            return False

        return True

    def pull(self):
        """Performs a git pull."""
        return_buffer = StringIO()

        params = "pull"

        ret = RunCmd("git", params, workingdir=self._path,
                     outstream=return_buffer)

        return_buffer.seek(0)
        p1 = return_buffer.getvalue().strip()
        if ret != 0:
            self._logger.error(p1)
            return False

        return True

    def checkout(self, branch=None, commit=None):
        """Checks out a branch or commit."""
        return_buffer = StringIO()
        if branch is not None:
            params = "checkout %s" % branch
        elif commit is not None:
            params = "checkout %s" % commit
        ret = RunCmd("git", params, workingdir=self._path,
                     outstream=return_buffer)

        return_buffer.seek(0)
        p1 = return_buffer.getvalue().strip()
        if ret != 0:
            self._logger.debug(p1)
            return False

        return True

    def delete(self):
        """Delete contents of the repository."""
        if not self.path:
            return

        self.free()
        RemoveTree(self.path)
        self._repo = None

    @classmethod
    def clone_from(self, url, to_path, branch=None, shallow=False, reference=None, **kwargs):
        """Clones a repository."""
        _logger = logging.getLogger("git.repo")
        _logger.debug("Cloning {0} into {1}".format(url, to_path))
        # make sure we get the commit if
        # use run command from utilities
        cmd = "git"
        params = ["clone"]
        if branch:
            shallow = True
            params.append(f'--branch {branch}')
            params.append('--single-branch')
        if shallow:
            # params.append("--shallow-submodules")
            params.append("--depth=5")
        if reference:
            params.append("--reference %s" % reference)
        else:
            params.append("--recurse-submodules")  # if we don't have a reference we can just recurse the submodules

        params.append(url)
        params.append(to_path)

        # Combine all the parameters together
        param_string = " ".join(params)

        ret = RunCmd(cmd, param_string)

        if ret != 0:
            _logger.error("ERROR CLONING ")
            return None

        # if we have a reference path we must init the submodules
        if reference:
            params = ["submodule", "update", "--init", "--recursive"]
            params.append("--reference %s" % reference)
            param_string = " ".join(params)
            RunCmd(cmd, param_string)

        return Repo(to_path)

    @classmethod
    def discover_repository(self, path):
        """Looks for a git repository and returns it's path."""
        return git.discover_repository(path)
