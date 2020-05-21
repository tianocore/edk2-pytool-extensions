# @file edk2_git.py
# This module contains code that supports simple git operations.  This should
# not be used as an extensive git lib but as what is needed for CI/CD builds
#
##
# Copyright (c) Microsoft Corporation
#
# SPDX-License-Identifier: BSD-2-Clause-Patent
##

import os
import logging
from io import StringIO
from edk2toollib.utility_functions import RunCmd


class ObjectDict(object):
    def __init__(self):
        self.__values = list()

    def __setattr__(self, key, value):
        if not key.startswith("_"):
            self.__values.append(key)
        super().__setattr__(key, value)

    def __str__(self):
        result = list()
        result.append("ObjectDict:")
        for value in self.__values:
            result.append(value + ":" + str(getattr(self, value)))
        return "\n".join(result)

    def set(self, key, value):
        self.__setattr__(key, value)


class Repo(object):

    def __init__(self, path=None):
        self._path = path  # the path that the repo is pointed at
        self.active_branch = None  # the active branch or none if detached
        self.bare = True  # if the repo is bare
        self.exists = False  # if the .git folder exists
        self.remotes = ObjectDict()
        self.initalized = False  # if there is a git repo at the directory
        self.url = None  # the origin remote
        self.dirty = False  # if there are changes
        self.head = None  # the head commit that this repo is at
        self.submodules = None  # List of submodule paths
        self._update_from_git()
        self._logger = logging.getLogger("git.repo")

    # Updates the .git file
    def _update_from_git(self):

        if os.path.isdir(self._path):
            try:
                self.exists = True
                self.active_branch = self._get_branch()
                self.remotes = self._get_remotes()
                self.head = self._get_head()
                self.dirty = self._get_dirty()
                self.url = self._get_url()
                self.bare = self._get_bare()
                self.initalized = self._get_initalized()
                self.submodules = self._get_submodule_list()
            except Exception as e:
                self._logger.error("GIT ERROR for {0}".format(self._path))
                self._logger.error(e)
                raise e
                return False

    def _get_submodule_list(self):
        submodule_list = []
        return_buffer = StringIO()
        params = "config --file .gitmodules --get-regexp path"
        RunCmd("git", params, workingdir=self._path, outstream=return_buffer)
        p1 = return_buffer.getvalue().strip()
        return_buffer.close()
        if (len(p1) > 0):
            submodule_list = p1.split("\n")
            for i in range(0, len(submodule_list)):
                submodule_list[i] = submodule_list[i].split(' ')[1]
        return submodule_list

    def _get_remotes(self):
        return_buffer = StringIO()
        params = "remote"
        new_remotes = ObjectDict()
        RunCmd("git", params, workingdir=self._path, outstream=return_buffer)
        p1 = return_buffer.getvalue().strip()
        return_buffer.close()
        remote_list = p1.split("\n")
        for remote in remote_list:
            url = ObjectDict()
            url.set("url", self._get_url(remote))
            setattr(new_remotes, remote, url)

        return new_remotes

    def _get_url(self, remote="origin"):
        return_buffer = StringIO()
        params = "config --get remote.{0}.url".format(remote)
        RunCmd("git", params, workingdir=self._path, outstream=return_buffer)

        p1 = return_buffer.getvalue().strip()
        return_buffer.close()
        return p1

    def _get_dirty(self):
        return_buffer = StringIO()
        params = "status --short"

        RunCmd("git", params, workingdir=self._path, outstream=return_buffer)

        p1 = return_buffer.getvalue().strip()
        return_buffer.close()

        if len(p1) > 0:
            return True

        return_buffer = StringIO()
        params = "log --branches --not --remotes --decorate --oneline"

        RunCmd("git", params, workingdir=self._path, outstream=return_buffer)

        p1 = return_buffer.getvalue().strip()
        return_buffer.close()

        if len(p1) > 0:
            return True

        return False

    def _get_branch(self):
        return_buffer = StringIO()
        params = "rev-parse --abbrev-ref HEAD"
        RunCmd("git", params, workingdir=self._path, outstream=return_buffer)

        p1 = return_buffer.getvalue().strip()
        return_buffer.close()
        return p1

    def _get_head(self):
        return_buffer = StringIO()
        params = "rev-parse HEAD"
        RunCmd("git", params, workingdir=self._path, outstream=return_buffer)

        p1 = return_buffer.getvalue().strip()
        return_buffer.close()

        head = ObjectDict()
        head.set("commit", p1)

        return head

    def _get_bare(self):
        return_buffer = StringIO()
        params = "rev-parse --is-bare-repository"
        RunCmd("git", params, workingdir=self._path, outstream=return_buffer)

        p1 = return_buffer.getvalue().strip()
        return_buffer.close()
        if p1.lower() == "true":
            return True
        else:
            return False

    def _get_initalized(self):
        return os.path.isdir(os.path.join(self._path, ".git"))

    def submodule(self, command, *args):
        self._logger.debug(
            "Calling command on submodule {0} with {1}".format(command, args))
        return_buffer = StringIO()
        flags = " ".join(args)
        params = "submodule {0} {1}".format(command, flags)

        ret = RunCmd("git", params, workingdir=self._path,
                     outstream=return_buffer)

        p1 = return_buffer.getvalue().strip()
        if ret != 0:
            self._logger.error(p1)
            return False

        return True

    def fetch(self):
        return_buffer = StringIO()

        params = "fetch"

        ret = RunCmd("git", params, workingdir=self._path,
                     outstream=return_buffer)

        p1 = return_buffer.getvalue().strip()
        if ret != 0:
            self._logger.error(p1)
            return False

        return True

    def pull(self):
        return_buffer = StringIO()

        params = "pull"

        ret = RunCmd("git", params, workingdir=self._path,
                     outstream=return_buffer)

        p1 = return_buffer.getvalue().strip()
        if ret != 0:
            self._logger.error(p1)
            return False

        return True

    def checkout(self, branch=None, commit=None):
        return_buffer = StringIO()
        if branch is not None:
            params = "checkout %s" % branch
        elif commit is not None:
            params = "checkout %s" % commit
        ret = RunCmd("git", params, workingdir=self._path,
                     outstream=return_buffer)

        p1 = return_buffer.getvalue().strip()
        if ret != 0:
            self._logger.debug(p1)
            return False

        return True

    @classmethod
    def clone_from(self, url, to_path, progress=None, env=None, shallow=False, reference=None, **kwargs):
        _logger = logging.getLogger("git.repo")
        _logger.debug("Cloning {0} into {1}".format(url, to_path))
        # make sure we get the commit if
        # use run command from utilities
        cmd = "git"
        params = ["clone"]
        if shallow:
            params.append("--shallow-submodules")
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
            logging.error("ERROR CLONING ")
            return None

        # if we have a reference path we must init the submodules
        if reference:
            params = ["submodule", "update", "--init", "--recursive"]
            params.append("--reference %s" % reference)
            param_string = " ".join(params)
            ret = RunCmd(cmd, param_string)

        return Repo(to_path)
