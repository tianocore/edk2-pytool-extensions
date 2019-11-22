# @file GitDependency.py
# This module implements ExternalDependency for a git repository
# This should only be used for read-only repositories. Any changes in
# these extdeps will be removed.
##
# Copyright (c) Microsoft Corporation
#
# SPDX-License-Identifier: BSD-2-Clause-Patent
##
import os
import logging
from urllib.parse import urlsplit, urlunsplit
from edk2toolext.environment.external_dependency import ExternalDependency
from edk2toolext.environment import repo_resolver
from edk2toolext.edk2_git import Repo
from edk2toolext.environment import shell_environment


class GitDependency(ExternalDependency):
    '''
    ext_dep fields:
    - source:  url for git clone
    - version: commit from git repo
    - url_creds_var: shell_var name for credential updating [optional]
    '''

    TypeString = "git"

    def __init__(self, descriptor):
        super().__init__(descriptor)

        # Check to see whether this URL should be patched.
        url_creds_var = descriptor.get('url_creds_var', None)
        if url_creds_var is not None:
            env = shell_environment.GetEnvironment()
            url_creds = env.get_shell_var(url_creds_var)
            if url_creds is not None:
                # Break things up.
                source_parts = urlsplit(self.source)
                # Modify the URL host with the creds.
                new_parts = (source_parts.scheme,
                             url_creds + '@' + source_parts.netloc,
                             source_parts.path,
                             source_parts.query,
                             source_parts.fragment)
                # Put things back together.
                self.source = urlunsplit(new_parts)

        self.repo_url = self.source
        self.commit = self.version
        self._local_repo_root_path = os.path.join(os.path.abspath(self.contents_dir), self.name)
        self.logger = logging.getLogger("git-dependency")

        # valid_attributes = ["Path", "Url", "Branch", "Commit", "ReferencePath", "Full"]
        self._repo_resolver_dep_obj = {"Path": self.name, "Url": self.repo_url, "Commit": self.commit}

    def __str__(self):
        """ return a string representation of this """
        return f"GitDependecy: {self.repo_url}@{self.commit}"

    def fetch(self):

        # def resolve(file_system_path, dependency, force=False, ignore=False, update_ok=False):
        repo_resolver.resolve(self._local_repo_root_path, self._repo_resolver_dep_obj, update_ok=True)

        # Add a file to track the state of the dependency.
        self.update_state_file()

    def clean(self):
        self.logger.debug("Cleaning git dependency directory for '%s'..." % self.name)

        if os.path.isdir(self._local_repo_root_path):
            # Clean up git dependency specific stuff
            repo_resolver.clear_folder(self.contents_dir)

        # Let super class clean up common dependency stuff
        super().clean()

    # override verify due to different scheme with git
    def verify(self):
        result = True

        if not os.path.isdir(self._local_repo_root_path):
            self.logger.error("no dir for Git Dependency")
            result = False

        if result and len(os.listdir(self._local_repo_root_path)) == 0:
            self.logger.error("no files in Git Dependency")
            result = False

        if result:
            # valid repo folder
            r = Repo(self._local_repo_root_path)
            if(not r.initalized):
                self.logger.error("Git Dependency: Not Initialized")
                result = False
            elif(r.dirty):
                self.logger.error("Git Dependency: dirty")
                result = False

            if(r.head.commit != self.version):
                self.logger.error(f"Git Dependency: head is {r.head.commit} and version is {self.version}")
                result = False

        self.logger.debug("Verify '%s' returning '%s'." % (self.name, result))
        return result
