# @file GitDependency.py
# This module implements ExternalDependency for a git repository
# This should only be used for read-only repositories. Any changes in
# these extdeps will be removed.
##
# Copyright (c) Microsoft Corporation
#
# SPDX-License-Identifier: BSD-2-Clause-Patent
##
"""An ExternalDependency subclass able to clone from git."""
import os
import logging
from urllib.parse import urlsplit, urlunsplit
from edk2toolext.environment.external_dependency import ExternalDependency
from edk2toolext.environment import repo_resolver
from edk2toolext.edk2_git import Repo
from edk2toolext.environment import shell_environment


class GitDependency(ExternalDependency):
    """An ExternalDependency subclass able to clone from git.

    Attributes:
        source (str): url for git clone
        version (str): commit from git repo
        url_creds_var (str): shell_var name for credential updating. Optional

    !!! tip
        The attributes are what must be described in the ext_dep yaml file!
    """
    TypeString = "git"

    def __init__(self, descriptor):
        """Inits a git dependency based off the provided descriptor."""
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
        """Return a string representation."""
        return f"GitDependecy: {self.repo_url}@{self.commit}"

    def fetch(self):
        """Fetches the dependency using internal state from the init."""
        # def resolve(file_system_path, dependency, force=False, ignore=False, update_ok=False):
        repo_resolver.resolve(self._local_repo_root_path, self._repo_resolver_dep_obj, update_ok=True)

        # Add a file to track the state of the dependency.
        self.update_state_file()

    def clean(self):
        """Removes the local clone of the repo."""
        self.logger.debug("Cleaning git dependency directory for '%s'..." % self.name)

        if os.path.isdir(self._local_repo_root_path):
            # Clean up git dependency specific stuff
            repo_resolver.clear_contents(self.contents_dir)

        # Let super class clean up common dependency stuff
        super().clean()

    def verify(self):
        """Verifies the clone was successful."""
        result = True

        if not os.path.isdir(self._local_repo_root_path):
            self.logger.info("no dir for Git Dependency")
            result = False

        if result and len(os.listdir(self._local_repo_root_path)) == 0:
            self.logger.info("no files in Git Dependency")
            result = False

        if result:
            # valid repo folder
            r = Repo(self._local_repo_root_path)
            if (not r.initialized):
                self.logger.info("Git Dependency: Not Initialized")
                result = False
            elif (r.dirty):
                self.logger.warning("Git Dependency: dirty")
                result = False

            elif (r.head.commit != self.version and r.head.short_commit != self.version):
                self.logger.info(f"Git Dependency: head is {r.head.commit} and version is {self.version}")
                result = False

        self.logger.debug("Verify '%s' returning '%s'." % (self.name, result))
        return result

    def compute_published_path(self):
        """Override to include the repository name in the published path."""
        return os.path.join(super().compute_published_path(), self.name)
