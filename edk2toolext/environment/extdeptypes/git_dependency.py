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

import logging
import os
from urllib.parse import urlsplit, urlunsplit

from edk2toolext.environment import repo_resolver, shell_environment
from edk2toolext.environment.external_dependency import ExternalDependency


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

    def __init__(self, descriptor: dict) -> None:
        """Inits a git dependency based off the provided descriptor."""
        super().__init__(descriptor)

        # Check to see whether this URL should be patched.
        url_creds_var = descriptor.get("url_creds_var", None)
        if url_creds_var is not None:
            env = shell_environment.GetEnvironment()
            url_creds = env.get_shell_var(url_creds_var)
            if url_creds is not None:
                # Break things up.
                source_parts = urlsplit(self.source)
                # Modify the URL host with the creds.
                new_parts = (
                    source_parts.scheme,
                    url_creds + "@" + source_parts.netloc,
                    source_parts.path,
                    source_parts.query,
                    source_parts.fragment,
                )
                # Put things back together.
                self.source = urlunsplit(new_parts)

        self.repo_url = self.source
        self.commit = self.version
        self._local_repo_root_path = os.path.join(os.path.abspath(self.contents_dir), self.name)
        self.logger = logging.getLogger("git-dependency")

        # valid_attributes = ["Path", "Url", "Branch", "Commit", "ReferencePath", "Full"]
        self._repo_resolver_dep_obj = {
            "Path": self.name,
            "Url": self.repo_url,
            "Commit": self.commit,
            "Recurse": True,
        }

    def __str__(self) -> str:
        """Return a string representation."""
        return f"GitDependecy: {self.repo_url}@{self.commit}"

    def fetch(self) -> None:
        """Fetches the dependency using internal state from the init."""
        try:
            repo_resolver.resolve(self._local_repo_root_path, self._repo_resolver_dep_obj, update_ok=True)
        except repo_resolver.GitCommandError as e:
            logging.debug(f"Cmd failed for git dependency: {self._local_repo_root_path}")
            logging.debug(e)

        # Add a file to track the state of the dependency.
        self.update_state_file()

    def clean(self) -> None:
        """Removes the local clone of the repo."""
        self.logger.debug("Cleaning git dependency directory for '%s'..." % self.name)

        if os.path.isdir(self._local_repo_root_path):
            # Clean up git dependency specific stuff
            repo_resolver.clear_folder(self.contents_dir)

        # Let super class clean up common dependency stuff
        super().clean()

    def verify(self) -> bool:
        """Verifies the clone was successful."""
        result = True
        details = repo_resolver.repo_details(self._local_repo_root_path)

        if not details["Path"].is_dir():
            self.logger.info("Not a directory")
            result = False

        elif not any(details["Path"].iterdir()):
            self.logger.info("No files in directory")
            result = False

        elif not details["Initialized"]:
            self.logger.info("Not Initialized")
            result = False

        elif details["Dirty"]:
            self.logger.info("Dirty")
            result = False

        elif self.version.lower() not in [details["Head"]["HexSha"], details["Head"]["HexShaShort"]]:
            self.logger.info(f"Mismatched sha: [head: {details['Head']['HexSha']}], [expected: {self.version}]")
            result = False

        self.logger.debug("Verify '%s' returning '%s'." % (self.name, result))
        return result

    def compute_published_path(self) -> str:
        """Override to include the repository name in the published path."""
        return os.path.join(super().compute_published_path(), self.name)
