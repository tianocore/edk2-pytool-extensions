# @file edk2_init
# Initializes submodules and/or downloads repositories as specified in the Config file.
##
# Copyright (c) Microsoft Corporation
#
# SPDX-License-Identifier: BSD-2-Clause-Patent
##
"""An invocable that initializes submodules and/or downloads repositories.

Contains a InitSettingsManager that must be subclassed in a configuration file.
This provides information to the Edk2Setup invocable on what to initialize.
"""
import logging
import os
from pathlib import Path
from typing import List

from edk2toollib.utility_functions import GetHostInfo

from edk2toolext import edk2_logging
from edk2toolext.environment import repo_resolver, version_aggregator
from edk2toolext.environment.repo_resolver import (
    GitCommandError,
    InvalidGitRepositoryError,
    clean,
    repo_details,
    submodule_clean,
    submodule_resolve,
)
from edk2toolext.invocables.edk2_multipkg_aware_invocable import (
    Edk2MultiPkgAwareInvocable,
    MultiPkgAwareSettingsInterface,
)


class Submodule():
    """Object to hold necessary information for resolving a submodule."""
    def __init__(self, path: str, recursive: bool = True):
        """Initializes the repository object.

        Args:
            path (str): workspace relative path to submodule that must be
                synchronized and updated
            recursive (bool): if recursion should be used in this submodule
        """
        self.path = path
        self.recursive = recursive


class Repository():
    """Object to hold necessary information for downloading a repository."""
    def __init__(self, path: str, url: str, **kwargs):
        """Initializes the repository object.

        Args:
            path (str): workspace relative path to download a repository to
            url (str): url to the repository
            kwargs (any): Keyword arguments

        Keyword Arguments:
            commit (str): the commit to checkout
            branch (str): the branch to checkout
            full (str): does a shallow checkout if false
            ref_path (str): workspace relative path to git repo to use as a ref
        """
        self.path = path
        self.url = url
        self.commit = kwargs.get("commit", None)
        self.branch = kwargs.get("branch", None)
        self.full = kwargs.get("full", False)
        self.ref_path = kwargs.get("ref_path", None)

    def as_dict(self) -> dict:
        """Returns a dictionary representation of the object."""
        d = {
            "Path": self.path,
            "Url": self.url,
            "Full": self.full
        }
        if self.commit:
            d["Commit"] = self.commit
        if self.branch:
            d["Branch"] = self.branch
        if self.ref_path:
            d["ReferencePath"] = self.ref_path
        return d


class InitializeSettingsManager(MultiPkgAwareSettingsInterface):
    """Configuration settings for Edk2Initialize.

    Provides configuration information to the `stuart_init` invocable.

    !!! example "Example of Overriding InitSettingsManager"
        ```python
        from edk2toolext.invocables.edk2_init import InitSettingsManager, RequiredSubmodule
        class PlatformManager(InitSettingsManager):
            def GetRequiredSubmodules(self) -> List[RequiredSubmodule]:
                return [RequiredSubmodule('Common/MU', True)]
        ```
    """

    def get_required_submodules(self) -> List[Submodule]:
        """Returns a list of submodules to initialize.

        !!! tip
            Optional override in a subclass

        Returns:
            (list[Submodule]): A list of submodules
        """
        return []

    def get_required_repositories(self) -> List[Repository]:
        """Returns a list of repositories to download.

        !!! tip
            Optional override in a subclass

        Returns:
            (list[Repository]): A list of repositories
        """
        return []

class Edk2Initialize(Edk2MultiPkgAwareInvocable):
    """An invocable supporting the ability to initialize an EDK2 project repository.

    Edk2Initialize will initialize any submodules and/or download any repositories as
    specified in the configuration settings file.
    """
    def AddCommandLineOptions(self, parserObj):
        """Adds command line arguments to Edk2Initialize."""
        parserObj.add_argument("-f", "--force", "--FORCE", dest="force", action="store_true",
                               help="Force the initialization.")
        parserObj.add_argument("-i", "--ignore", "--IGNORE", dest="ignore", action="store_true",
                               help="Whether to ignore errors in the process or not.")
        parserObj.add_argument("-r", "--repo-only", dest="repo_only", action="store_true",
                               help="Only initialize repositories")
        parserObj.add_argument("-s", "--submodule-only", dest="submodule_only", action="store_true",
                               help="Only initialize submodules")
        parserObj.add_argument("-o", "--omnicache", "--reference", dest="omnicache_path",
                               default=os.environ.get('OMNICACHE_PATH'),
                               help="path to the a git repository to use as a reference for cloning")
        # return super().AddCommandLineOptions(parserObj)

    def RetrieveCommandLineOptions(self, args):
        """Retrieve command line options from the argparser."""
        self.force = args.force
        self.repo_only = args.repo_only
        self.submodule_only = args.submodule_only
        self.omnicache_path = args.omnicache_path
        self.ignore = args.ignore

        if self.omnicache_path is not None and not Path(self.omnicache_path).exists():
            logging.warning(f'Omnicache path does not exist: {self.omnicache_path}')
            self.omnicache_path = None
        # return super().RetrieveCommandLineOptions(args)

    def GetVerifyCheckRequired(self):
        """Whether to verify the environment or not."""
        return False

    def GetSettingsClass(self):
        """The settings manager that must exist for configuration purposes."""
        return InitializeSettingsManager

    def GetLoggingFileName(self, loggerType):
        """Returns the filename of where the logs for the Edk2Initialize invocable are stored in."""
        return "INITLOG"

    def Go(self):
        """Executes the core functionality of the Edk2Initialize invocable."""
        ws = self.GetWorkspaceRoot()
        git_version = repo_details(ws)['GitVersion']
        version_aggregator.GetVersionAggregator().ReportVersion("Git",
                                                                git_version,
                                                                version_aggregator.VersionTypes.TOOL)
        if not self.submodule_only:
            repo_list = map(lambda repo: repo.as_dict(), self.PlatformSettings.get_required_repositories())
            if self.initialize_repos(ws, repo_list) != 0:
                return -1

        if not self.repo_only:
            submodule_list = self.PlatformSettings.get_required_submodules()
            if self.initialize_submodules(ws, submodule_list) != 0:
                return -1

        return 0

    def initialize_repos(self, ws: str, repo_list: list[Repository]):
        """Resolves all repositories."""
        # If force, delete all repositories.
        if self.force:
            for repo in repo_list:
                repo_path = Path(repo["Path"])
                if repo_path.exists():
                    for file_path in repo_path.rglob('*'):
                        file_path.unlink()
                    repo_path.rmdir()
        try:
            repo_resolver.resolve_all(
                ws,
                repo_list,
                ignore=self.ignore,
                force = self.force,
                update_ok = self.force,
                omnicache_dir=self.omnicache_path
            )
        except Exception as e:
            logging.error("Failed to resolve a repository.")
            logging.error(e)
            return -1

        return 0

    def initialize_submodules(self, ws: str, submodule_list: list[Submodule]):
        """Resolves all submodules."""
        if GetHostInfo().os != "Windows":
            for submodule in submodule_list:
                if submodule.path.find("\\") != -1:
                    logging.error("Windows Path format detected on a non-Windows system. This is not supported.")
                    logging.error(f"    Path: {submodule.path}")
                    logging.error("    Defined at: GetRequiredSubmodules()")
                    return -1

        # If force, clean all submodules
        if self.force:
            try:
                # Clean the workspace
                edk2_logging.log_progress('## Cleaning the root repo')
                clean(ws, ignore_files=[f'Build/{self.GetLoggingFileName("txt")}.txt'])
                edk2_logging.log_progress("Done.\n")
            except InvalidGitRepositoryError:
                logging.error(f"Error when trying to clean {ws}")
                logging.error(f"Invalid Git Repository at {ws}")
                return -1

            # Clean the submodules
            for required_submodule in submodule_list:
                try:
                    submodule_path = os.path.join(ws, required_submodule.path)
                    edk2_logging.log_progress(f'## Cleaning Git Submodule: {required_submodule.path}')
                    submodule_clean(ws, required_submodule)
                    edk2_logging.log_progress('## Done.\n')
                except InvalidGitRepositoryError:
                    logging.error(f"Error when trying to clean {submodule_path}")
                    logging.error(f"Invalid Git Repository at {submodule_path}")
                    return -1
                except ValueError as e:
                    logging.error(f"Error when trying to clean {submodule_path}")
                    logging.error(e)
                    return -1

        # Resolve all of the submodules to the specifed branch and commit. i.e. sync, then update
        for submodule in submodule_list:
            edk2_logging.log_progress(f'## Resolving Git Submodule: {submodule.path}')
            submodule_details = repo_details(os.path.join(ws, submodule.path))

            # Don't update a dirty submodule unless we are forcing.
            if submodule_details['Dirty'] and not self.force:
                logging.info('-- NOTE: Submodule currently exists and appears to have local changes!')
                logging.info('-- Skipping fetch!')
                logging.log(edk2_logging.get_progress_level(), "Done.\n")
                continue
            try:
                # Sync, then Update & Init the submodule
                submodule_resolve(ws, submodule, omnicache_path=self.omnicache_path)
                edk2_logging.log_progress('## Done.\n')
            except InvalidGitRepositoryError:
                logging.error(f"Error when trying to resolve {submodule.path}")
                logging.error(f"Invalid Git Repository at {submodule.path}")
                return -1
            except GitCommandError as e:
                logging.error(f"Error when trying to resolve {submodule.path}")
                logging.error(e)
                return -1

        return 0

def main():
    """Entry point to invoke Edk2Initialize."""
    Edk2Initialize().Invoke()
