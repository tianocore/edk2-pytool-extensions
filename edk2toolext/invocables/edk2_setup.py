# @file edk2_setup
# updates submodules listed as Required Submodules in Config file.
##
# Copyright (c) Microsoft Corporation
#
# SPDX-License-Identifier: BSD-2-Clause-Patent
##
"""Code that updates required submodules.

Contains a SetupSettingsManager that must be subclassed in a build settings
file. This provides platform specific information to Edk2PlatformSetup invocable
while allowing the invocable itself to remain platform agnostic.
"""

import argparse
import logging
import os
import timeit
from typing import Iterable

from edk2toollib.utility_functions import GetHostInfo

from edk2toolext import edk2_logging
from edk2toolext.environment import version_aggregator
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


class RequiredSubmodule:
    """A class containing information about a git submodule."""

    def __init__(self, path: str, recursive: bool = True) -> None:
        """Object to hold necessary information for resolving submodules.

        Args:
            path (str): workspace relative path to submodule that must be
                synchronized and updated
            recursive (bool): if recursion should be used in this submodule
        """
        self.path = path
        self.recursive = recursive


class SetupSettingsManager(MultiPkgAwareSettingsInterface):
    """Platform specific settings for Edk2PlatformSetup.

    Provides information necessary for `stuart_setup.exe` or `edk2_setup.py`
    to successfully execute for a given platform.

    !!! example "Example of Overriding SetupSettingsManager"
        ```python
        from edk2toolext.invocables.edk2_setup import SetupSettingsManager, RequiredSubmodule
        class PlatformManager(SetupSettingsManager):
            def GetRequiredSubmodules(self) -> Iterable[RequiredSubmodule]:
                return [RequiredSubmodule('Common/MU', True)]
        ```
    """

    def GetRequiredSubmodules(self) -> Iterable[RequiredSubmodule]:
        """Provides a list of required git submodules.

        These submodules are those that must be setup for the platform
        to successfully build.

        !!! tip
            Optional Override in a subclass

        Returns:
            A Iterable of required submodules, or an empty Iterable
        """
        return []


class Edk2PlatformSetup(Edk2MultiPkgAwareInvocable):
    """Invocable that updates git submodules listed in RequiredSubmodules."""

    def AddCommandLineOptions(self, parserObj: argparse.ArgumentParser) -> None:
        """Adds command line options to the argparser."""
        parserObj.add_argument("--force", "--FORCE", "--Force", dest="force", action="store_true", default=False)
        parserObj.add_argument(
            "--omnicache", "--OMNICACHE", "--Omnicache", dest="omnicache_path", default=os.environ.get("OMNICACHE_PATH")
        )

        super().AddCommandLineOptions(parserObj)

    def RetrieveCommandLineOptions(self, args: argparse.Namespace) -> None:
        """Retrieve command line options from the argparser."""
        self.force_it = args.force
        self.omnicache_path = args.omnicache_path
        if (self.omnicache_path is not None) and (not os.path.exists(self.omnicache_path)):
            logging.warning(f"Omnicache path set to invalid path: {args.omnicache_path}")
            self.omnicache_path = None

        super().RetrieveCommandLineOptions(args)

    def GetVerifyCheckRequired(self) -> bool:
        """Will not call self_describing_environment.VerifyEnvironment because it hasn't been set up yet."""
        return False

    def GetSettingsClass(self) -> type:
        """Returns the SetupSettingsManager class.

        !!! warning
            SetupSettingsManager must be subclassed in your platform settings file.
        """
        return SetupSettingsManager

    def GetLoggingFileName(self, loggerType: str) -> str:
        """Returns the filename (SETUPLOG) of where the logs for the Edk2CiBuild invocable are stored in."""
        return "SETUPLOG"

    def Go(self) -> int:
        """Executes the core functionality of the Edk2PlatformSetup invocable."""
        full_start_time = timeit.default_timer()

        required_submodules = self.PlatformSettings.GetRequiredSubmodules()

        # Return clear error if submodules are a windows format on a non-windows system
        # This will cause errors with git commands and produces ugly errors.
        if GetHostInfo().os != "Windows":
            for submodule in required_submodules:
                if submodule.path.find("\\") != -1:
                    logging.error("Windows Path format detected on a non-Windows system. This is not supported.")
                    logging.error(f"    Path: {submodule.path}")
                    logging.error("    Defined at: GetRequiredSubmodules()")
                    return -1

        workspace_path = self.GetWorkspaceRoot()

        details = repo_details(workspace_path)
        git_version = details["GitVersion"]

        version_aggregator.GetVersionAggregator().ReportVersion(
            "Git", git_version, version_aggregator.VersionTypes.TOOL
        )

        # Pre-setup cleaning if "--force" is specified.
        if self.force_it:
            try:
                # Clean the workspace
                edk2_logging.log_progress("## Cleaning the root repo")
                clean(workspace_path, ignore_files=[f"Build/{self.GetLoggingFileName('txt')}.txt"])
                edk2_logging.log_progress("Done.\n")
            except InvalidGitRepositoryError:
                logging.error(f"Error when trying to clean {workspace_path}")
                logging.error(f"Invalid Git Repository at {workspace_path}")
                return -1

            # Clean the submodules
            for required_submodule in required_submodules:
                try:
                    submodule_path = os.path.join(workspace_path, required_submodule.path)
                    edk2_logging.log_progress(f"## Cleaning Git Submodule: {required_submodule.path}")
                    submodule_clean(workspace_path, required_submodule)
                    edk2_logging.log_progress("## Done.\n")
                except InvalidGitRepositoryError:
                    logging.error(f"Error when trying to clean {submodule_path}")
                    logging.error(f"Invalid Git Repository at {submodule_path}")
                    return -1
                except ValueError as e:
                    logging.error(f"Error when trying to clean {submodule_path}")
                    logging.error(e)
                    return -1

        # Resolve all of the submodules to the specifed branch and commit. i.e. sync, then update
        for submodule in required_submodules:
            edk2_logging.log_progress(f"## Resolving Git Submodule: {submodule.path}")
            submodule_details = repo_details(os.path.join(workspace_path, submodule.path))

            # Don't update a dirty submodule unless we are forcing.
            if submodule_details["Dirty"] and not self.force_it:
                logging.info("-- NOTE: Submodule currently exists and appears to have local changes!")
                logging.info("-- Skipping fetch!")
                logging.log(edk2_logging.get_progress_level(), "Done.\n")
                continue
            try:
                # Sync, then Update & Init the submodule
                submodule_resolve(workspace_path, submodule, omnicache_path=self.omnicache_path)
                edk2_logging.log_progress("## Done.\n")
            except InvalidGitRepositoryError:
                logging.error(f"Error when trying to resolve {submodule.path}")
                logging.error(f"Invalid Git Repository at {submodule.path}")
                return -1
            except GitCommandError as e:
                logging.error(f"Error when trying to resolve {submodule.path}")
                logging.error(e)
                return -1

        edk2_logging.perf_measurement("Complete Setup", timeit.default_timer() - full_start_time)

        return 0


def main() -> None:
    """Entry point to invoke Edk2PlatformSetup."""
    Edk2PlatformSetup().Invoke()
