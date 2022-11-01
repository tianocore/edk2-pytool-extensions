# @file edk2_ci_setup.py
# Resolves all dependent repos for a CI environment.
#
##
# Copyright (c) Microsoft Corporation
#
# SPDX-License-Identifier: BSD-2-Clause-Patent
##
"""Code that supports CI/CD via the ci_setup invocable.

Contains a CISetupSettingsManager that must be subclassed in a build settings
file. This provides platform specific information to Edk2CiSetup invocable
while allowing the invocable itself to remain platform agnostic.
"""
import os
import logging

from edk2toolext.invocables.edk2_multipkg_aware_invocable import Edk2MultiPkgAwareInvocable
from edk2toolext.invocables.edk2_multipkg_aware_invocable import MultiPkgAwareSettingsInterface
from edk2toolext.environment import repo_resolver


class CiSetupSettingsManager(MultiPkgAwareSettingsInterface):
    """Platform specific settings for Edk2CiSetup.

    Provide information necessary for `stuart_ci_setup.exe` or
    `edk2_ci_setup.py` to successfully execute.

    Example: Example: Overriding CiSetupSettingsManager
        ```python
        from edk2toolext.invocables.edk2_ci_setup import CiSetupSettingsManager
        class CiManager(CiSetupSettingsManager):
            def GetDependencies(self):
                return {
                    "Path": "/Common/MU",
                    "Url":  "https://github.com/Microsoft/mu_tiano_plus.git"
                }
        ```
    """

    def GetDependencies(self):
        """Get any Git Repository Dependendencies.

        This list of repositories will be resolved during the setup step.

        TIP: Optional Override in subclass

        TIP: Return an iterable of dictionary objects with the following fields
        {
            Path: <required> Workspace relative path
            Url: <required> Url of git repo
            Commit: <optional> Commit to checkout of repo
            Branch: <optional> Branch to checkout (will checkout most recent commit in branch)
            Full: <optional> Boolean to do shallow or Full checkout.  (default is False)
            ReferencePath: <optional> Workspace relative path to git repo to use as "reference"
        }
        """
        return []


class Edk2CiBuildSetup(Edk2MultiPkgAwareInvocable):
    """Invocable supporting an iterative multi-package build and test process leveraging CI build plugins.

    Edk2CiBuildSetup sets up the necessary environment for Edk2CiBuild by preparing all necessary submodules.
    """
    def AddCommandLineOptions(self, parser):
        """Adds command line arguments to Edk2CiBuild."""
        parser.add_argument('-ignore', '--ignore-git', dest="git_ignore", action="store_true",
                            help="Whether to ignore errors in the git cloning process", default=False)
        parser.add_argument('--omnicache', '--reference', dest='omnicache_path',
                            default=os.environ.get('OMNICACHE_PATH'))
        parser.add_argument('-force', '--force-git', dest="git_force", action="store_true",
                            help="Whether to force git repos to clone in the git cloning process", default=False)
        parser.add_argument('-update-git', '--update-git', dest="git_update", action="store_true",
                            help="Whether to update git repos as needed in the git cloning process", default=False)
        super().AddCommandLineOptions(parser)

    def RetrieveCommandLineOptions(self, args):
        """Retrieve command line options from the argparser."""
        self.git_ignore = args.git_ignore
        self.git_force = args.git_force
        self.git_update = args.git_update
        self.omnicache_path = args.omnicache_path
        if (self.omnicache_path is not None) and (not os.path.exists(self.omnicache_path)):
            logging.warning(f"Omnicache path set to invalid path: {args.omnicache_path}")
            self.omnicache_path = None

        super().RetrieveCommandLineOptions(args)

    def GetVerifyCheckRequired(self):
        """Will not verify environment."""
        return False

    def GetSettingsClass(self):
        """Returns the CiSetupSettingsManager class.

        WARNING: CiSetupSettingsManager must be subclassed in your platform settings file.
        """
        return CiSetupSettingsManager

    def GetLoggingFileName(self, loggerType):
        """Returns the filename (CISETUP) of where the logs for the Edk2CiBuild invocable are stored in."""
        return "CISETUP"

    def Go(self):
        """Executes the core functionality of the Edk2CiSetup invocable."""
        setup_dependencies = self.PlatformSettings.GetDependencies()
        logging.debug(f"Dependencies list {setup_dependencies}")
        repos = repo_resolver.resolve_all(self.GetWorkspaceRoot(),
                                          setup_dependencies,
                                          ignore=self.git_ignore, force=self.git_force,
                                          update_ok=self.git_update, omnicache_dir=self.omnicache_path)

        logging.info(f"Repo resolver resolved {repos}")

        return 0 if None not in repos else -1


def main():
    """Entry point invoke Edk2CiBuild."""
    Edk2CiBuildSetup().Invoke()
