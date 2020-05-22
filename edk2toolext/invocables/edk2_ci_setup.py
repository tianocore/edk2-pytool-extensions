# @file edk2_ci_setup.py
# Resolves all dependent repos for a CI environment.
#
##
# Copyright (c) Microsoft Corporation
#
# SPDX-License-Identifier: BSD-2-Clause-Patent
##
import os
import logging

from edk2toolext.invocables.edk2_multipkg_aware_invocable import Edk2MultiPkgAwareInvocable
from edk2toolext.invocables.edk2_multipkg_aware_invocable import MultiPkgAwareSettingsInterface
from edk2toolext.environment import repo_resolver


class CiSetupSettingsManager(MultiPkgAwareSettingsInterface):
    ''' Platform settings will be accessed through this implementation. '''

    def GetDependencies(self):
        ''' Return Git Repository Dependendencies
        This list of repositories will be resolved during the setup step.

        Return an iterable of dictionary objects with the following fields
        {
            Path: <required> Workspace relative path
            Url: <required> Url of git repo
            Commit: <optional> Commit to checkout of repo
            Branch: <optional> Branch to checkout (will checkout most recent commit in branch)
            Full: <optional> Boolean to do shallow or Full checkout.  (default is False)
            ReferencePath: <optional> Workspace relative path to git repo to use as "reference"
        }
        '''
        return []


class Edk2CiBuildSetup(Edk2MultiPkgAwareInvocable):

    def AddCommandLineOptions(self, parser):
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
        '''  Retrieve command line options from the argparser '''
        self.git_ignore = args.git_ignore
        self.git_force = args.git_force
        self.git_update = args.git_update
        self.omnicache_path = args.omnicache_path
        if (self.omnicache_path is not None) and (not os.path.exists(self.omnicache_path)):
            logging.warning(f"Omnicache path set to invalid path: {args.omnicache_Path}")
            self.omnicache_path = None

        super().RetrieveCommandLineOptions(args)

    def GetVerifyCheckRequired(self):
        ''' Will not verify environment '''
        return False

    def GetSettingsClass(self):
        return CiSetupSettingsManager

    def GetLoggingFileName(self, loggerType):
        return "CISETUP"

    def Go(self):

        ret = repo_resolver.resolve_all(self.GetWorkspaceRoot(),
                                        self.PlatformSettings.GetDependencies(),
                                        ignore=self.git_ignore, force=self.git_force,
                                        update_ok=self.git_update, omnicache_dir=self.omnicache_path)

        logging.info(f"Repo resolver resolved {ret}")

        return 0


def main():
    Edk2CiBuildSetup().Invoke()
