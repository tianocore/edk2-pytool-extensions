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

from edk2toolext.edk2_invocable import Edk2Invocable
from edk2toolext.environment import repo_resolver


class CiSetupSettingsManager():
    ''' Platform settings will be accessed through this implementation. '''

    def GetDependencies(self):
        raise NotImplementedError()

    def GetWorkspaceRoot(self):
        ''' get WorkspacePath '''
        raise NotImplementedError()

    def GetOmnicachePath(self):
        ''' Optionally point to omnicache path '''
        pass

    def AddCommandLineOptions(self, parserObj):
        ''' Implement in subclass to add command line options to the argparser '''
        pass

    def RetrieveCommandLineOptions(self, args):
        '''  Implement in subclass to retrieve command line options from the argparser '''
        pass

    def GetLoggingLevel(self, loggerType):
        ''' Get the logging level for a given type
        base == lowest logging level supported
        con  == Screen logging
        txt  == plain text file logging
        md   == markdown file logging
        '''
        pass


def merge_config(mu_config, pkg_config, descriptor={}):
    plugin_name = ""
    config = dict()
    if "module" in descriptor:
        plugin_name = descriptor["module"]
    if "config_name" in descriptor:
        plugin_name = descriptor["config_name"]

    if plugin_name == "":
        return config

    if plugin_name in mu_config:
        config.update(mu_config[plugin_name])

    if plugin_name in pkg_config:
        config.update(pkg_config[plugin_name])

    return config


class Edk2CiBuildSetup(Edk2Invocable):

    def AddCommandLineOptions(self, parser):
        parser.add_argument('-ignore', '--ignore-git', dest="git_ignore", action="store_true",
                            help="Whether to ignore errors in the git cloing process", default=False)
        parser.add_argument('--omnicache', '--reference', dest='omnicache_path',
                            default=os.environ.get('OMNICACHE_PATH'))
        parser.add_argument('-force', '--force-git', dest="git_force", action="store_true",
                            help="Whether to force git repos to clone in the git cloing process", default=False)
        parser.add_argument('-update-git', '--update-git', dest="git_update", action="store_true",
                            help="Whether to update git repos as needed in the git cloing process", default=False)

    def GetVerifyCheckRequired(self):
        ''' Will not verify environemnt '''
        return False

    def RetrieveCommandLineOptions(self, args):
        '''  Retrieve command line options from the argparser '''
        self.git_ignore = args.git_ignore
        self.omnicache_path = args.omnicache_path
        self.git_force = args.git_force
        self.git_update = args.git_update

    def GetSettingsClass(self):
        return CiSetupSettingsManager

    def GetLoggingFileName(self, loggerType):
        return "CISETUP"

    # get_mu_config
    def Go(self):
        # Parse command line arguments

        omnicache_path = self.omnicache_path
        try:
            omnicache_path = self.PlatformSettings.GetOmnicachePath()
        except:
            pass

        ret = repo_resolver.resolve_all(self.GetWorkspaceRoot(),
                                        self.PlatformSettings.GetDependencies(),
                                        ignore=self.git_ignore, force=self.git_force,
                                        update_ok=self.git_update, omnicache_dir=omnicache_path)

        logging.info(f"Repo resolver resolved {ret}")

        return 0


def main():
    Edk2CiBuildSetup().Invoke()
