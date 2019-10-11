# @file edk2_setup
# updates submodules listed as RequiredS ubmodules in Config file.
##
# Copyright (c) Microsoft Corporation
#
# SPDX-License-Identifier: BSD-2-Clause-Patent
##

import os
import logging
from io import StringIO
from edk2toolext import edk2_logging
from edk2toolext.environment import version_aggregator
from edk2toolext.invocables.edk2_multipkg_aware_invocable import Edk2MultiPkgAwareInvocable
from edk2toolext.invocables.edk2_multipkg_aware_invocable import MultiPkgAwareSettingsInterface
from edk2toollib.utility_functions import RunCmd
from edk2toollib.utility_functions import version_compare


class RequiredSubmodule():

    def __init__(self, path: str, recursive: bool = True):
        '''
        Object to hold necessary information for resolving submodules

        path:   workspace relative path to submodule that must be
                synchronized and updated
        recursive: boolean if recursion should be used in this submodule
        '''
        self.path = path
        self.recursive = recursive


class SetupSettingsManager(MultiPkgAwareSettingsInterface):
    ''' Platform settings will be accessed through this implementation. '''

    def GetActiveScopes(self):
        ''' return tuple containing scopes that should be active for this process '''
        raise NotImplementedError()

    def GetWorkspaceRoot(self):
        ''' return absolute path to the edk2 workspace root '''
        raise NotImplementedError()

    def GetRequiredSubmodules(self):
        ''' return iterable containing RequiredSubmodule objects.
        If no RequiredSubmodules return an empty iterable
        '''
        raise NotImplementedError()

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


class Edk2PlatformSetup(Edk2MultiPkgAwareInvocable):
    ''' Updates git submodules listed in RequiredSubmodules '''

    def AddCommandLineOptions(self, parserObj):
        ''' adds command line options to the argparser '''
        parserObj.add_argument('--force', '--FORCE', '--Force', dest="force", action='store_true', default=False)
        parserObj.add_argument('--omnicache', '--OMNICACHE', '--Omnicache', dest='omnicache_path',
                               default=os.environ.get('OMNICACHE_PATH'))

        super().AddCommandLineOptions(parserObj)

    def RetrieveCommandLineOptions(self, args):
        '''  Retrieve command line options from the argparser '''
        self.force_it = args.force
        self.omnicache_path = args.omnicache_path
        if (self.omnicache_path is not None) and (not os.path.exists(self.omnicache_path)):
            logging.warning(f"Omnicache path set to invalid path: {args.omnicache_Path}")
            self.omnicache_path = None

        super().RetrieveCommandLineOptions(args)

    def GetVerifyCheckRequired(self):
        ''' Will not call self_describing_environment.VerifyEnvironment because it hasn't been set up yet '''
        return False

    def GetSettingsClass(self):
        '''  Providing SetupSettingsManager  '''
        return SetupSettingsManager

    def GetLoggingFileName(self, loggerType):
        return "SETUPLOG"

    def Go(self):
        required_submodules = self.PlatformSettings.GetRequiredSubmodules()
        workspace_path = self.GetWorkspaceRoot()
        # Make sure git is installed
        return_buffer = StringIO()
        RunCmd("git", "--version", outstream=return_buffer, raise_exception_on_nonzero=True)
        git_version = return_buffer.getvalue().strip()
        return_buffer.close()
        version_aggregator.GetVersionAggregator().ReportVersion("Git",
                                                                git_version,
                                                                version_aggregator.VersionTypes.TOOL)
        min_git = "2.11.0"
        # This code is highly specific to the return value of "git version"...
        cur_git = ".".join(git_version.split(' ')[2].split(".")[:3])
        if version_compare(min_git, cur_git) > 0:
            raise RuntimeError("Please upgrade Git! Current version is %s. Minimum is %s." % (cur_git, min_git))

        # Pre-setup cleaning if "--force" is specified.
        if self.force_it:
            try:
                # Clean and reset the main repo.
                edk2_logging.log_progress("## Cleaning the root repo...")
                RunCmd("git", "reset --hard", workingdir=workspace_path,
                       logging_level=logging.DEBUG, raise_exception_on_nonzero=True)
                # Because logging is running right now, we have to skip the files that are open.
                ignore_files = "-e Build/%s.txt -e Build/%s.md" % (self.GetLoggingFileName('txt'),
                                                                   self.GetLoggingFileName('md'))
                RunCmd("git", "clean -xffd %s" % ignore_files, workingdir=workspace_path,
                       logging_level=logging.DEBUG, raise_exception_on_nonzero=True)
                edk2_logging.log_progress("Done.\n")

                # Clean any submodule repos.
                if required_submodules:
                    for required_submodule in required_submodules:
                        edk2_logging.log_progress("## Cleaning Git repository: %s..." % required_submodule.path)
                        required_submodule_path = os.path.normpath(
                            os.path.join(workspace_path, required_submodule.path))
                        RunCmd("git", "reset --hard", workingdir=required_submodule_path,
                               logging_level=logging.DEBUG, raise_exception_on_nonzero=True)
                        RunCmd("git", "clean -xffd", workingdir=required_submodule_path,
                               logging_level=logging.DEBUG, raise_exception_on_nonzero=True)

                        edk2_logging.log_progress("Done.\n")

            except RuntimeError as e:
                logging.error("FAILED!\n")
                logging.error("Error while trying to clean the environment!")
                logging.error(str(e))
                return

        # Grab the remaining Git repos.
        if required_submodules and len(required_submodules) > 0:

            # Git Repos: STEP 1 --------------------------------------
            # Make sure that the repos are all synced.
            try:
                submodule_string = " ".join([x.path for x in required_submodules])
                edk2_logging.log_progress(f"## Syncing Git repositories: {submodule_string}...")
                RunCmd("git", f'submodule sync -- {submodule_string}',
                       workingdir=workspace_path, logging_level=logging.DEBUG, raise_exception_on_nonzero=True)

                edk2_logging.log_progress("Done.\n")
            except RuntimeError as e:
                logging.error("FAILED!\n")
                logging.error("Error while trying to synchronize the environment!")
                logging.error(str(e))
                return

            # Git Repos: STEP 2 --------------------------------------
            # Iterate through all repos and see whether they should be fetched.
            for required_submodule in required_submodules:
                try:
                    edk2_logging.log_progress(f"## Checking Git repository: {required_submodule.path}...")

                    # Git Repos: STEP 2a ---------------------------------
                    # Need to determine whether to skip this repo.
                    required_submodule_path = os.path.normpath(os.path.join(workspace_path, required_submodule.path))
                    skip_repo = False
                    # If the repo exists (and we're not forcing things) make
                    # sure that it's not in a "dirty" state.
                    if os.path.exists(required_submodule_path) and not self.force_it:
                        return_buffer = StringIO()
                        RunCmd("git", 'diff ' + required_submodule.path, outstream=return_buffer,
                               workingdir=workspace_path, logging_level=logging.DEBUG, raise_exception_on_nonzero=True)
                        git_data = return_buffer.getvalue().strip()
                        return_buffer.close()
                        # If anything was returned, we should skip processing the repo.
                        # It is either on a different commit or it has local changes.
                        if git_data != "":
                            logging.info("-- NOTE: Repo currently exists and appears to have local changes!")
                            logging.info("-- Skipping fetch!")
                            skip_repo = True

                    # Git Repos: STEP 2b ---------------------------------
                    # If we're not skipping, grab it.
                    if not skip_repo or self.force_it:
                        logging.info("## Fetching repo.")
                        cmd_string = "submodule update --init"
                        if required_submodule.recursive:
                            cmd_string += " --recursive"
                        cmd_string += " --progress"
                        if self.omnicache_path is not None:
                            cmd_string += " --reference " + self.omnicache_path
                        cmd_string += " " + required_submodule.path
                        RunCmd('git', cmd_string, workingdir=workspace_path,
                               logging_level=logging.DEBUG, raise_exception_on_nonzero=True)

                    edk2_logging.log_progress("Done.\n")

                except RuntimeError as e:
                    logging.error("FAILED!\n")
                    logging.error("Failed to fetch required repository!\n")
                    logging.error(str(e))

        return 0


def main():
    Edk2PlatformSetup().Invoke()
