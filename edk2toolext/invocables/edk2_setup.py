# @file edk2_setup
# updates submodules listed as REQUIRED_REPOS in Config file.
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
from edk2toolext.edk2_invocable import Edk2Invocable
from edk2toollib.utility_functions import RunCmd
from edk2toollib.utility_functions import version_compare


class SetupSettingsManager():
    ''' Platform settings will be accessed through this implementation. '''

    def GetActiveScopes(self):
        ''' get scope '''
        raise NotImplementedError()

    def GetWorkspaceRoot(self):
        ''' get WorkspacePath '''
        raise NotImplementedError()

    def GetRequiredRepos(self):
        ''' get required repos '''
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

    # ####################################################################################### #
    #                           Supported Values and Defaults                                 #
    # ####################################################################################### #
    def GetPackagesSupported(self):
        ''' return iterable of edk2 packages supported by this build.
        These should be edk2 workspace relative paths '''
        raise NotImplementedError()

    def GetArchitecturesSupported(self):
        ''' return iterable of edk2 architectures supported by this build '''
        raise NotImplementedError()

    def GetTargetsSupported(self):
        ''' return iterable of edk2 target tags supported by this build '''
        raise NotImplementedError()

    # ####################################################################################### #
    #                     Verify and Save requested Config                                    #
    # ####################################################################################### #
    def SetToPackage(self, list_of_requested_packages):
        ''' Confirm the requests package list is valid and configure SettingsManager
        to build only the requested packages.

        Raise Exception if a requested_package is not supported
        '''
        pass

    def SetToArchitecture(self, list_of_requested_architectures):
        ''' Confirm the requests architecture list is valid and configure SettingsManager
        to run only the requested architectures.

        Raise Exception if a list_of_requested_architectures is not supported
        '''
        pass

    def SetToTarget(self, list_of_requested_target):
        ''' Confirm the requests target list is valid and configure SettingsManager
        to run only the requested targets.

        Raise Exception if a requested_target is not supported
        '''
        pass


class Edk2PlatformSetup(Edk2Invocable):
    ''' Updates git submodules listed in required_repos '''

    def AddCommandLineOptions(self, parserObj):
        ''' adds command line options to the argparser '''
        parserObj.add_argument('--force', '--FORCE', '--Force', dest="force", action='store_true', default=False)
        parserObj.add_argument('--omnicache', '--OMNICACHE', '--Omnicache', dest='omnicache_path',
                               default=os.environ.get('OMNICACHE_PATH'))
        # This will parse the packages that we are going to build
        parserObj.add_argument('-p', '--pkg', '--pkg-dir', dest='packageList', type=str,
                               help='Optional - A package or folder you want to setup (workspace relative).'
                               'Can list multiple by doing -p <pkg1>,<pkg2> or -p <pkg3> -p <pkg4>',
                               action="append", default=[])
        parserObj.add_argument('-a', '--arch', dest="requested_arch", type=str, default=None,
                               help="Optional - CSV of architecutres requested to Setup. Example: -a X64,AARCH64")
        parserObj.add_argument('-t', '--target', dest='requested_target', type=str, default=None,
                               help="Optional - CSV of targets requested to Setup.  Example: -t DEBUG,NOOPT")

    def RetrieveCommandLineOptions(self, args):
        '''  Retrieve command line options from the argparser '''
        self.force_it = args.force
        self.omnicache_path = args.omnicache_path

        packageListSet = set()
        for item in args.packageList:  # Parse out the individual packages
            item_list = item.split(",")
            for indiv_item in item_list:
                indiv_item = indiv_item.replace("\\", "/")  # in case cmdline caller used Windows folder slashes
                packageListSet.add(indiv_item.strip())
        self.requested_package_list = list(packageListSet)

        if args.requested_arch is not None:
            self.requested_architecture_list = args.requested_arch.upper().split(",")
        else:
            self.requested_architecture_list = []

        if args.requested_target is not None:
            self.requested_target_list = args.requested_target.upper().split(",")
        else:
            self.requested_target_list = []

    def InputParametersConfigured(self):
        ''' Do any necessary work once all the input parameters are configured.
            Notify settings manager of Requested packages, arch, and targets '''
        if(len(self.requested_package_list) == 0):
            self.requested_package_list = list(self.PlatformSettings.GetPackagesSupported())
        self.PlatformSettings.SetToPackage(self.requested_package_list)

        if(len(self.requested_architecture_list) == 0):
            self.requested_architecture_list = list(self.PlatformSettings.GetArchitecturesSupported())
        self.PlatformSettings.SetToArchitecture(self.requested_architecture_list)

        if(len(self.requested_target_list) == 0):
            self.requested_target_list = list(self.PlatformSettings.GetTargetsSupported())
        self.PlatformSettings.SetToTarget(self.requested_target_list)

    def GetVerifyCheckRequired(self):
        ''' Will not call self_describing_environment.VerifyEnvironment because it hasn't been set up yet '''
        return False

    def GetSettingsClass(self):
        '''  Providing SetupSettingsManager  '''
        return SetupSettingsManager

    def GetLoggingFileName(self, loggerType):
        return "SETUPLOG"

    def Go(self):
        required_repos = self.PlatformSettings.GetRequiredRepos()
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
                if required_repos:
                    for required_repo in required_repos:
                        edk2_logging.log_progress("## Cleaning Git repository: %s..." % required_repo)
                        required_repo_path = os.path.normpath(os.path.join(workspace_path, required_repo))
                        RunCmd("git", "reset --hard", workingdir=required_repo_path,
                               logging_level=logging.DEBUG, raise_exception_on_nonzero=True)
                        RunCmd("git", "clean -xffd", workingdir=required_repo_path,
                               logging_level=logging.DEBUG, raise_exception_on_nonzero=True)

                        edk2_logging.log_progress("Done.\n")

            except RuntimeError as e:
                logging.error("FAILED!\n")
                logging.error("Error while trying to clean the environment!")
                logging.error(str(e))
                return

        # Grab the remaining Git repos.
        if required_repos:
            # Git Repos: STEP 1 --------------------------------------
            # Make sure that the repos are all synced.
            try:
                edk2_logging.log_progress("## Syncing Git repositories: %s..." % ", ".join(required_repos))
                RunCmd("git", 'submodule sync -- ' + " ".join(required_repos),
                       workingdir=workspace_path, logging_level=logging.DEBUG, raise_exception_on_nonzero=True)

                edk2_logging.log_progress("Done.\n")
            except RuntimeError as e:
                logging.error("FAILED!\n")
                logging.error("Error while trying to synchronize the environment!")
                logging.error(str(e))
                return

            # Git Repos: STEP 2 --------------------------------------
            # Iterate through all repos and see whether they should be fetched.
            for required_repo in required_repos:
                try:
                    edk2_logging.log_progress("## Checking Git repository: %s..." % required_repo)

                    # Git Repos: STEP 2a ---------------------------------
                    # Need to determine whether to skip this repo.
                    required_repo_path = os.path.normpath(os.path.join(workspace_path, required_repo))
                    skip_repo = False
                    # If the repo exists (and we're not forcing things) make
                    # sure that it's not in a "dirty" state.
                    if os.path.exists(required_repo_path) and not self.force_it:
                        return_buffer = StringIO()
                        RunCmd("git", 'diff ' + required_repo, outstream=return_buffer, workingdir=workspace_path,
                               logging_level=logging.DEBUG, raise_exception_on_nonzero=True)
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
                        cmd_string = "submodule update --init --recursive --progress"
                        if self.omnicache_path is not None:
                            cmd_string += " --reference " + self.omnicache_path
                        cmd_string += " " + required_repo
                        RunCmd('git', cmd_string, workingdir=workspace_path,
                               logging_level=logging.DEBUG, raise_exception_on_nonzero=True)

                    edk2_logging.log_progress("Done.\n")

                except RuntimeError as e:
                    logging.error("FAILED!\n")
                    logging.error("Failed to fetch required repository!\n")
                    logging.error(str(e))

        return 0

        # TODO: Install any certs any other things that might be required.


def main():
    Edk2PlatformSetup().Invoke()
