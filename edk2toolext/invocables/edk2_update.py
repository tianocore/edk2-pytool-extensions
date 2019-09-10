# @file Edk2Update
# Updates external dependencies for project_scope in workspace_path
# as listed in Platform Config file.
##
# Copyright (c) Microsoft Corporation
#
# SPDX-License-Identifier: BSD-2-Clause-Patent
##
import logging
from edk2toolext import edk2_logging
from edk2toolext.environment import self_describing_environment
from edk2toolext.edk2_invocable import Edk2Invocable


class UpdateSettingsManager():
    ''' Platform settings will be accessed through this implementation. '''

    def GetActiveScopes(self):
        ''' get scope '''
        raise NotImplementedError()

    def GetWorkspaceRoot(self):
        ''' get WorkspacePath '''
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


def build_env_changed(build_env, build_env_2):
    ''' return True if build_env has changed '''

    return (build_env.paths != build_env_2.paths) or \
           (build_env.extdeps != build_env_2.extdeps) or \
           (build_env.plugins != build_env_2.plugins)


class Edk2Update(Edk2Invocable):
    ''' Updates dependencies in workspace for active scopes '''

    MAX_RETRY_COUNT = 10

    def PerformUpdate(self):
        (build_env, shell_env) = self_describing_environment.BootstrapEnvironment(
            self.GetWorkspaceRoot(), self.GetActiveScopes())
        self_describing_environment.UpdateDependencies(self.GetWorkspaceRoot(), self.GetActiveScopes())
        return (build_env, shell_env)

    def GetVerifyCheckRequired(self):
        ''' Will not call self_describing_environment.VerifyEnvironment because ext_deps haven't been unpacked yet '''
        return False

    def GetSettingsClass(self):
        '''  Providing UpdateSettingsManger '''
        return UpdateSettingsManager

    def GetLoggingFileName(self, loggerType):
        return "UPDATE_LOG"

    def AddCommandLineOptions(self, parserObj):
        ''' adds command line options to the argparser '''
        # This will parse the packages that we are going to update
        parserObj.add_argument('-p', '--pkg', '--pkg-dir', dest='packageList', type=str,
                               help='Optional - A package or folder you want to update (workspace relative).'
                               'Can list multiple by doing -p <pkg1>,<pkg2> or -p <pkg3> -p <pkg4>',
                               action="append", default=[])
        parserObj.add_argument('-a', '--arch', dest="requested_arch", type=str, default=None,
                               help="Optional - CSV of architecutres requested to update. Example: -a X64,AARCH64")
        parserObj.add_argument('-t', '--target', dest='requested_target', type=str, default=None,
                               help="Optional - CSV of targets requested to update.  Example: -t DEBUG,NOOPT")

    def RetrieveCommandLineOptions(self, args):
        '''  Retrieve command line options from the argparser '''
        packageListSet = set()
        for item in args.packageList:  # Parse out the individual packages
            item_list = item.split(",")
            for indiv_item in item_list:
                indiv_item = indiv_item.replace("\\", "/")  # in case cmd line caller used Windows folder slashes
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

    def InputParametersConfiguredCallback(self):
        ''' This function is called once all the input parameters are collected and can be used to initialize environment '''
        if(len(self.requested_package_list) == 0):
            self.requested_package_list = list(self.PlatformSettings.GetPackagesSupported())
        self.PlatformSettings.SetToPackage(self.requested_package_list)

        if(len(self.requested_architecture_list) == 0):
            self.requested_architecture_list = list(self.PlatformSettings.GetArchitecturesSupported())
        self.PlatformSettings.SetToArchitecture(self.requested_architecture_list)

        if(len(self.requested_target_list) == 0):
            self.requested_target_list = list(self.PlatformSettings.GetTargetsSupported())
        self.PlatformSettings.SetToTarget(self.requested_target_list)

    def Go(self):
        # Get the environment set up.
        RetryCount = 0
        logging.log(edk2_logging.SECTION, "Initial update of environment")

        (build_env_old, shell_env_old) = self.PerformUpdate()
        self_describing_environment.DestroyEnvironment()

        # Loop updating dependencies until there are 0 new dependencies or
        # we have exceeded retry count.  This allows dependencies to carry
        # files that influence the SDE.
        while RetryCount < Edk2Update.MAX_RETRY_COUNT:
            (build_env, shell_env) = self.PerformUpdate()

            if not build_env_changed(build_env, build_env_old):  # check if the environment changed on our last update
                break
            # if the environment has changed, increment the retry count and notify user
            RetryCount += 1
            logging.log(edk2_logging.SECTION,
                        f"Something in the environment changed. Updating environment again. Pass #{RetryCount}")

            build_env_old = build_env
            self_describing_environment.DestroyEnvironment()

        if RetryCount >= Edk2Update.MAX_RETRY_COUNT:
            logging.error(f"We did an update more than {Edk2Update.MAX_RETRY_COUNT} times.")
            logging.error("Please check your dependencies and make sure you don't have any circular ones.")
            return 1
        return 0


def main():
    Edk2Update().Invoke()
