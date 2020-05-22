# @file edk2_multipkg_aware_invocable
# An intermediate class that supports a multi-package aware
# invocable process.
#
# Add cmdline parameter handling, a base settings manager class,
# and a Callback.
#
##
# Copyright (c) Microsoft Corporation
#
# SPDX-License-Identifier: BSD-2-Clause-Patent
##
from edk2toolext.edk2_invocable import Edk2Invocable, Edk2InvocableSettingsInterface


class MultiPkgAwareSettingsInterface(Edk2InvocableSettingsInterface):
    ''' Settings to support Multi-Pkg functionality.
        This is an interface definition only
        to show which functions are required to be implemented
        and which functions can be implemented.
     '''

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
    def SetPackages(self, list_of_requested_packages):
        ''' Confirm the requests package list is valid and configure SettingsManager
        to build only the requested packages.

        Raise Exception if a requested_package is not supported
        '''
        pass

    def SetArchitectures(self, list_of_requested_architectures):
        ''' Confirm the requests architecture list is valid and configure SettingsManager
        to run only the requested architectures.

        Raise Exception if a requested_architecture is not supported
        '''
        pass

    def SetTargets(self, list_of_requested_target):
        ''' Confirm the requests target list is valid and configure SettingsManager
        to run only the requested targets.

        Raise Exception if a requested_target is not supported
        '''
        pass


class Edk2MultiPkgAwareInvocable(Edk2Invocable):
    ''' Base class for Multi-Pkg aware invocable '''

    def __init__(self):
        self.requested_architecture_list = []
        self.requested_package_list = []
        self.requested_target_list = []
        super().__init__()

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
            for individual_item in item_list:
                # in case cmd line caller used Windows folder slashes
                individual_item = individual_item.replace("\\", "/").rstrip("/")
                packageListSet.add(individual_item.strip())
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
        ''' This function is called once all the input parameters are collected
            and can be used to initialize environment
        '''
        if(len(self.requested_package_list) == 0):
            self.requested_package_list = list(self.PlatformSettings.GetPackagesSupported())
        self.PlatformSettings.SetPackages(self.requested_package_list)

        if(len(self.requested_architecture_list) == 0):
            self.requested_architecture_list = list(self.PlatformSettings.GetArchitecturesSupported())
        self.PlatformSettings.SetArchitectures(self.requested_architecture_list)

        if(len(self.requested_target_list) == 0):
            self.requested_target_list = list(self.PlatformSettings.GetTargetsSupported())
        self.PlatformSettings.SetTargets(self.requested_target_list)
