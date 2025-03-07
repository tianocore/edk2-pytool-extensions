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
"""An intermediate class that supports a multi-package aware invocable process.

Provides two main classes, the MultiPkgAwareSettingsInterface and the
Edk2MultiPkgAwareInvocable that act as an intermediate class that other
invocables that require a multi-package aware invocable process. These classes
should only be subclassed if a new invocable is being developed. Any
Edk2MultiPkgAwareInvocable should be platform agnostic and work for any
platform. Platform specific data is provided via the
MultiPkgAwareSettingsInterface
"""

import argparse
from typing import Iterable

from edk2toolext.edk2_invocable import Edk2Invocable, Edk2InvocableSettingsInterface


class MultiPkgAwareSettingsInterface(Edk2InvocableSettingsInterface):
    """Settings to support Multi-Pkg functionality.

    This is an interface definition only to show which functions are required
    to be implemented and which functions can be implemented.

    !!! example " Example of Overriding MultiPkgAwareSettingsInterface"
        ``` python
        import os
        import logging
        import argparse
        from typing import Iterable, Tuple
        from edk2toolext.edk2_multipkg_aware_invocable import MultiPkgAwareSettingsInterface
        class NewInvocableSettingsManager(MultiPkgAwareSettingsInterface):

            def GetPackagesSupported(self):
                return ("PlatformPkg",)

            def GetArchitecturesSupported(self):
                return ("IA32","X64")

            def GetTargetsSupported(self):
                return ("TARGET", "RELEASE")

            def SetPackages(self, list_of_requested_packages):

                if len(filter(lambda pkg: pkg in self.GetPackagesSupported(), list_of_requested_packages)) !=
                   len(list_of_requested_packages):
                   raise Exception("Requested Packages contains unsupported Package")
                else:
                    self.pkgs = list_of_requested_packages

            def SetArchitectures(self, list_of_requested_architectures):
                if list_of_requested_architectures != self.GetPackagesSupported():
                    raise Exception("Only Support IA32,X64 combination")
            def SetTargets(self, list_of_requested_targets):
                if list_of_requested_targets != self.GetArchitecturesSupported():
                    raise Exception("Only Support "TARGET", "RELEASE combination")
        ```

    !!! warning
        This interface should not be subclassed directly unless creating a new invocable type. Override these
        methods as a part of other subclasses invocable settings managers such as SetupSettingsManager, etc.
    """

    # ####################################################################################### #
    #                           Supported Values and Defaults                                 #
    # ####################################################################################### #
    def GetPackagesSupported(self) -> Iterable[str]:
        """Returns an iterable of edk2 packages supported by this build.

        !!! tip
            Required Override in a subclass

        Returns:
            (Iterable): edk2 packages

        Note:
            packages should be relative to workspace or package path
        """
        raise NotImplementedError()

    def GetArchitecturesSupported(self) -> Iterable[str]:
        """Returns an iterable of edk2 architectures supported by this build.

        !!! tip
            Required Override in a subclass

        Returns:
            (Iterable): architectures (X64, I32, etc.)
        """
        raise NotImplementedError()

    def GetTargetsSupported(self) -> Iterable[str]:
        """Returns an iterable of edk2 target tags supported by this build.

        !!! tip
            Required Override in a subclass

        Returns:
            (Iterable): targets (DEBUG, RELEASE, etc)
        """
        raise NotImplementedError()

    # ####################################################################################### #
    #                     Verify and Save requested Config                                    #
    # ####################################################################################### #
    def SetPackages(self, list_of_requested_packages: list) -> None:
        """Confirms the requested package list is valid.

        !!! tip
            Optional Override in a subclass

        Args:
            list_of_requested_packages (list[str]): packages to be built

        Raises:
            Exception: A requested package is not supported
        """

    def SetArchitectures(self, list_of_requested_architectures: list) -> None:
        """Confirms the requested architecture list is valid.

        !!! tip
            Optional Override in a subclass

        Args:
            list_of_requested_architectures (list[str]): architectures to be built

        Raises:
            Exception: A requested architecture is not supported
        """

    def SetTargets(self, list_of_requested_target: list) -> None:
        """Confirms the requested target list is valid.

        !!! tip
            Optional Override in a subclass

        Args:
            list_of_requested_target (list[str]): targets to use

        Raises:
            Exception: A requested target is not supported
        """


class Edk2MultiPkgAwareInvocable(Edk2Invocable):
    """Base class for Multi-Pkg aware invocable.

    Attributes:
        requested_architecture_list (list): requested architectures to build
        requested_package_list (list): requested packages to build
        requested_target_list (list): requested targets to use

    !!! tip
        Checkout Edk2Invocable Attributes to find any additional attributes that might exist.

    !!! warning
        This invocable should only be subclassed if creating a new invocable
    """

    def __init__(self) -> None:
        """Initializes the Invocable."""
        self.requested_architecture_list = []
        self.requested_package_list = []
        self.requested_target_list = []
        super().__init__()

    def AddCommandLineOptions(self, parserObj: argparse.ArgumentParser) -> None:
        """Adds command line options to the argparser."""
        # This will parse the packages that we are going to update
        pkg_options = ""
        arch_options = ""
        target_options = ""
        if self.PlatformSettings:
            pkg_options = f" \n[{','.join(self.PlatformSettings.GetPackagesSupported())}]"
            arch_options = f" \n[{','.join(self.PlatformSettings.GetArchitecturesSupported())}]"
            target_options = f" \n[{','.join(self.PlatformSettings.GetTargetsSupported())}]"

        parserObj.add_argument(
            "-p",
            "--pkg",
            "--pkg-dir",
            dest="packageList",
            type=str,
            help=f"CSV of EDKII packages / folder containing packages to operate on. {pkg_options}",
            action="append",
            default=[],
        )
        parserObj.add_argument(
            "-a",
            "--arch",
            dest="requested_arch",
            type=str,
            default=None,
            help=f"CSV of architectures to operate on.{arch_options}",
        )
        parserObj.add_argument(
            "-t",
            "--target",
            dest="requested_target",
            type=str,
            default=None,
            help=f"CSV of targets to operate on.{target_options}",
        )

    def RetrieveCommandLineOptions(self, args: argparse.Namespace) -> None:
        """Retrieve command line options from the argparser ."""
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

    def InputParametersConfiguredCallback(self) -> None:
        """Initializes the environment once input parameters are collected."""
        if len(self.requested_package_list) == 0:
            self.requested_package_list = list(self.PlatformSettings.GetPackagesSupported())
        self.PlatformSettings.SetPackages(self.requested_package_list)

        if len(self.requested_architecture_list) == 0:
            self.requested_architecture_list = list(self.PlatformSettings.GetArchitecturesSupported())
        self.PlatformSettings.SetArchitectures(self.requested_architecture_list)

        if len(self.requested_target_list) == 0:
            self.requested_target_list = list(self.PlatformSettings.GetTargetsSupported())
        self.PlatformSettings.SetTargets(self.requested_target_list)
