# @file ci_build_plugin
# Plugin that supports adding tests or operations to the ci environment
##
# Copyright (c) Microsoft Corporation
#
# SPDX-License-Identifier: BSD-2-Clause-Patent
##
"""Plugin that supports adding tests or operations to the ci environment."""

import logging
import os
from typing import TextIO

from edk2toollib.log.junit_report_format import JunitReportTestCase
from edk2toollib.uefi.edk2.path_utilities import Edk2Path

from edk2toolext.environment.plugin_manager import PluginManager
from edk2toolext.environment.plugintypes.uefi_helper_plugin import HelperFunctions
from edk2toolext.environment.var_dict import VarDict


class ICiBuildPlugin(object):
    """Plugin that supports adding tests or operations to the ci environment."""

    def RunBuildPlugin(
        self,
        packagename: str,
        Edk2pathObj: Edk2Path,
        pkgconfig: dict,
        environment: VarDict,
        PLM: PluginManager,
        PLMHelper: HelperFunctions,
        tc: JunitReportTestCase,
        output_stream: TextIO,
    ) -> int:
        """External function of plugin.

        This function is used to perform the task of the CiBuild Plugin

        Args:
            packagename (str): edk2 path to package (workspace/package path relative)
            Edk2pathObj (Edk2Path): Edk2Path configured with workspace and package path
            pkgconfig (dict): Package config
            environment (VarDict): Environment config
            PLM (PluginManager): Plugin manager instance
            PLMHelper (HelperFunctions): Plugin helper object instace
            tc (obj): test case that needs state configured for reporting by plugin
            output_stream (StringIO): output stream from this plugin via logging

        Returns:
            (int): >0 - number of errors found
            (int): 0 - passed successfully
            (int): -1 - skipped for missing prereq
        """

    def GetTestName(self, packagename: str, environment: object) -> tuple[str, str]:
        """Provides the test case and class name.

        Given the package name and configuration provide the caller
        the name of the test case and the class name.  These are both used in logging
        and reporting test status.

        Args:
            packagename (str): Package Name
            environment (EnvDict): Environment Dictionary configuration

        Returns:
            (Tuple[str, str]): (test case name, test case base class name)
        """

    def RunsOnTargetList(self) -> list[str]:
        """Returns a list of edk2 TARGETs that this plugin would like to run on.

        !!! note "Known target values"
            DEBUG, RELEASE, NOOPT, NO-TARGET

        !!! hint
            If the plugin is not Target specific it should return a list of one element of "NO-TARGET"
        """
        return ["NO-TARGET"]

    def WalkDirectoryForExtension(
        self, extensionlist: list[str], directory: os.PathLike, ignorelist: list[str] = None
    ) -> list[os.PathLike]:
        """Walks a file directory recursively for all items ending in certain extension.

        Args:
            extensionlist (List[str]): list of file extensions
            directory (os.PathLike): absolute path to directory to start looking
            ignorelist (List[str]): a list of case insensitive filenames to ignore (Optional)

        Returns:
            (List): file paths to matching files
        """
        if not isinstance(extensionlist, list):
            logging.critical("Expected list but got " + str(type(extensionlist)))
            raise TypeError("extensionlist must be a list")

        if directory is None:
            logging.critical("No directory given")
            raise TypeError("directory is None")

        if not os.path.isabs(directory):
            logging.critical("Directory not abs path")
            raise ValueError("directory is not an absolute path")

        if not os.path.isdir(directory):
            logging.critical("Invalid find directory to walk")
            raise ValueError("directory is not a valid directory path")

        if ignorelist is not None:
            if not isinstance(ignorelist, list):
                logging.critical("Expected list but got " + str(type(ignorelist)))
                raise TypeError("ignorelist must be a list")

            ignorelist_lower = list()
            for item in ignorelist:
                ignorelist_lower.append(item.lower())

        extensionlist_lower = list()
        for item in extensionlist:
            extensionlist_lower.append(item.lower())

        returnlist = list()
        for Root, Dirs, Files in os.walk(directory):
            for File in Files:
                for Extension in extensionlist_lower:
                    if File.lower().endswith(Extension):
                        ignoreIt = False
                        if ignorelist is not None:
                            for c in ignorelist_lower:
                                if File.lower().startswith(c):
                                    ignoreIt = True
                                    break
                        if not ignoreIt:
                            returnlist.append(os.path.join(Root, File))

        return returnlist
