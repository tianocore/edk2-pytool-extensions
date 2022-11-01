# @file ci_build_plugin
# Plugin that supports adding tests or operations to the ci environment
##
# Copyright (c) Microsoft Corporation
#
# SPDX-License-Identifier: BSD-2-Clause-Patent
##
"""Plugin that supports adding tests or operations to the ci environment."""

import os
import logging
from typing import List, Tuple


class ICiBuildPlugin(object):
    """Plugin that supports adding tests or operations to the ci environment."""
    def RunBuildPlugin(self, packagename, Edk2pathObj, pkgconfig, environment, PLM, PLMHelper, tc, output_stream):
        """External function of plugin.

        This function is used to perform the task of the CiBuild Plugin

        Args:
            packagename (str): edk2 path to package (workspace/package path relative)
            Edk2pathObj (Edk2Path): Edk2Path configured with workspace and package path
            pkgconfig (dict): Package config
            environment (EnvConfig): Environment config
            PLM (PluginManager): Plugin manager instance
            PLMHelper (HelperFunctions): Plugin helper object instace
            tc (obj): test case that needs state configured for reporting by plugin
            output_stream (StringIO): output stream from this plugin via logging

        Returns:
            (int): >0 - number of errors found
            (int): 0 - passed successfully
            (int): -1 - skipped for missing prereq
        """
        pass

    def GetTestName(self, packagename: str, environment: object) -> Tuple[str, str]:
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
        pass

    def RunsOnTargetList(self) -> List[str]:
        """Returns a list of edk2 TARGETs that this plugin would like to run on.

        HINT: known target values:
        DEBUG
        RELEASE
        NOOPT
        NO-TARGET

        HINT: If the plugin is not Target specific it should return a list of one element of "NO-TARGET"
        """
        return ["NO-TARGET"]

    def WalkDirectoryForExtension(self, extensionlist: List[str], directory: os.PathLike,
                                  ignorelist: List[str] = None) -> List[os.PathLike]:
        """Walks a file directory recursively for all items ending in certain extension.

        Args:
            extensionlist (List[str]): list of file extensions
            directory (PathLike): absolute path to directory to start looking
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
                        if (ignorelist is not None):
                            for c in ignorelist_lower:
                                if (File.lower().startswith(c)):
                                    ignoreIt = True
                                    break
                        if not ignoreIt:
                            logging.debug(os.path.join(Root, File))
                            returnlist.append(os.path.join(Root, File))

        return returnlist
