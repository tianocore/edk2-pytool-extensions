# @file ci_build_plugin
# Plugin that supports adding tests or operations to the ci environment
##
# Copyright (c) Microsoft Corporation
#
# SPDX-License-Identifier: BSD-2-Clause-Patent
##


import os
import logging
from typing import List, Tuple


class ICiBuildPlugin(object):

    ##
    # External function of plugin.  This function is used to perform the task of the CiBuild Plugin
    #
    #   - package is the edk2 path to package.  This means workspace/package path relative.
    #   - edk2path object configured with workspace and packages path
    #   - PkgConfig Object (dict) for the pkg
    #   - EnvConfig Object
    #   - Plugin Manager Instance
    #   - Plugin Helper Obj Instance
    #   - tc - test case that needs state configured for reporting by plugin.
    #   - output_stream the StringIO output stream from this plugin via logging
    #
    #   Returns  >0 : number of errors found
    #             0 : passed successfully
    #            -1 : skipped for missing prereq
    #
    #
    def RunBuildPlugin(self, packagename, Edk2pathObj, pkgconfig, environment, PLM, PLMHelper, tc, output_stream):
        pass

    def GetTestName(self, packagename: str, environment: object) -> Tuple[str, str]:
        ''' Given the package name and configuration provide the caller
            the name of the test case and the class name.  These are both used in logging
            and reporting test status.

            @packagename: String - Package Name
            @environment: EnvDict Object - Environment Dictionary configuration

            @returns tuple of (test case name, test case base class name)
        '''
        pass

    def RunsOnTargetList(self) -> List[str]:
        ''' Returns a list of edk2 TARGETs that this plugin would like to run on

            KNOWN TARGET VALUES:
            DEBUG
            RELEASE
            NOOPT
            NO-TARGET

            If the plugin is not Target specific it should return a list of
            one element of "NO-TARGET"
        '''
        return ["NO-TARGET"]

    def WalkDirectoryForExtension(self, extensionlist: List[str], directory: os.PathLike,
                                  ignorelist: List[str] = None) -> List[os.PathLike]:
        ''' Walks a file directory recursively for all items ending in certain extension

            @extensionlist: List[str] list of file extensions
            @directory: Path - absolute path to directory to start looking
            @ignorelist: List[str] or None.  optional - default is None: a list of case insensitive filenames to ignore

            @returns a List of file paths to matching files
        '''
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
                        if(ignorelist is not None):
                            for c in ignorelist_lower:
                                if(File.lower().startswith(c)):
                                    ignoreIt = True
                                    break
                        if not ignoreIt:
                            logging.debug(os.path.join(Root, File))
                            returnlist.append(os.path.join(Root, File))

        return returnlist
