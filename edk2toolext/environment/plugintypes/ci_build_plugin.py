# @file ci_build_plugin
# Plugin that supports adding tests or operations to the ci environment
##
# Copyright (c) Microsoft Corporation
#
# SPDX-License-Identifier: BSD-2-Clause-Patent
##


import os
import logging


class ICiBuildPlugin(object):

    ##
    # External function of plugin.  This function is used to perform the task of the CiBuild Plugin
    #
    #   - package is the edk2 path to package.  This means workspace/packagepath relative.
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

    ##
    # Return tuple (string, string) that is the (test case name, test case base class name)
    #
    #
    def GetTestName(self, packagename, environment):
        pass

    ##
    # Returns a list of edk2 TARGETs that this plugin would like to run on
    #
    # KNOWN TARGET VALUES:
    #  DEBUG
    #  RELEASE
    #  NOOPT
    #  NO-TARGET
    #
    # If the plugin is not Target specific it should return a list of
    # one element of "NO-TARGET"
    ##
    def RunsOnTargetList(self):
        return ["NO-TARGET"]

    #
    # Walks a directory for all items ending in certain extension
    # Default is to walk all of workspace
    #
    def WalkDirectoryForExtension(self, extensionlist, directory, ignorelist=None):
        if not isinstance(extensionlist, list):
            logging.critical("Expected list but got " + str(type(extensionlist)))
            return -1

        if directory is None:
            logging.critical("No directory given")
            return -2

        if not os.path.isabs(directory):
            logging.critical("Directory not abs path")
            return -3

        if not os.path.isdir(directory):
            logging.critical("Invalid find directory to walk")
            return -4

        if ignorelist is not None:
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
