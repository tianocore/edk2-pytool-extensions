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
    #   - Junit Logger
    #   - output_stream the StringIO output stream from this plugin via logging
    def RunBuildPlugin(self, packagename, Edk2pathObj, pkgconfig, environment, PLM, PLMHelper, tc, output_stream):
        pass

    ##
    # Return tuple (string, string) that is the (test case name, test case base class name)
    #
    #
    def GetTestName(self, packagename, environment):
        pass

    ##
    # Returns true or false if plugin would like to be called for each target
    ##
    def IsTargetDependent(self):
        return False

    ##
    # Validates a configurations package .mu.json
    ##

    def ValidateConfig(self, config, name=""):
        # rather than doing the validation in the plugin, perhaps the plugin
        # can return their required list and their optional list
        # raise an exception if error is found
        pass

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

    # Gets the first DSC it can find in a particular folder (currently doesn't handle .mu.dsc.yamls)
    # returns None when none are found
    def get_dsc_name_in_dir(self, folderpath):
        dsc_list = self.get_dscs_in_dir(folderpath)
        if len(dsc_list) == 0:
            return None
        else:
            return dsc_list[0]

    # Gets the DSC's for a particular folder (currently doesn't handle .mu.dsc.yamls)
    # returns an empty list when none ar efound
    def get_dscs_in_dir(self, folderpath):
        try:
            directory = folderpath
            allEntries = os.listdir(directory)
            dscsFound = []
            for entry in allEntries:
                if entry.endswith(".dsc"):
                    dscsFound.append(os.path.join(directory, entry))
                if entry.endswith(".mu.dsc.yaml"):
                    jsonFile = entry
                    logging.info("We should create a DSC from the JSON file on the fly: {0}".format(jsonFile))
            return dscsFound
        except Exception:
            logging.error("Unable to find DSC for package:{0}".format(folderpath))
            return []
