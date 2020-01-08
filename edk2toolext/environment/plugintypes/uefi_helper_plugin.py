# @file uefi_helper_plugin
# Plugin that supports adding Extension or helper methods
# to the build environment
##
# Copyright (c) Microsoft Corporation
#
# SPDX-License-Identifier: BSD-2-Clause-Patent
##

import logging


class IUefiHelperPlugin(object):

    ##
    # Function that allows plugin to register its functions with the
    # obj.
    # @param obj[in, out]: HelperFunctions object that allows functional
    # registration.
    #
    def RegisterHelpers(self, obj):
        pass

# Supports IUefiHelperPlugin type


class HelperFunctions(object):
    def __init__(self):
        self.RegisteredFunctions = {}

    #
    # Function to logging.debug all registered functions and their source path
    #
    def DebugLogRegisteredFunctions(self):
        logging.debug("Logging all Registered Helper Functions:")
        for name, file in self.RegisteredFunctions.items():
            logging.debug("  Function %s registered from file %s", name, file)
        logging.debug("Finished logging %d functions",
                      len(self.RegisteredFunctions))

    #
    # Plugins that want to register a helper function should call
    # this routine for each function
    #
    # @param name[in]: name of function
    # @param function[in] function being registered
    # @param filepath[in] filepath registering function.  used for tracking and debug purposes
    #
    def Register(self, name, function, filepath):
        if(name in self.RegisteredFunctions.keys()):
            raise Exception("Function %s already registered from plugin file %s.  Can't register again from %s" % (
                name, self.RegisteredFunctions[name], filepath))
        setattr(self, name, function)
        self.RegisteredFunctions[name] = filepath

    def HasFunction(self, name):
        if(name in self.RegisteredFunctions.keys()):
            return True
        else:
            return False

    def LoadFromPluginManager(self, pm):
        error = 0
        for Descriptor in pm.GetPluginsOfClass(IUefiHelperPlugin):
            logging.info(Descriptor)
            logging.debug("Helper Plugin Register: %s", Descriptor.Name)
            try:
                Descriptor.Obj.RegisterHelpers(self)
            except Exception as e:
                logging.warning(
                    "Unable to register {0}".format(Descriptor.Name))
                logging.info(e)
                error += 1
        return error
