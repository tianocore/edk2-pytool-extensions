# @file dsc_processor_plugin
# Plugin for for parsing DSCs
##
# Copyright (c) Microsoft Corporation
#
# SPDX-License-Identifier: BSD-2-Clause-Patent
##


class IDscProcessorPlugin(object):

    ##
    # does the transform on the DSC
    #
    # @param dsc - the in-memory model of the DSC
    # @param thebuilder - UefiBuild object to get env information
    #
    # @return 0 for success NonZero for error.
    ##
    def do_transform(self, dsc, thebuilder):
        return 0

    ##
    # gets the level that this transform operates at
    #
    # @param thebuilder - UefiBuild object to get env information
    #
    # @return 0 for the most generic level
    ##
    def get_level(self, thebuilder):

        return 0
