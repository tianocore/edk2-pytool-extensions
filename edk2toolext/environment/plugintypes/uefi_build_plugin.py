# @file UefiBuildPlugin
# Plugin that supports Pre and Post Build steps
##
# Copyright (c) Microsoft Corporation
#
# SPDX-License-Identifier: BSD-2-Clause-Patent
##


class IUefiBuildPlugin(object):

    ##
    # Run Post Build Operations
    #
    # @param thebuilder - UefiBuild object to get env information
    #
    # @return 0 for success NonZero for error.
    ##
    def do_post_build(self, thebuilder):
        return 0

    ##
    # Run Pre Build Operations
    #
    # @param thebuilder - UefiBuild object to get env information
    #
    # @return 0 for success NonZero for error.
    ##
    def do_pre_build(self, thebuilder):
        '''
        Run Pre build Operation
        '''
        return 0
