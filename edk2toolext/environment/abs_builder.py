# @file abs_build.py
# This module contains code that supports the Tianocore Edk2 build system
# This class is designed to be subclassed by a platform to allow
# more extensive and custom behavior.
##
# Copyright (c) Microsoft Corporation
#
# SPDX-License-Identifier: BSD-2-Clause-Patent
##

class AbsBuilder(object):

    # TODO: this initiablize block should go to pipeline builder

    def AddPlatformCommandLineOptions(self, parserObj):
        pass

    def RetrievePlatformCommandLineOptions(self, args):
        pass

    def Go(self, WorkSpace, PackagesPath, PInHelper, PInManager):
        raise NotImplementedError