# @file customizable_builder.py
#  
##
# Copyright (c) 2021, Intel Corporation. All rights reserved.<BR>
#
# SPDX-License-Identifier: BSD-2-Clause-Patent
##
from edk2toolext.environment.multiple_workspace import MultipleWorkspace
from edk2toolext.environment import shell_environment

class CustomizableBuilder():
    
    def AddPlatformCommandLineOptions(self, parserObj):
        pass

    def RetrievePlatformCommandLineOptions(self, args):
        pass

    def execute(self):
        raise NotImplementedError

    def Go(self, WorkSpace, PackagesPath, PInHelper, PInManager):
        self.env = shell_environment.GetBuildVars()
        self.mws = MultipleWorkspace()
        self.mws.setWs(WorkSpace, PackagesPath)
        self.ws = WorkSpace
        self.pp = PackagesPath  # string using os.pathsep
        self.Helper = PInHelper
        self.pm = PInManager
        
        self.execute()
        return 0

