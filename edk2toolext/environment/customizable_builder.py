# @file customizable_builder.py
#  
##
# Copyright (c) 2021, Intel Corporation. All rights reserved.<BR>
#
# SPDX-License-Identifier: BSD-2-Clause-Patent
##
from edk2toolext.environment.multiple_workspace import MultipleWorkspace
from edk2toolext.environment import shell_environment
import logging
from edk2toolext import edk2_logging
from edk2toolext.environment.plugintypes.uefi_build_plugin import IUefiBuildPlugin

class CustomizableBuilder():

    def AddPlatformCommandLineOptions(self, parserObj):
        ''' adds command line options to the argparser '''
        parserObj.add_argument("--SKIPBUILD", "--skipbuild", "--SkipBuild", dest="SKIPBUILD",
                               action='store_true', default=False, help="Skip the build process")
        parserObj.add_argument("--SKIPPREBUILD", "--skipprebuild", "--SkipPrebuild", dest="SKIPPREBUILD",
                               action='store_true', default=False, help="Skip prebuild process")
        parserObj.add_argument("--SKIPPOSTBUILD", "--skippostbuild", "--SkipPostBuild", dest="SKIPPOSTBUILD",
                               action='store_true', default=False, help="Skip postbuild process")

    def RetrievePlatformCommandLineOptions(self, args):

        self.SkipBuild = False
        self.SkipPreBuild = False
        self.SkipPostBuild = False

        if(args.SKIPBUILD):
            self.SkipBuild = True
        elif(args.SKIPPREBUILD):
            self.SkipPreBuild = True
        elif(args.SKIPPOSTBUILD):
            self.SkipPostBuild = True

    def Build(self):
        raise NotImplementedError

    @classmethod
    def SetPlatformEnv(self):
        return 0

    def SetEnv(self):
        # process platform parameters defined in platform build file
        ret = self.SetPlatformEnv()
        return ret

    def Go(self, WorkSpace, PackagesPath, PInHelper, PInManager):
        self.env = shell_environment.GetBuildVars()
        self.mws = MultipleWorkspace()
        self.mws.setWs(WorkSpace, PackagesPath)
        self.ws = WorkSpace
        self.pp = PackagesPath  # string using os.pathsep
        self.Helper = PInHelper
        self.pm = PInManager

        ret = self.SetEnv()

        if(self.SkipPreBuild):
            edk2_logging.log_progress("Skipping Pre Build")
        else:
            ret = self.PreBuild()
            if(ret != 0):
                logging.critical("Pre Build failed")
                return ret
        if(self.SkipBuild):
            edk2_logging.log_progress("Skipping Build")
        else:
            ret = self.Build()

            if(ret != 0):
                logging.critical("Build failed")
                return ret

        # postbuild
        if(self.SkipPostBuild):
            edk2_logging.log_progress("Skipping Post Build")
        else:
            ret = self.PostBuild()
            if(ret != 0):
                logging.critical("Post Build failed")
                return ret

        return 0
    def PreBuild(self):
        edk2_logging.log_progress("Running Pre Build")
        #
        # Run the platform pre-build steps.
        #
        ret = self.PlatformPreBuild()

        if(ret != 0):
            logging.critical("PlatformPreBuild failed %d" % ret)
            return ret
        #
        # run all loaded UefiBuild Plugins
        #
        for Descriptor in self.pm.GetPluginsOfClass(IUefiBuildPlugin):
            rc = Descriptor.Obj.do_pre_build(self)
            if(rc != 0):
                if(rc is None):
                    logging.error(
                        "Plugin Failed: %s returned NoneType" % Descriptor.Name)
                    ret = -1
                else:
                    logging.error("Plugin Failed: %s returned %d" %
                                  (Descriptor.Name, rc))
                    ret = rc
                break  # fail on plugin error
            else:
                logging.debug("Plugin Success: %s" % Descriptor.Name)
        return ret
    def PostBuild(self):
        edk2_logging.log_progress("Running Post Build")
        #
        # Run the platform post-build steps.
        #
        ret = self.PlatformPostBuild()

        if(ret != 0):
            logging.critical("PlatformPostBuild failed %d" % ret)
            return ret

        #
        # run all loaded UefiBuild Plugins
        #
        for Descriptor in self.pm.GetPluginsOfClass(IUefiBuildPlugin):
            rc = Descriptor.Obj.do_post_build(self)
            if(rc != 0):
                if(rc is None):
                    logging.error(
                        "Plugin Failed: %s returned NoneType" % Descriptor.Name)
                    ret = -1
                else:
                    logging.error("Plugin Failed: %s returned %d" %
                                  (Descriptor.Name, rc))
                    ret = rc
                break  # fail on plugin error
            else:
                logging.debug("Plugin Success: %s" % Descriptor.Name)

        return ret

    @classmethod
    def PlatformPreBuild(self):
        return 0

    @classmethod
    def PlatformPostBuild(self):
        return 0
