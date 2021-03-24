# @file customizable_build
# Invocable class that does a customized build.
# Needs a child of CustomizableBuilder for pre/post build steps.
##
# Copyright (c) 2021, Intel Corporation. All rights reserved.<BR>
#
# SPDX-License-Identifier: BSD-2-Clause-Patent
##
import os
import sys
import logging

from edk2toolext import edk2_logging
from edk2toolext.environment import plugin_manager
from edk2toolext.environment.plugintypes.uefi_helper_plugin import HelperFunctions
from edk2toolext.environment import self_describing_environment
from edk2toolext.environment.customizable_builder import CustomizableBuilder
from edk2toolext.edk2_invocable import Edk2Invocable,Edk2InvocableSettingsInterface
from edk2toollib.utility_functions import locate_class_in_module
from edk2toollib.uefi.edk2.path_utilities import Edk2Path


class BuildSettingsManager(Edk2InvocableSettingsInterface):
    ''' Platform settings will be accessed through this implementation. '''

    def GetName(self):
        ''' Get the name of the repo, platform, or product being build '''
        return None

class CustomizableBuild(Edk2Invocable):
    ''' Imports UefiBuilder and calls go '''

    def AddCommandLineOptions(self, parserObj):
        ''' adds command line options to the argparser '''

        # PlatformSettings could also be a subclass of UefiBuilder, who knows!
        if isinstance(self.PlatformSettings, CustomizableBuilder):
            self.PlatformBuilder = self.PlatformSettings
        else:
            try:
                # if it's not, we will try to find it in the module that was originally provided.
                self.PlatformBuilder = locate_class_in_module(self.PlatformModule, CustomizableBuilder)()
            except (TypeError):
                raise RuntimeError(f"UefiBuild not found in module:\n{dir(self.PlatformModule)}")

        self.PlatformBuilder.AddPlatformCommandLineOptions(parserObj)
    def RetrieveCommandLineOptions(self, args):
        '''  Retrieve command line options from the argparser '''
        self.PlatformBuilder.RetrievePlatformCommandLineOptions(args)
        
    def GetSettingsClass(self):
        '''  Providing BuildSettingsManager  '''
        return BuildSettingsManager

    def GetLoggingFileName(self, loggerType):
        name = self.PlatformSettings.GetName()
        if name is not None:
            return f"BUILDLOG_{name}"
        return "BUILDLOG"

    def Go(self):
        logging.info("Running Python version: " + str(sys.version_info))

        CustomizableBuild.collect_python_pip_info()

        (build_env, shell_env) = self_describing_environment.BootstrapEnvironment(
            self.GetWorkspaceRoot(), self.GetActiveScopes())

        # Load plugins
        logging.log(edk2_logging.SECTION, "Loading Plugins")
        pm = plugin_manager.PluginManager()
        failedPlugins = pm.SetListOfEnvironmentDescriptors(
            build_env.plugins)
        if failedPlugins:
            logging.critical("One or more plugins failed to load. Halting build.")
            for a in failedPlugins:
                logging.error("Failed Plugin: {0}".format(a["name"]))
            raise Exception("One or more plugins failed to load.")

        helper = HelperFunctions()
        if(helper.LoadFromPluginManager(pm) > 0):
            raise Exception("One or more helper plugins failed to load.")

        # Make a pathobj so we can normalize and validate the workspace
        # and packages path.  The Settings Manager can return absolute or
        # relative paths
        pathobj = Edk2Path(self.GetWorkspaceRoot(), self.GetPackagesPath())
        #
        # Now we can actually kick off a build.
        #
        logging.log(edk2_logging.SECTION, "Kicking off build")
        ret = self.PlatformBuilder.Go(pathobj.WorkspacePath,
                                      os.pathsep.join(pathobj.PackagePathList),
                                      helper, pm)
        logging.log(edk2_logging.SECTION, f"Log file is located at: {self.log_filename}")
        return ret


def main():
    CustomizableBuild().Invoke()

