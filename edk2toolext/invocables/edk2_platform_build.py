# @file edk2_platform_build
# Invocable class that does a build.
# Needs a child of UefiBuilder for pre/post build steps.
##
# Copyright (c) Microsoft Corporation
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
from edk2toolext.environment.uefi_build import UefiBuilder
from edk2toolext.edk2_invocable import Edk2Invocable, Edk2InvocableSettingsInterface
from edk2toollib.utility_functions import locate_class_in_module
from edk2toollib.uefi.edk2.path_utilities import Edk2Path


class BuildSettingsManager(Edk2InvocableSettingsInterface):
    ''' Platform settings will be accessed through this implementation. '''

    def GetName(self):
        ''' Get the name of the repo, platform, or product being build '''
        return None


class Edk2PlatformBuild(Edk2Invocable):
    ''' Imports UefiBuilder and calls go '''

    def AddCommandLineOptions(self, parserObj):
        ''' adds command line options to the argparser '''

        # PlatformSettings could also be a subclass of UefiBuilder, who knows!
        if isinstance(self.PlatformSettings, UefiBuilder):
            self.PlatformBuilder = self.PlatformSettings
        else:
            try:
                # if it's not, we will try to find it in the module that was originally provided.
                self.PlatformBuilder = locate_class_in_module(self.PlatformModule, UefiBuilder)()
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

        Edk2PlatformBuild.collect_python_pip_info()

        (build_env, shell_env) = self_describing_environment.BootstrapEnvironment(
            self.GetWorkspaceRoot(), self.GetActiveScopes())

        # Bind our current execution environment into the shell vars.
        ph = os.path.dirname(sys.executable)
        if " " in ph:
            ph = '"' + ph + '"'
        shell_env.set_shell_var("PYTHON_HOME", ph)
        # PYTHON_COMMAND is required to be set for using edk2 python builds.
        # todo: work with edk2 to remove the bat file and move to native python calls
        pc = sys.executable
        if " " in pc:
            pc = '"' + pc + '"'
        shell_env.set_shell_var("PYTHON_COMMAND", pc)

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
    Edk2PlatformBuild().Invoke()
