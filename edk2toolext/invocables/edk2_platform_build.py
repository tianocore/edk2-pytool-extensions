# @file edk2_platform_build
# Invocable class that does a build.
# Needs a child of UefiBuilder for pre/post build steps.
##
# Copyright (c) Microsoft Corporation
#
# SPDX-License-Identifier: BSD-2-Clause-Patent
##
"""Invocable class that does a build.

Contains a BuildSettingsManager that must be subclassed in a build settings
file, along with a UefiBuilder subclass. This provides platform specific
information to the Edk2PlatformBuild invocable while allowing the invocable
itself to remain platform agnostic.
"""

import argparse
import logging
import os
import sys
import timeit
from textwrap import wrap

from edk2toollib.uefi.edk2.path_utilities import Edk2Path
from edk2toollib.utility_functions import locate_class_in_module

from edk2toolext import edk2_logging
from edk2toolext.edk2_invocable import Edk2Invocable, Edk2InvocableSettingsInterface
from edk2toolext.environment import plugin_manager, self_describing_environment
from edk2toolext.environment.plugintypes.uefi_helper_plugin import HelperFunctions
from edk2toolext.environment.uefi_build import UefiBuilder


class BuildSettingsManager(Edk2InvocableSettingsInterface):
    """Platform specific settings for Edk2PlatformBuild.

    Provides information necessary for `stuart_build.exe`
    or `edk2_platform_build.py` to successfully execute.

    !!! example "Example of Overriding BuildSettingsManager"
        ```python
        from edk2toolext.invocables.edk2_platform_build import BuildSettingsManager
        class PlatformManager(BuildSettingsManager):
            def GetName(self) -> str:
                return "QemuQ35"
        ```
    """

    def GetName(self) -> str:
        """Get the name of the repo, platform, or product being build.

        !!! tip
            Optional Override in subclass

        Returns:
            (str): Name of the repo, platform, or product
        """
        return None


class Edk2PlatformBuild(Edk2Invocable):
    """Invocable that performs some environment setup,Imports UefiBuilder and calls go."""

    def __init__(self) -> None:
        """Init the Invocable."""
        super().__init__()
        self.PlatformBuilder = None

    def AddCommandLineOptions(self, parserObj: argparse.ArgumentParser) -> None:
        """Adds command line options to the argparser."""
        # PlatformSettings could also be a subclass of UefiBuilder, who knows!
        if isinstance(self.PlatformSettings, UefiBuilder):
            self.PlatformBuilder = self.PlatformSettings
        else:
            try:
                # if it's not, we will try to find it in the module that was originally provided.
                self.PlatformBuilder = locate_class_in_module(self.PlatformModule, UefiBuilder)()
            except TypeError:
                raise RuntimeError(f"UefiBuild not found in module:\n{dir(self.PlatformModule)}")

        self.PlatformBuilder.AddPlatformCommandLineOptions(parserObj)

    def RetrieveCommandLineOptions(self, args: argparse.Namespace) -> None:
        """Retrieve command line options from the argparser."""
        self.PlatformBuilder.RetrievePlatformCommandLineOptions(args)

    def AddParserEpilog(self) -> str:
        """Adds an epilog to the end of the argument parser when displaying help information.

        Returns:
            (str): The string to be added to the end of the argument parser.
        """
        epilog = super().AddParserEpilog()
        custom_epilog = ""

        if self.PlatformBuilder:
            variables = self.PlatformBuilder.SetPlatformDefaultEnv()
            if any(variables):
                max_name_len = max(len(var.name) for var in variables)
                max_desc_len = min(max(len(var.description) for var in variables), 55)

                custom_epilog += "CLI Env Variables:"
                for v in variables:
                    # Setup wrap and print first portion of description
                    desc = wrap(
                        v.description, max_desc_len, drop_whitespace=True, break_on_hyphens=True, break_long_words=True
                    )
                    custom_epilog += f"\n  {v.name:<{max_name_len}} - {desc[0]:<{max_desc_len}}  [{v.default}]"

                    # If the line actually wrapped, we can print the rest of the lines here
                    for d in desc[1:]:
                        custom_epilog += f"\n  {'':<{max_name_len}}   {d:{max_desc_len}}"
                custom_epilog += "\n\n"

        return custom_epilog + epilog

    def GetSettingsClass(self) -> type:
        """Returns the BuildSettingsManager class.

        !!! warning
            CiSetupSettingsManager must be subclassed in your platform settings file.
        """
        return BuildSettingsManager

    def GetLoggingFileName(self, loggerType: str) -> str:
        """Returns the filename of where the logs for the Edk2PlatformBuild invocable are stored in."""
        name = self.PlatformSettings.GetName()
        if name is not None:
            return f"BUILDLOG_{name}"
        return "BUILDLOG"

    def Go(self) -> int:
        """Executes the core functionality of the Edk2PlatformBuild invocable."""
        full_start_time = timeit.default_timer()
        logging.info("Running Python version: " + str(sys.version_info))

        Edk2PlatformBuild.collect_python_pip_info()
        Edk2PlatformBuild.collect_rust_info()

        (build_env, shell_env) = self_describing_environment.BootstrapEnvironment(
            self.GetWorkspaceRoot(), self.GetActiveScopes(), self.GetSkippedDirectories()
        )

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
        failedPlugins = pm.SetListOfEnvironmentDescriptors(build_env.plugins)
        if failedPlugins:
            logging.critical("One or more plugins failed to load. Halting build.")
            for a in failedPlugins:
                logging.error("Failed Plugin: {0}".format(a["name"]))
            raise Exception("One or more plugins failed to load.")

        helper = HelperFunctions()
        if helper.LoadFromPluginManager(pm) > 0:
            raise Exception("One or more helper plugins failed to load.")

        # Make a pathobj so we can normalize and validate the workspace
        # and packages path.  The Settings Manager can return absolute or
        # relative paths
        pathobj = Edk2Path(self.GetWorkspaceRoot(), self.GetPackagesPath())
        #
        # Now we can actually kick off a build.
        #
        edk2_logging.perf_measurement("Kick Off Platform Build", timeit.default_timer() - full_start_time)

        logging.log(edk2_logging.SECTION, "Kicking off build")
        ret = self.PlatformBuilder.Go(pathobj.WorkspacePath, os.pathsep.join(pathobj.PackagePathList), helper, pm)
        logging.log(edk2_logging.SECTION, f"Log file is located at: {self.log_filename}")
        return ret


def main() -> None:
    """Entry point invoke Edk2PlatformBuild."""
    Edk2PlatformBuild().Invoke()
