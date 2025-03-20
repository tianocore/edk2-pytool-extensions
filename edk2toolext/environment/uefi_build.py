# @file uefi_build.py
# This module contains code that supports the Tianocore Edk2 build system
# This class is designed to be subclassed by a platform to allow
# more extensive and custom behavior.
##
# Copyright (c) Microsoft Corporation
# Copyright (c) 2022 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
#
# SPDX-License-Identifier: BSD-2-Clause-Patent
##
"""Code that supports the Tianocore Edk2 build system.

This class is designed to be subclassed by a platform to allow more extensive
and custom behavior.
"""

import argparse
import datetime
import logging
import os
import time
import timeit
import traceback
from collections import namedtuple

from edk2toollib.uefi.edk2.parsers.dsc_parser import DscParser
from edk2toollib.uefi.edk2.parsers.fdf_parser import FdfParser
from edk2toollib.uefi.edk2.parsers.targettxt_parser import TargetTxtParser
from edk2toollib.uefi.edk2.path_utilities import Edk2Path
from edk2toollib.utility_functions import RemoveTree, RunCmd

from edk2toolext import edk2_logging
from edk2toolext.environment import conf_mgmt, shell_environment
from edk2toolext.environment.multiple_workspace import MultipleWorkspace
from edk2toolext.environment.plugin_manager import PluginManager
from edk2toolext.environment.plugintypes.uefi_build_plugin import IUefiBuildPlugin
from edk2toolext.environment.plugintypes.uefi_helper_plugin import HelperFunctions


class UefiBuilder(object):
    """Object responsible for the full build process.

    The following steps are completed by the `UefiBuilder` and is overridable
    by the platform:

    1. `PlatformPreBuild()`
    2. `UefiBuildPlugins` that implement `do_pre_build()`
    3. `Build()` (should not be overridden)
    4. `UefiBuildPlugins` that implement `do_post_build()`
    5. `PlatformFlashImage()`

    Attributes:
        SkipPreBuild (bool): Skip Pre Build or not
        SkipPostBuild (bool): Skip Post Build or not
        SkipBuild (bool): Skip Build or not
        FlashImage (bool): Flash the image not
        Clean (bool): Clean the build directory or not
        Update Conf (bool): Update the conf or not
        env (VarDict): Special dictionary containing build and env vars
        mws (MultipleWorkspace): DEPRECATED. Use self.edk2path
        edk2path (Edk2Path): path utilities for manipulating edk2 paths, packages, and modules
        ws (str): Workspace root dir
        pp (str): packagespath separated by os.pathsep
        Helper (HelperFunctions): object containing registered helper functions
        pm (PluginManager): The plugin manager
    """

    def __init__(self) -> None:
        """Inits an empty UefiBuilder."""
        self.SkipBuild = False
        self.SkipPreBuild = False
        self.SkipPostBuild = False
        self.FlashImage = False
        self.ShowHelpOnly = False
        self.OutputBuildEnvBeforeBuildToFile = None
        self.Clean = False
        self.UpdateConf = False
        self.OutputConfig = None
        self.Verbose = False

    def AddPlatformCommandLineOptions(self, parserObj: argparse.ArgumentParser) -> None:
        """Adds command line options to the argparser.

        Args:
            parserObj (argparser): argparser object
        """
        parserObj.add_argument(
            "--SKIPBUILD",
            "--skipbuild",
            "--SkipBuild",
            dest="SKIPBUILD",
            action="store_true",
            default=False,
            help="Skip the build process",
        )
        parserObj.add_argument(
            "--SKIPPREBUILD",
            "--skipprebuild",
            "--SkipPrebuild",
            dest="SKIPPREBUILD",
            action="store_true",
            default=False,
            help="Skip prebuild process",
        )
        parserObj.add_argument(
            "--SKIPPOSTBUILD",
            "--skippostbuild",
            "--SkipPostBuild",
            dest="SKIPPOSTBUILD",
            action="store_true",
            default=False,
            help="Skip postbuild process",
        )
        parserObj.add_argument(
            "--FLASHONLY",
            "--flashonly",
            "--FlashOnly",
            dest="FLASHONLY",
            action="store_true",
            default=False,
            help="Flash rom after build.",
        )
        parserObj.add_argument(
            "--FLASHROM",
            "--flashrom",
            "--FlashRom",
            dest="FLASHROM",
            action="store_true",
            default=False,
            help="Flash rom.  Rom must be built previously.",
        )
        parserObj.add_argument(
            "--UPDATECONF",
            "--updateconf",
            "--UpdateConf",
            dest="UPDATECONF",
            action="store_true",
            default=False,
            help="Update Conf. Builders Conf files will be replaced with latest template files",
        )
        parserObj.add_argument(
            "--CLEAN",
            "--clean",
            "--CLEAN",
            dest="CLEAN",
            action="store_true",
            default=False,
            help="Clean. Remove all old build artifacts and intermediate files",
        )
        parserObj.add_argument(
            "--CLEANONLY",
            "--cleanonly",
            "--CleanOnly",
            dest="CLEANONLY",
            action="store_true",
            default=False,
            help="Clean Only. Do clean operation and don't build just exit.",
        )
        parserObj.add_argument(
            "--OUTPUTCONFIG",
            "--outputconfig",
            "--OutputConfig",
            dest="OutputConfig",
            required=False,
            type=str,
            help="Provide shell variables in a file",
        )

    def RetrievePlatformCommandLineOptions(self, args: argparse.Namespace) -> None:
        """Retrieve command line options from the argparser.

        Args:
            args (Namespace): namespace containing gathered args from argparser
        """
        self.OutputConfig = os.path.abspath(args.OutputConfig) if args.OutputConfig else None

        self.SkipBuild = args.SKIPBUILD
        self.SkipPreBuild = args.SKIPPREBUILD
        self.SkipPostBuild = args.SKIPPOSTBUILD
        self.Clean = args.CLEAN
        self.FlashImage = args.FLASHROM
        self.UpdateConf = args.UPDATECONF

        if args.FLASHONLY:
            self.SkipPostBuild = True
            self.SkipBuild = True
            self.SkipPreBuild = True
            self.FlashImage = True
        elif args.CLEANONLY:
            self.Clean = True
            self.SkipBuild = True
            self.SkipPreBuild = True
            self.SkipPostBuild = True
            self.FlashImage = False

    def Go(self, WorkSpace: str, PackagesPath: str, PInHelper: HelperFunctions, PInManager: PluginManager) -> int:
        """Core executable that performs all build steps."""
        self.env = shell_environment.GetBuildVars()
        self.mws = MultipleWorkspace()
        self.mws.setWs(WorkSpace, PackagesPath)
        self.edk2path = Edk2Path(WorkSpace, PackagesPath.split(os.pathsep))
        self.ws = WorkSpace
        self.pp = PackagesPath  # string using os.pathsep
        self.Helper = PInHelper
        self.pm = PInManager

        try:
            edk2_logging.log_progress("Start time: {0}".format(datetime.datetime.now()))
            start_time = time.perf_counter()

            self.Helper.DebugLogRegisteredFunctions()

            ret = self.SetEnv()
            if ret != 0:
                logging.critical("SetEnv failed")
                return ret

            # clean
            if self.Clean:
                edk2_logging.log_progress("Cleaning")
                ret = self.CleanTree()
                if ret != 0:
                    logging.critical("Clean failed")
                    return ret

            # prebuild
            if self.SkipPreBuild:
                edk2_logging.log_progress("Skipping Pre Build")
            else:
                ret = self.PreBuild()
                if ret != 0:
                    logging.critical("Pre Build failed")
                    return ret

            # Output Build Environment to File - this is mostly for debug of build
            # issues or adding other build features using existing variables
            if self.OutputConfig is not None:
                edk2_logging.log_progress("Writing Build Env Info out to File")
                logging.debug("Found an Output Build Env File: " + self.OutputConfig)
                self.env.PrintAll(self.OutputConfig)

            if (self.env.GetValue("GATEDBUILD") is not None) and (self.env.GetValue("GATEDBUILD").upper() == "TRUE"):
                ShouldGatedBuildRun = self.PlatformGatedBuildShouldHappen()
                logging.debug("Platform Gated Build Should Run returned: %s" % str(ShouldGatedBuildRun))
                if not self.SkipBuild:
                    self.SkipBuild = not ShouldGatedBuildRun
                if not self.SkipPostBuild:
                    self.SkipPostBuild = not ShouldGatedBuildRun

            # build
            if self.SkipBuild:
                edk2_logging.log_progress("Skipping Build")
            else:
                ret = self.Build()

                if ret != 0:
                    logging.critical("Build failed")
                    return ret

            # postbuild
            if self.SkipPostBuild:
                edk2_logging.log_progress("Skipping Post Build")
            else:
                ret = self.PostBuild()
                if ret != 0:
                    logging.critical("Post Build failed")
                    return ret

            # flash
            if self.FlashImage:
                edk2_logging.log_progress("Flashing Image")
                ret = self.FlashRomImage()
                if ret != 0:
                    logging.critical("Flash Image failed")
                    return ret

        except Exception:
            logging.critical("Build Process Exception")
            logging.error(traceback.format_exc())
            return -1

        except SystemExit:
            logging.critical("Build Process Exit")
            logging.error(traceback.format_exc())
            return -1

        except KeyboardInterrupt:
            logging.critical("Build Cancelled by user")
            return -2

        finally:
            end_time = time.perf_counter()
            elapsed_time_s = int((end_time - start_time))
            edk2_logging.log_progress(
                "End time: {0}\t Total time Elapsed: {1}".format(
                    datetime.datetime.now(), datetime.timedelta(seconds=elapsed_time_s)
                )
            )

        return 0

    def CleanTree(self, RemoveConfTemplateFilesToo: bool = False) -> int:
        """Cleans the build directory.

        Args:
            RemoveConfTemplateFilesToo (bool): deletes conf files used for building makefiles
        """
        ret = 0
        # loop thru each build target set.
        edk2_logging.log_progress("Cleaning All Output for Build")

        d = self.env.GetValue("BUILD_OUTPUT_BASE")
        if os.path.isdir(d):
            logging.debug("Removing [%s]", d)
            # if the folder is opened in Explorer do not fail the entire Rebuild
            try:
                RemoveTree(d)
            except WindowsError as wex:
                logging.debug(wex)

        else:
            logging.debug("Directory [%s] already clean" % d)

        # delete the conf .dbcache
        # this needs to be removed in case build flags changed
        d = os.path.join(self.ws, "Conf", ".cache")
        if os.path.isdir(d):
            logging.debug("Removing [%s]" % d)
            RemoveTree(d)

        if RemoveConfTemplateFilesToo:
            for a in ["target.txt", "build_rule.txt", "tools_def.txt"]:
                d = os.path.join(self.ws, "Conf", a)
                if os.path.isfile(d):
                    logging.debug("Removing [%s]" % d)
                    os.remove(d)

        return ret

    def Build(self) -> int:
        """Adds all arguments to the build command and runs it."""
        build_start_time = timeit.default_timer()

        BuildType = self.env.GetValue("TARGET")
        edk2_logging.log_progress("Running Build %s" % BuildType)

        # set target, arch, toolchain, threads, and platform
        params = "-p " + self.env.GetValue("ACTIVE_PLATFORM")
        params += " -b " + BuildType
        params += " -t " + self.env.GetValue("TOOL_CHAIN_TAG")

        if self.env.GetValue("EDK2_BUILD_VERBOSE") == "TRUE":
            params += " --verbose"

        # Thread number is now optional and not set in default tianocore target.txt
        if self.env.GetValue("MAX_CONCURRENT_THREAD_NUMBER") is not None:
            params += " -n " + self.env.GetValue("MAX_CONCURRENT_THREAD_NUMBER")

        # Set the arch flags.  Multiple are split by space
        rt = self.env.GetValue("TARGET_ARCH").split(" ")
        for t in rt:
            params += " -a " + t

        # get the report options and setup the build command
        if self.env.GetValue("BUILDREPORTING") == "TRUE":
            params += " -y " + self.env.GetValue("BUILDREPORT_FILE")
            rt = self.env.GetValue("BUILDREPORT_TYPES").split(" ")
            for t in rt:
                params += " -Y " + t

        # add special processing to handle building a single module
        mod = self.env.GetValue("BUILDMODULE")
        if mod is not None and len(mod.strip()) > 0:
            params += " -m " + mod
            edk2_logging.log_progress("Single Module Build: " + mod)
            self.SkipPostBuild = True
            self.FlashImage = False

        # attach the generic build vars
        buildvars = self.env.GetAllBuildKeyValues(BuildType)
        for key, value in buildvars.items():
            params += " -D " + key + "=" + value
        output_stream = edk2_logging.create_output_stream()

        env = shell_environment.ShellEnvironment()
        # WORKAROUND - Pin the PYTHONHASHSEED so that TianoCore build tools
        #               have consistent ordering. Addresses incremental builds.
        pre_build_env_chk = env.checkpoint()
        env.set_shell_var("PYTHONHASHSEED", "0")
        env.log_environment()

        edk2_build_cmd = self.env.GetValue("EDK_BUILD_CMD")
        if edk2_build_cmd is None:
            edk2_build_cmd = "build"
        logging.debug(f"The edk2 build command is {edk2_build_cmd}")

        edk2_build_params = self.env.GetValue("EDK_BUILD_PARAMS")
        if edk2_build_params is None:
            edk2_build_params = params
        logging.debug(f"Edk2 build parameters are {edk2_build_params}")

        ret = RunCmd(edk2_build_cmd, edk2_build_params, close_fds=False)
        # WORKAROUND - Undo the workaround.
        env.restore_checkpoint(pre_build_env_chk)

        problems = edk2_logging.scan_compiler_output(output_stream)
        edk2_logging.remove_output_stream(output_stream)
        for level, problem in problems:
            logging.log(level, problem)

        edk2_logging.perf_measurement("Build", timeit.default_timer() - build_start_time)

        if ret != 0:
            return ret

        return 0

    def PreBuild(self) -> int:
        """Performs internal PreBuild steps.

        This includes calling the platform overridable `PlatformPreBuild()`
        """
        prebuild_start_time = timeit.default_timer()

        edk2_logging.log_progress("Running Pre Build")
        #
        # Run the platform pre-build steps.
        #
        platform_pre_build_start_time = timeit.default_timer()
        ret = self.PlatformPreBuild()
        edk2_logging.perf_measurement("PlatformPreBuild", timeit.default_timer() - platform_pre_build_start_time)

        if ret != 0:
            logging.critical("PlatformPreBuild failed %d" % ret)
            return ret
        #
        # run all loaded UefiBuild Plugins
        #
        for Descriptor in self.pm.GetPluginsOfClass(IUefiBuildPlugin):
            plugin_start_time = timeit.default_timer()
            rc = Descriptor.Obj.do_pre_build(self)
            edk2_logging.perf_measurement(
                f"do_pre_build()[{Descriptor.Name}]", timeit.default_timer() - plugin_start_time
            )
            if rc != 0:
                if rc is None:
                    logging.error("Plugin Failed: %s returned NoneType" % Descriptor.Name)
                    ret = -1
                else:
                    logging.error("Plugin Failed: %s returned %d" % (Descriptor.Name, rc))
                    ret = rc
                break  # fail on plugin error
            else:
                logging.debug("Plugin Success: %s" % Descriptor.Name)

        edk2_logging.perf_measurement("PreBuild", timeit.default_timer() - prebuild_start_time)

        return ret

    def PostBuild(self) -> int:
        """Performs internal PostBuild steps.

        This includes calling the platform overridable `PlatformPostBuild()`.
        """
        postbuild_start_time = timeit.default_timer()

        edk2_logging.log_progress("Running Post Build")
        #
        # Run the platform post-build steps.
        #
        platform_post_build_start_time = timeit.default_timer()
        ret = self.PlatformPostBuild()
        edk2_logging.perf_measurement("PlatformPostBuild", timeit.default_timer() - platform_post_build_start_time)

        if ret != 0:
            logging.critical("PlatformPostBuild failed %d" % ret)
            return ret

        #
        # run all loaded UefiBuild Plugins
        #
        for Descriptor in self.pm.GetPluginsOfClass(IUefiBuildPlugin):
            plugin_start_time = timeit.default_timer()
            rc = Descriptor.Obj.do_post_build(self)
            edk2_logging.perf_measurement(
                f"do_post_build()[{Descriptor.Name}]", timeit.default_timer() - plugin_start_time
            )
            if rc != 0:
                if rc is None:
                    logging.error("Plugin Failed: %s returned NoneType" % Descriptor.Name)
                    ret = -1
                else:
                    logging.error("Plugin Failed: %s returned %d" % (Descriptor.Name, rc))
                    ret = rc
                break  # fail on plugin error
            else:
                logging.debug("Plugin Success: %s" % Descriptor.Name)

        edk2_logging.perf_measurement("PostBuild", timeit.default_timer() - postbuild_start_time)

        return ret

    def SetEnv(self) -> int:
        """Performs internal SetEnv steps.

        This includes platform overridable `SetPlatformEnv()` and `SetPlatformEnvAfterTarget().
        """
        setenv_start_time = timeit.default_timer()

        edk2_logging.log_progress("Setting up the Environment")
        shell_environment.GetEnvironment().set_shell_var("WORKSPACE", self.ws)
        shell_environment.GetBuildVars().SetValue("WORKSPACE", self.ws, "Set in SetEnv")

        if self.pp is not None:
            shell_environment.GetEnvironment().set_shell_var("PACKAGES_PATH", self.pp)
            shell_environment.GetBuildVars().SetValue("PACKAGES_PATH", self.pp, "Set in SetEnv")

        # process platform parameters defined in platform build file
        ret = self.SetPlatformEnv()
        if ret != 0:
            logging.critical("Set Platform Env failed")
            return ret

        # set some basic defaults
        self.SetBasicDefaults()

        # Handle all the template files for workspace/conf/ Allow override
        TemplateDirList = [self.env.GetValue("EDK_TOOLS_PATH")]  # set to edk2 BaseTools
        PlatTemplatesForConf = self.env.GetValue("CONF_TEMPLATE_DIR")  # get platform defined additional path
        if PlatTemplatesForConf is not None:
            PlatTemplatesForConf = self.edk2path.GetAbsolutePathOnThisSystemFromEdk2RelativePath(PlatTemplatesForConf)
            TemplateDirList.insert(0, PlatTemplatesForConf)
            logging.debug(f"Platform defined override for Template Conf Files: {PlatTemplatesForConf}")

        conf_dir = os.path.join(self.ws, "Conf")
        conf_mgmt.ConfMgmt().populate_conf_dir(conf_dir, self.UpdateConf, TemplateDirList)

        # parse target file
        ret = self.ParseTargetFile()
        if ret != 0:
            logging.critical("ParseTargetFile failed")
            return ret

        # parse tools_def file
        ret = self.ParseToolsDefFile()
        if ret != 0:
            logging.critical("ParseToolsDefFile failed")
            return ret

        # parse DSC file
        ret = self.ParseDscFile()
        if ret != 0:
            logging.critical("ParseDscFile failed")
            return ret

        # parse FDF file
        ret = self.ParseFdfFile()
        if ret != 0:
            logging.critical("ParseFdfFile failed")
            return ret

        # set build output base envs for all builds
        if self.env.GetValue("OUTPUT_DIRECTORY") is None:
            logging.warn("OUTPUT_DIRECTORY was not found, defaulting to Build")
            self.env.SetValue("OUTPUT_DIRECTORY", "Build", "default from uefi_build", True)

        # BUILD_OUT_TEMP is a path so the value should use native directory separators
        self.env.SetValue(
            "BUILD_OUT_TEMP",
            os.path.normpath(os.path.join(self.ws, self.env.GetValue("OUTPUT_DIRECTORY"))),
            "Computed in SetEnv",
        )

        target = self.env.GetValue("TARGET", None)
        if target is None:
            logging.error("Environment variable TARGET must be set to a build target.")
            logging.error("Review the 'CLI Env Guide' section provided when using stuart_build with the -help flag.")
            return -1

        self.env.SetValue(
            "BUILD_OUTPUT_BASE",
            os.path.join(self.env.GetValue("BUILD_OUT_TEMP"), target + "_" + self.env.GetValue("TOOL_CHAIN_TAG")),
            "Computed in SetEnv",
        )

        # We have our build target now.  Give platform build one more chance for target specific settings.
        ret = self.SetPlatformEnvAfterTarget()
        if ret != 0:
            logging.critical("SetPlatformEnvAfterTarget failed")
            return ret

        # set the build report file
        self.env.SetValue(
            "BUILDREPORT_FILE", os.path.join(self.env.GetValue("BUILD_OUTPUT_BASE"), "BUILD_REPORT.TXT"), True
        )

        # set environment variables for the build process
        os.environ["EFI_SOURCE"] = self.ws

        # set critical platform Env Defaults if not set anywhere else in the build.
        for env_var in self.SetPlatformDefaultEnv():
            self.env.SetValue(env_var.name, env_var.default, "Default Critical Platform Env Value.")

        edk2_logging.perf_measurement("SetEnv", timeit.default_timer() - setenv_start_time)

        return 0

    def FlashRomImage(self) -> int:
        """Executes platform overridable `PlatformFlashImage()`."""
        return self.PlatformFlashImage()

    # -----------------------------------------------------------------------
    # Methods that will be overridden by child class
    # -----------------------------------------------------------------------

    @classmethod
    def PlatformPreBuild(self: "UefiBuilder") -> int:
        """Perform Platform PreBuild Steps.

        Returns:
            (int): 0 on success, 1 on failure
        """
        return 0

    @classmethod
    def PlatformPostBuild(self: "UefiBuilder") -> int:
        """Perform Platform PostBuild Steps.

        Returns:
            (int): 0 on success, 1 on failure
        """
        return 0

    @classmethod
    def SetPlatformEnv(self: "UefiBuilder") -> int:
        """Set and read Platform Env variables.

        This is performed before platform files like the DSC and FDF have been parsed.

        !!! tip
            If a platform file (DSC, FDF, etc) relies on a variable set in
            the `UefiBuilder`, it must be set here, before the platform files
            have been parsed and values have been set.

        Returns:
            (int): 0 on success, 1 on failure
        """
        return 0

    @classmethod
    def SetPlatformEnvAfterTarget(self: "UefiBuilder") -> int:
        """Set and read Platform Env variables after platform files have been parsed.

        Returns:
            (int): 0 on success, 1 on failure
        """
        return 0

    @classmethod
    def SetPlatformDefaultEnv(self: "UefiBuilder") -> list[namedtuple]:
        """Sets platform default environment variables by returning them as a list.

        Variables returned from this method are printed to the command line when
        calling stuart_build with -h, --help. Variables added here should be
        reserved only those that are commonly overwritten in the command line for
        developers.

        Variables returned from this function are the last variables to be set,
        ensuring that default values are only added if none have been provided by
        other means.

        Returns:
            (list[namedtuple]): List of named tuples containing name, description, default
        """
        return []

    @classmethod
    def PlatformBuildRom(self: "UefiBuilder") -> int:
        """Build the platform Rom.

        !!! tip
            Typically called by the platform in PlatformFlashImage. Not called
            automatically by the `UefiBuilder`.
        """
        return 0

    @classmethod
    def PlatformFlashImage(self: "UefiBuilder") -> int:
        """Flashes the image to the system.

        Returns:
            (int): 0 on success, 1 on failure
        """
        return 0

    @classmethod
    def PlatformGatedBuildShouldHappen(self: "UefiBuilder") -> bool:
        """Specifies if a gated build should happen.

        Returns:
            (bool): True if gated build should happen, else False
        """
        return True

    # ------------------------------------------------------------------------
    #  HELPER FUNCTIONS
    # ------------------------------------------------------------------------
    #
    def ParseTargetFile(self) -> int:
        """Parses the target.txt file and adds values as env settings.

        "Sets them so they can be overriden.
        """
        parse_target_file_start_time = timeit.default_timer()

        conf_file_path = self.edk2path.GetAbsolutePathOnThisSystemFromEdk2RelativePath("Conf", "target.txt")
        if os.path.isfile(conf_file_path):
            # parse TargetTxt File
            logging.debug("Parse Target.txt file")
            ttp = TargetTxtParser()
            ttp.ParseFile(conf_file_path)
            for key, value in ttp.Dict.items():
                # set env as overrideable
                self.env.SetValue(key, value, "From Target.txt", True)

            # Set the two additional edk2 common macros.  These will be resolved by now as
            # target.txt will set them if they aren't already set.
            self.env.SetValue(
                "TOOLCHAIN", self.env.GetValue("TOOL_CHAIN_TAG"), "DSC Spec macro - set based on tool_Chain_tag"
            )
            # need to check how multiple arch are handled
            self.env.SetValue("ARCH", self.env.GetValue("TARGET_ARCH"), "DSC Spec macro - set based on target_arch")

        else:
            logging.error("Failed to find target.txt file")
            return -1

        edk2_logging.perf_measurement("ParseTargetFile", timeit.default_timer() - parse_target_file_start_time)

        return 0

    def ParseToolsDefFile(self) -> int:
        """Parses the tools_def.txt file and adds values as env settings.

        "Sets them so they can be overriden.
        """
        parse_toolsdef_file_start_time = timeit.default_timer()

        toolsdef_file_path = self.edk2path.GetAbsolutePathOnThisSystemFromEdk2RelativePath("Conf", "tools_def.txt")
        if os.path.isfile(toolsdef_file_path):
            # parse ToolsdefTxt File
            logging.debug("Parse tools_def.txt file")
            tdp = TargetTxtParser()
            tdp.ParseFile(toolsdef_file_path)

            # Get the tool chain tag and then find the family
            # need to parse tools_def and find *_<TAG>_*_*_FAMILY
            # Example:  *_VS2019_*_*_FAMILY        = MSFT
            tool_chain = self.env.GetValue("TOOL_CHAIN_TAG", None)
            if tool_chain is None:
                logging.error("Environment variable TOOL_CHAIN_TAG must be set to a tool chain.")
                logging.error(
                    "Review the 'CLI Env Guide' section provided when using stuart_build with the -help flag."
                )
                return -1
            tag = "*_" + tool_chain + "_*_*_FAMILY"
            tool_chain_family = tdp.Dict.get(tag, "UNKNOWN")
            self.env.SetValue("FAMILY", tool_chain_family, "DSC Spec macro - from tools_def.txt")

        else:
            logging.error("Failed to find tools_def.txt file")
            return -1

        edk2_logging.perf_measurement("ParseToolsDefFile", timeit.default_timer() - parse_toolsdef_file_start_time)

        return 0

    def ParseDscFile(self) -> int:
        """Parses the active platform DSC file.

        This will get lots of variable info to be used in the build. This
        makes it so we don't have to define things twice.
        """
        parse_dsc_file_start_time = timeit.default_timer()

        if self.env.GetValue("ACTIVE_PLATFORM") is None:
            logging.error("The DSC file was not set. Please set ACTIVE_PLATFORM")
            return -1
        dsc_file_path = self.edk2path.GetAbsolutePathOnThisSystemFromEdk2RelativePath(
            self.env.GetValue("ACTIVE_PLATFORM")
        )
        if os.path.isfile(dsc_file_path):
            # parse DSC File
            logging.debug("Parse Active Platform DSC file: {0}".format(dsc_file_path))

            # Get the vars from the environment that are not build keys
            input_vars = self.env.GetAllNonBuildKeyValues()
            # Update with special environment set build keys
            input_vars.update(self.env.GetAllBuildKeyValues())
            dscp = DscParser().SetEdk2Path(self.edk2path).SetInputVars(input_vars)
            dscp.ParseFile(dsc_file_path)
            for key, value in dscp.LocalVars.items():
                # set env as overrideable
                self.env.SetValue(key, value, "From Platform DSC File", True)
        else:
            logging.error("Failed to find DSC file")
            return -1

        edk2_logging.perf_measurement("ParseDscFile", timeit.default_timer() - parse_dsc_file_start_time)

        return 0

    def ParseFdfFile(self) -> int:
        """Parses the active platform FDF file.

        This will get lots of variable info to be used in the build. This makes
        it so we don't have to define things twice the FDF file usually comes
        from the Active Platform DSC file so it needs to be parsed first.
        """
        parse_fdf_file_start_time = timeit.default_timer()

        if self.env.GetValue("FLASH_DEFINITION") is None:
            logging.debug("No flash definition set")
            return 0
        fdf_file_path = self.edk2path.GetAbsolutePathOnThisSystemFromEdk2RelativePath(
            self.env.GetValue("FLASH_DEFINITION")
        )
        if os.path.isfile(fdf_file_path):
            # parse the FDF file- fdf files have similar syntax to DSC and therefore parser works for both.
            logging.debug("Parse Active Flash Definition (FDF) file")

            # Get the vars from the environment that are not build keys
            input_vars = self.env.GetAllNonBuildKeyValues()
            # Update with special environment set build keys
            input_vars.update(self.env.GetAllBuildKeyValues())
            fdf_parser = FdfParser().SetEdk2Path(self.edk2path).SetInputVars(input_vars)
            fdf_parser.ParseFile(fdf_file_path)
            for key, value in fdf_parser.LocalVars.items():
                self.env.SetValue(key, value, "From Platform FDF File", True)

        else:
            logging.error("Failed to find FDF file")
            return -2

        edk2_logging.perf_measurement("ParseFdfFile", timeit.default_timer() - parse_fdf_file_start_time)

        return 0

    def SetBasicDefaults(self) -> int:
        """Sets default values for numerous build control flow variables."""
        self.env.SetValue("WORKSPACE", self.ws, "DEFAULT")
        if self.pp is not None:
            self.env.SetValue("PACKAGES_PATH", self.pp, "DEFAULT")
        return 0
