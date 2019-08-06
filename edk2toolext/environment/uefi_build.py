# @file uefi_build.py
# This module contains code that supports the Tianocore Edk2 build system
# This class is designed to be subclassed by a platform to allow
# more extensive and custom behavior.
##
# Copyright (c) Microsoft Corporation
#
# SPDX-License-Identifier: BSD-2-Clause-Patent
##


import os
import logging
from edk2toolext.environment.multiple_workspace import MultipleWorkspace
from edk2toolext.environment import conf_mgmt
import traceback
import shutil
import time
from edk2toolext.environment import shell_environment
from edk2toollib.uefi.edk2.parsers.targettxt_parser import TargetTxtParser
from edk2toollib.uefi.edk2.parsers.dsc_parser import DscParser
from edk2toollib.utility_functions import RunCmd
from edk2toolext import edk2_logging
from edk2toolext.environment.plugintypes.uefi_build_plugin import IUefiBuildPlugin
import datetime


class UefiBuilder(object):

    def __init__(self):
        self.SkipBuild = False
        self.SkipPreBuild = False
        self.SkipPostBuild = False
        self.FlashImage = False
        self.ShowHelpOnly = False
        self.OutputBuildEnvBeforeBuildToFile = None
        self.Clean = False
        self.UpdateConf = False
        self.OutputConfig = None

    def AddCommandLineOptions(self, parserObj):
        ''' adds command line options to the argparser '''
        parserObj.add_argument("--SKIPBUILD", "--skipbuild", "--SkipBuild", dest="SKIPBUILD",
                               action='store_true', default=False, help="Skip the build process")
        parserObj.add_argument("--SKIPPREBUILD", "--skipprebuild", "--SkipPrebuild", dest="SKIPPREBUILD",
                               action='store_true', default=False, help="Skip prebuild process")
        parserObj.add_argument("--SKIPPOSTBUILD", "--skippostbuild", "--SkipPostBuild", dest="SKIPPOSTBUILD",
                               action='store_true', default=False, help="Skip postbuild process")
        parserObj.add_argument("--FLASHONLY", "--flashonly", "--FlashOnly", dest="FLASHONLY",
                               action='store_true', default=False, help="Flash rom after build.")
        parserObj.add_argument("--FLASHROM", "--flashrom", "--FlashRom", dest="FLASHROM",
                               action='store_true', default=False, help="Flash rom.  Rom must be built previously.")
        parserObj.add_argument("--UPDATECONF", "--updateconf", "--UpdateConf",
                               dest="UPDATECONF", action='store_true', default=False,
                               help="Update Conf. Builders Conf files will be replaced with latest template files")
        parserObj.add_argument("--CLEAN", "--clean", "--CLEAN", dest="CLEAN",
                               action='store_true', default=False,
                               help="Clean. Remove all old build artifacts and intermediate files")
        parserObj.add_argument("--CLEANONLY", "--cleanonly", "--CleanOnly", dest="CLEANONLY",
                               action='store_true', default=False,
                               help="Clean Only. Do clean operation and don't build just exit.")
        parserObj.add_argument("--OUTPUTCONFIG", "--outputconfig", "--OutputConfig",
                               dest='OutputConfig', required=False, type=str,
                               help='Provide shell variables in a file')

    def RetrieveCommandLineOptions(self, args):
        '''  Retrieve command line options from the argparser'''
        self.OutputConfig = os.path.abspath(args.OutputConfig) if args.OutputConfig else None

        if(args.SKIPBUILD):
            self.SkipBuild = True
        elif(args.SKIPPREBUILD):
            self.SkipPreBuild = True
        elif(args.SKIPPOSTBUILD):
            self.SkipPostBuild = True
        elif(args.FLASHONLY):
            self.SkipPostBuild = True
            self.SkipBuild = True
            self.SkipPreBuild = True
            self.FlashImage = True
        elif(args.FLASHROM):
            self.FlashImage = True
        elif(args.UPDATECONF):
            self.UpdateConf = True
        elif(args.CLEAN):
            self.Clean = True
        elif(args.CLEANONLY):
            self.Clean = True
            self.SkipBuild = True
            self.SkipPreBuild = True
            self.SkipPostBuild = True
            self.FlashImage = False

    def Go(self, WorkSpace, PackagesPath, PInHelper, PInManager):
        self.env = shell_environment.GetBuildVars()
        self.mws = MultipleWorkspace()
        self.mws.setWs(WorkSpace, PackagesPath)
        self.ws = WorkSpace
        self.pp = PackagesPath  # string using os.pathsep
        self.Helper = PInHelper
        self.pm = PInManager

        try:
            edk2_logging.log_progress("Start time: {0}".format(datetime.datetime.now()))
            start_time = time.perf_counter()

            self.Helper.DebugLogRegisteredFunctions()

            ret = self.SetEnv()
            if(ret != 0):
                logging.critical("SetEnv failed")
                return ret

            # clean
            if(self.Clean):
                edk2_logging.log_progress("Cleaning")
                ret = self.CleanTree()
                if(ret != 0):
                    logging.critical("Clean failed")
                    return ret

            # prebuild
            if(self.SkipPreBuild):
                edk2_logging.log_progress("Skipping Pre Build")
            else:
                ret = self.PreBuild()
                if(ret != 0):
                    logging.critical("Pre Build failed")
                    return ret

            # Output Build Environment to File - this is mostly for debug of build
            # issues or adding other build features using existing variables
            if(self.OutputConfig is not None):
                edk2_logging.log_progress("Writing Build Env Info out to File")
                logging.debug("Found an Output Build Env File: " + self.OutputConfig)
                self.env.PrintAll(self.OutputConfig)

            if(self.env.GetValue("GATEDBUILD") is not None) and (self.env.GetValue("GATEDBUILD").upper() == "TRUE"):
                ShouldGatedBuildRun = self.PlatformGatedBuildShouldHappen()
                logging.debug("Platform Gated Build Should Run returned: %s" % str(
                    ShouldGatedBuildRun))
                if(not self.SkipBuild):
                    self.SkipBuild = not ShouldGatedBuildRun
                if(not self.SkipPostBuild):
                    self.SkipPostBuild = not ShouldGatedBuildRun

            # build
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

            # flash
            if(self.FlashImage):
                edk2_logging.log_progress("Flashing Image")
                ret = self.FlashRomImage()
                if(ret != 0):
                    logging.critical("Flash Image failed")
                    return ret

        except:
            logging.critical("Build Process Exception")
            logging.error(traceback.format_exc())
            return -1
        finally:
            end_time = time.perf_counter()
            elapsed_time_s = int((end_time - start_time))
            edk2_logging.log_progress("End time: {0}\t Total time Elapsed: {1}".format(
                datetime.datetime.now(), datetime.timedelta(seconds=elapsed_time_s)))

        return 0

    def CleanTree(self, RemoveConfTemplateFilesToo=False):
        ret = 0
        # loop thru each build target set.
        edk2_logging.log_progress("Cleaning All Output for Build")

        d = self.env.GetValue("BUILD_OUTPUT_BASE")
        if(os.path.isdir(d)):
            logging.debug("Removing [%s]", d)
            # if the folder is opened in Explorer do not fail the entire Rebuild
            try:
                shutil.rmtree(d)
            except WindowsError as wex:
                logging.debug(wex)

        else:
            logging.debug("Directory [%s] already clean" % d)

        # delete the conf .dbcache
        # this needs to be removed in case build flags changed
        d = os.path.join(self.ws, "Conf", ".cache")
        if(os.path.isdir(d)):
            shutil.rmtree(d)
            logging.debug("Removing [%s]" % d)

        if(RemoveConfTemplateFilesToo):
            for a in ["target.txt", "build_rule.txt", "tools_def.txt"]:
                d = os.path.join(self.ws, "Conf", a)
                if(os.path.isfile(d)):
                    os.remove(d)
                    logging.debug("Removing [%s]" % d)

        return ret

    #
    # Build step
    #

    def Build(self):
        BuildType = self.env.GetValue("TARGET")
        edk2_logging.log_progress("Running Build %s" % BuildType)

        # set target, arch, toolchain, threads, and platform
        params = "-p " + self.env.GetValue("ACTIVE_PLATFORM")
        params += " -b " + BuildType
        params += " -t " + self.env.GetValue("TOOL_CHAIN_TAG")
        params += " -n " + self.env.GetValue("MAX_CONCURRENT_THREAD_NUMBER")

        # Set the arch flags.  Multiple are split by space
        rt = self.env.GetValue("TARGET_ARCH").split(" ")
        for t in rt:
            params += " -a " + t

        # get the report options and setup the build command
        if(self.env.GetValue("BUILDREPORTING") == "TRUE"):
            params += " -y " + self.env.GetValue("BUILDREPORT_FILE")
            rt = self.env.GetValue("BUILDREPORT_TYPES").split(" ")
            for t in rt:
                params += " -Y " + t

        # add special processing to handle building a single module
        mod = self.env.GetValue("BUILDMODULE")
        if(mod is not None and len(mod.strip()) > 0):
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
        env.set_shell_var('PYTHONHASHSEED', '0')
        env.log_environment()
        ret = RunCmd("build", params)
        # WORKAROUND - Undo the workaround.
        env.restore_checkpoint(pre_build_env_chk)

        problems = edk2_logging.scan_compiler_output(output_stream)
        edk2_logging.remove_output_stream(output_stream)
        for level, problem in problems:
            logging.log(level, problem)

        if(ret != 0):
            return ret

        return 0

    def PreBuild(self):
        edk2_logging.log_progress("Running Pre Build")
        #
        # Run the plaform pre-build steps.
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

    def SetEnv(self):
        edk2_logging.log_progress("Setting up the Environment")
        shell_environment.GetEnvironment().set_shell_var("WORKSPACE", self.ws)
        shell_environment.GetBuildVars().SetValue("WORKSPACE", self.ws, "Set in SetEnv")

        if(self.pp is not None):
            shell_environment.GetEnvironment().set_shell_var("PACKAGES_PATH", self.pp)
            shell_environment.GetBuildVars().SetValue(
                "PACKAGES_PATH", self.pp, "Set in SetEnv")

        # process platform parameters defined in platform build file
        ret = self.SetPlatformEnv()
        if(ret != 0):
            logging.critical("Set Platform Env failed")
            return ret

        # set some basic defaults
        self.SetBasicDefaults()

        # Handle all the template files for workspace/conf/ Allow override
        TemplatesForConf = self.env.GetValue("CONF_TEMPLATE_DIR")
        if(TemplatesForConf is not None):
            TemplatesForConf = self.mws.join(self.ws, TemplatesForConf)
            logging.debug(
                "Platform defined override for Template Conf Files: %s", TemplatesForConf)
        e = conf_mgmt.ConfMgmt(self.UpdateConf, TemplatesForConf)

        # parse target file
        ret = self.ParseTargetFile()
        if(ret != 0):
            logging.critical("ParseTargetFile failed")
            return ret

        ret = e.ToolsDefConfigure()
        if(ret != 0):
            logging.critical("ParseTargetFile failed")
            return ret

        # parse DSC file
        ret = self.ParseDscFile()
        if(ret != 0):
            logging.critical("ParseDscFile failed")
            return ret

        # parse FDF file
        ret = self.ParseFdfFile()
        if(ret != 0):
            logging.critical("ParseFdfFile failed")
            return ret

        # set build output base envs for all builds
        self.env.SetValue("BUILD_OUT_TEMP", os.path.join(
            self.ws, self.env.GetValue("OUTPUT_DIRECTORY")), "Computed in SetEnv")

        target = self.env.GetValue("TARGET")
        self.env.SetValue("BUILD_OUTPUT_BASE", os.path.join(self.env.GetValue(
            "BUILD_OUT_TEMP"), target + "_" + self.env.GetValue("TOOL_CHAIN_TAG")), "Computed in SetEnv")

        # We have our build target now.  Give platform build one more chance for target specific settings.
        ret = self.SetPlatformEnvAfterTarget()
        if(ret != 0):
            logging.critical("SetPlatformEnvAfterTarget failed")
            return ret

        # set the build report file
        self.env.SetValue("BUILDREPORT_FILE", os.path.join(
            self.env.GetValue("BUILD_OUTPUT_BASE"), "BUILD_REPORT.TXT"), True)

        # set environment variables for the build process
        os.environ["EFI_SOURCE"] = self.ws

        return 0

    def FlashRomImage(self):
        return self.PlatformFlashImage()

    # -----------------------------------------------------------------------
    # Methods that will be overridden by child class
    # -----------------------------------------------------------------------

    @classmethod
    def PlatformPreBuild(self):
        return 0

    @classmethod
    def PlatformPostBuild(self):
        return 0

    @classmethod
    def SetPlatformEnv(self):
        return 0

    @classmethod
    def SetPlatformEnvAfterTarget(self):
        return 0

    @classmethod
    def PlatformBuildRom(self):
        return 0

    @classmethod
    def PlatformFlashImage(self):
        return 0

    @classmethod
    def PlatformGatedBuildShouldHappen(self):
        return True

    # ------------------------------------------------------------------------
    #  HELPER FUNCTIONS
    # ------------------------------------------------------------------------
    #

    #
    # Parse the TargetText file and add them as env settings.
    # set them so they can be overridden.
    #
    def ParseTargetFile(self):
        if(os.path.isfile(self.mws.join(self.ws, "Conf", "target.txt"))):
            # parse TargetTxt File
            logging.debug("Parse Target.txt file")
            ttp = TargetTxtParser()
            ttp.ParseFile(self.mws.join(self.ws, "Conf", "target.txt"))
            for key, value in ttp.Dict.items():
                # set env as overrideable
                self.env.SetValue(key, value, "From Target.txt", True)

        else:
            logging.error("Failed to find target.txt file")
            return -1

        return 0

    #
    # Parse the Active platform DSC file.  This will get lots of variable info to
    # be used in the build.  This makes it so we don't have to define things twice
    #

    def ParseDscFile(self):
        dsc_file_path = self.mws.join(
            self.ws, self.env.GetValue("ACTIVE_PLATFORM"))
        if(os.path.isfile(dsc_file_path)):
            # parse DSC File
            logging.debug(
                "Parse Active Platform DSC file: {0}".format(dsc_file_path))
            dscp = DscParser().SetBaseAbsPath(self.ws).SetPackagePaths(
                self.pp.split(os.pathsep)).SetInputVars(self.env.GetAllBuildKeyValues())
            dscp.ParseFile(dsc_file_path)
            for key, value in dscp.LocalVars.items():
                # set env as overrideable
                self.env.SetValue(key, value, "From Platform DSC File", True)

        else:
            logging.error("Failed to find DSC file")
            return -1

        return 0

    #
    # Parse the Active platform FDF file.  This will get lots of variable info to
    # be used in the build.  This makes it so we don't have to define things twice
    # the FDF file usually comes from the Active Platform DSC file so it needs to
    # be parsed first.
    #
    def ParseFdfFile(self):
        if(self.env.GetValue("FLASH_DEFINITION") is None):
            logging.debug("No flash definition set")
            return 0
        if(os.path.isfile(self.mws.join(self.ws, self.env.GetValue("FLASH_DEFINITION")))):
            # parse the FDF file- fdf files have similar syntax to DSC and therefore parser works for both.
            logging.debug("Parse Active Flash Definition (FDF) file")
            fdfp = DscParser().SetBaseAbsPath(self.ws).SetPackagePaths(
                self.pp.split(os.pathsep)).SetInputVars(self.env.GetAllBuildKeyValues())
            pa = self.mws.join(self.ws, self.env.GetValue("FLASH_DEFINITION"))
            fdfp.ParseFile(pa)
            for key, value in fdfp.LocalVars.items():
                self.env.SetValue(key, value, "From Platform FDF File", True)

        else:
            logging.error("Failed to find FDF file")
            return -2

        return 0

    #
    # Function used to set default values for numerous build
    # flow control variables
    #
    def SetBasicDefaults(self):
        self.env.SetValue("WORKSPACE", self.ws, "DEFAULT")
        if(self.pp is not None):
            self.env.SetValue("PACKAGES_PATH", self.pp, "DEFAULT")
        return 0
