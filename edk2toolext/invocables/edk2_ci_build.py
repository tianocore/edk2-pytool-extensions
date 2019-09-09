# @file Edk2CiBuild.py
# This module contains code that supports CI/CD
# This is the main entry for the build and test process
# of Non-Product builds
##
# Copyright (c) Microsoft Corporation
#
# SPDX-License-Identifier: BSD-2-Clause-Patent
##
import os
import sys
import logging
import yaml
import traceback
from edk2toollib.uefi.edk2.path_utilities import Edk2Path
from edk2toollib.log.junit_report_format import JunitTestReport
from edk2toolext.edk2_invocable import Edk2Invocable
from edk2toolext.environment import self_describing_environment
from edk2toolext.environment.plugintypes.ci_build_plugin import ICiBuildPlugin
from edk2toolext.environment import shell_environment
from edk2toolext import edk2_logging
from edk2toolext import config_validator


class CiBuildSettingsManager():
    ''' Platform settings will be accessed through this implementation. '''

    def GetActiveScopes(self):
        ''' get scope '''
        raise NotImplementedError()

    def GetDependencies(self):
        pass

    def GetPackagesPath(self):
        pass

    # ####################################################################################### #
    #                        Default Support for this Ci Build                                #
    # ####################################################################################### #
    def GetPackagesSupported(self) -> iterable:
        ''' return iterable of edk2 packages supported by this build. 
        These should be edk2 workspace relative paths '''
        pass

    def GetArchitecturesSupported(self) -> iterable:
        ''' return iterable of edk2 architectures supported by this build ''' 
        raise NotImplementedError()

    def GetTargetsSupported(self):
        ''' return iterable of edk2 target tags supported by this build '''
        raise NotImplementedError()

    def GetWorkspaceRoot(self):
        ''' get WorkspacePath '''
        raise NotImplementedError()

    def GetName(self):
        ''' Get the name of the repo, platform, or product being build by CI '''
        raise NotImplementedError()

    def AddCommandLineOptions(self, parserObj):
        ''' Implement in subclass to add command line options to the argparser '''
        pass

    def RetrieveCommandLineOptions(self, args):
        '''  Implement in subclass to retrieve command line options from the argparser '''
        pass

    def GetLoggingLevel(self, loggerType):
        ''' Get the logging level for a given type
        base == lowest logging level supported
        con  == Screen logging
        txt  == plain text file logging
        md   == markdown file logging
        '''
        pass

    def GetPluginSettings(self):
        '''  Implement in subclass to pass dictionary of settings for individual plugins '''
        return {}

    # ####################################################################################### #
    #                     Verify and Save requested Ci Build Config                           #
    # ####################################################################################### #
    def SetToPackage(self, list_of_requested_packages):
        ''' Confirm the requests package list is valid and configure SettingsManager
        to build only the requested packages.

        Raise Exception if a requested_package is not supported
        '''
        pass

    def SetToArchitecture(self, list_of_requested_architectures):
        ''' Confirm the requests architecture list is valid and configure SettingsManager
        to run only the requested architectures.

        Raise Exception if a list_of_requested_architectures is not supported
        '''
        pass

    def SetToTarget(self, list_of_requested_target):
        ''' Confirm the requests target list is valid and configure SettingsManager
        to run only the requested targets.

        Raise Exception if a requested_target is not supported
        '''
        pass


def merge_config(config, pkg_config, descriptor={}):
    plugin_name = ""
    config = dict()
    if "module" in descriptor:
        plugin_name = descriptor["module"]
    if "config_name" in descriptor:
        plugin_name = descriptor["config_name"]

    if plugin_name == "":
        return config

    if plugin_name in config:
        config.update(config[plugin_name])

    if plugin_name in pkg_config:
        config.update(pkg_config[plugin_name])

    return config


class Edk2CiBuild(Edk2Invocable):
    def GetLoggingLevel(self, loggerType):
        ''' Get the logging level for a given type
        base == lowest logging level supported
        con  == Screen logging
        txt  == plain text file logging
        md   == markdown file logging
        '''
        if(loggerType == "con") and not self.Verbose:
            return logging.WARNING
        return logging.DEBUG

    def AddCommandLineOptions(self, parser):
        '''  Add command line options to the argparser '''
        # This will parse the packages that we are going to build
        parser.add_argument('-p', '--pkg', '--pkg-dir', dest='packageList', type=str,
                            help='A package or folder you want to test (workspace relative).'
                            'Can list multiple by doing -p <pkg1>,<pkg2> or -p <pkg3> -p <pkg4>',
                            action="append", default=[])
        parser.add_argument('-a', '--arch', dest="requested_arch", type=str, default=None,
                            help="CSV of architecutres requested to build. Example: -a X64,AARCH64")
        parser.add_argument('-t', '--target', dest='requested_target', type=str, default=None,
                            help="csv of targets requested to build.  Example: -t DEBUG,NOOPT")

    def RetrieveCommandLineOptions(self, args):
        '''  Retrieve command line options from the argparser '''
        packageListSet = set()
        for item in args.packageList:  # Parse out the individual packages
            item_list = item.split(",")
            for indiv_item in item_list:
                indiv_item = indiv_item.replace("\\", "/")  # in case cmdline caller used Windows folder slashes
                packageListSet.add(indiv_item.strip())
        self.requested_package_list = list(packageListSet)
        self.requested_architecture_list = args.requested_arch.upper().split(",")
        self.requested_target_list = args.requested_target.upper().split(",")

    def NotifySettingsManager(self):
        ''' Notify settings manager of Requested packages, arch, and targets'''
        if(len(self.requested_package_list) == 0):
            self.requested_package_list = list(self.PlatformSettings.GetPackagesSupported())
        self.PlatformSettings.SetToPackage(self.requested_package_list)
        
        if(len(self.requested_architecture_list) == 0):
            self.requested_architecture_list = list(self.PlatformSettings.GetArchitecturesSupported())
        PlatformSettings.SetToArchitecture(self.requested_architecture_list)

        if(len(self.requested_target_list) == 0):
            self.requested_target_list = list(self.PlatformSettings.GetTargetsSupported())
        PlatformSettings.SetToTarget(self.requested_target_list)

    def GetSettingsClass(self):
        return CiBuildSettingsManager

    def GetLoggingFileName(self, loggerType):
        return "CI_BUILDLOG"

    def Go(self):
        log_directory = os.path.join(self.GetWorkspaceRoot(), self.GetLoggingFolderRelativeToRoot())

        #
        # Get Package Path from config file
        pplist = self.PlatformSettings.GetPackagesPath() if self.PlatformSettings.GetPackagesPath() else []

        # make Edk2Path object to handle all path operations
        try:
            edk2path = Edk2Path(self.GetWorkspaceRoot(), pplist)
        except Exception as e:
            logging.error("Src Tree is invalid.  Did you Setup correctly?")
            raise e

        logging.info(f"Running CI Build: {self.PlatformSettings.GetName()}")
        logging.info(f"WorkSpace: {self.GetWorkspaceRoot()}")
        logging.info(f"Package Path: {pplist}")
        # Bring up the common minimum environment.
        logging.log(edk2_logging.SECTION, "Getting Environment")
        (build_env, shell_env) = self_describing_environment.BootstrapEnvironment(
            self.GetWorkspaceRoot(), self.GetActiveScopes())
        env = shell_environment.GetBuildVars()

        # Bind our current execution environment into the shell vars.
        ph = os.path.dirname(sys.executable)
        if " " in ph:
            ph = '"' + ph + '"'
        shell_env.set_shell_var("PYTHON_HOME", ph)
        # PYTHON_COMMAND is required to be set for using edk2 python builds.
        # todo: work with edk2 to remove the bat file and move to native python calls.
        #       This would be better in an edk2 plugin so that it could be modified/controlled
        #       more easily
        #
        pc = sys.executable
        if " " in pc:
            pc = '"' + pc + '"'
        shell_env.set_shell_var("PYTHON_COMMAND", pc)


        env.SetValue("TARGET_ARCH", " ".join(self.requested_architecture_list), "from edk2 ci build.py")

        # Generate consumable XML object- junit format
        JunitReport = JunitTestReport()

        # Keep track of failures
        failure_num = 0
        total_num = 0

        # Load plugins
        logging.log(edk2_logging.SECTION, "Loading plugins")

        pluginList = self.plugin_manager.GetPluginsOfClass(ICiBuildPlugin)

        for pkgToRunOn in self.requested_package_list:
            #
            # run all loaded Edk2CiBuild Plugins/Tests
            #
            logging.log(edk2_logging.SECTION, f"Building {pkgToRunOn} Package")
            logging.info(f"Running on Package: {pkgToRunOn}")
            package_class_name = f"Edk2CiBuild.{self.PlatformSettings.GetName()}.{pkgToRunOn}"
            ts = JunitReport.create_new_testsuite(pkgToRunOn, package_class_name)
            packagebuildlog_path = os.path.join(log_directory, pkgToRunOn)
            _, txthandle = edk2_logging.setup_txt_logger(
                packagebuildlog_path, f"BUILDLOG_{pkgToRunOn}", logging_level=logging.DEBUG, isVerbose=True)
            _, mdhandle = edk2_logging.setup_markdown_logger(
                packagebuildlog_path, f"BUILDLOG_{pkgToRunOn}", logging_level=logging.DEBUG, isVerbose=True)
            loghandle = [txthandle, mdhandle]
            shell_environment.CheckpointBuildVars()
            env = shell_environment.GetBuildVars()

            # load the package level .mu.json
            pkg_config_file = edk2path.GetAbsolutePathOnThisSytemFromEdk2RelativePath(
                os.path.join(pkgToRunOn, pkgToRunOn + ".mu.yaml"))
            if(pkg_config_file):
                with open(pkg_config_file, 'r') as f:
                    pkg_config = yaml.safe_load(f)
            else:
                logging.info(f"No Pkg Config file for {pkgToRunOn}")
                pkg_config = dict()

            # check the resulting configuration
            config_validator.check_package_confg(pkgToRunOn, pkg_config, pluginList)

            # get all the defines from the package configuration
            if "Defines" in pkg_config:
                for definition_key in pkg_config["Defines"]:
                    definition = pkg_config["Defines"][definition_key]
                    env.SetValue(definition_key, definition, "Edk2CiBuild.py from PkgConfig yaml", False)

            # For each plugin
            for Descriptor in pluginList:
                # For each target
                for target in self.requested_target_list:
                    edk2_logging.log_progress(f"--Running {pkgToRunOn}: {Descriptor.Name} {target} --")
                    total_num += 1
                    shell_environment.CheckpointBuildVars()
                    env = shell_environment.GetBuildVars()

                    env.SetValue("TARGET", target, "Edk2CiBuild.py before RunBuildPlugin")
                    (testcasename, testclassname) = Descriptor.Obj.GetTestName(package_class_name, env)
                    tc = ts.create_new_testcase(testcasename, testclassname)

                    # create the stream for the build log
                    plugin_output_stream = edk2_logging.create_output_stream()

                    # merge the repo level and package level for this specific plugin
                    pkg_plugin_configuration = merge_config(self.PlatformSettings.GetPluginSettings(),
                                                            pkg_config, Descriptor.descriptor)

                    # Still need to see if the package decided this should be skipped
                    if pkg_plugin_configuration is None or\
                            "skip" in pkg_plugin_configuration and pkg_plugin_configuration["skip"]:
                        tc.SetSkipped()
                        edk2_logging.log_progress("--->Test Skipped by package! %s" % Descriptor.Name)

                    else:
                        try:
                            #   - package is the edk2 path to package.  This means workspace/packagepath relative.
                            #   - edk2path object configured with workspace and packages path
                            #   - any additional command line args
                            #   - RepoConfig Object (dict) for the build
                            #   - PkgConfig Object (dict)
                            #   - EnvConfig Object
                            #   - Plugin Manager Instance
                            #   - Plugin Helper Obj Instance
                            #   - testcase Object used for outputing junit results
                            #   - output_stream the StringIO output stream from this plugin
                            rc = Descriptor.Obj.RunBuildPlugin(pkgToRunOn, edk2path, pkg_plugin_configuration,
                                                               env, self.plugin_manager, self.helper,
                                                               tc, plugin_output_stream)
                        except Exception as exp:
                            exc_type, exc_value, exc_traceback = sys.exc_info()
                            logging.critical("EXCEPTION: {0}".format(exp))
                            exceptionPrint = traceback.format_exception(type(exp), exp, exc_traceback)
                            logging.critical(" ".join(exceptionPrint))
                            tc.SetError("Exception: {0}".format(
                                exp), "UNEXPECTED EXCEPTION")
                            rc = 1

                        if(rc > 0):
                            failure_num += 1
                            if(rc is None):
                                logging.error(
                                    f"--->Test Failed: {Descriptor.Name} {target} returned NoneType")
                            else:
                                logging.error(
                                    f"--->Test Failed: {Descriptor.Name} {target} returned {rc}")
                        elif(rc < 0):
                            logging.warn(f"--->Test Skipped: in plugin! {Descriptor.Name} {target}")
                        else:
                            edk2_logging.log_progress(f"--->Test Success: {Descriptor.Name} {target}")

                    # revert to the checkpoint we created previously
                    shell_environment.RevertBuildVars()
                    # remove the logger
                    edk2_logging.remove_output_stream(plugin_output_stream)

                    if not Descriptor.Obj.IsTargetDependent():
                        # Plugin isn't Target Dependent -- break out of loop
                        break
                # finished target loop
            # Finished plugin loop

            edk2_logging.stop_logging(loghandle)  # stop the logging for this particular buildfile
            shell_environment.RevertBuildVars()
        # Finished buildable file loop

        JunitReport.Output(os.path.join(self.GetWorkspaceRoot(), "Build", "TestSuites.xml"))

        # Print Overall Success
        if(failure_num != 0):
            logging.error("Overall Build Status: Error")
            edk2_logging.log_progress(f"There were {failure_num} failures out of {total_num} attempts")
        else:
            edk2_logging.log_progress("Overall Build Status: Success")

        return failure_num


def main():
    Edk2CiBuild().Invoke()
