# @file edk2_report.py
# Parses a UEFI workspace and generates reports are requested.
##
# Copyright (c) Microsoft Corporation
#
# SPDX-License-Identifier: BSD-2-Clause-Patent
##
"""A Uefi workspace parser and report generator."""
import inspect
import logging
import os
import time
import yaml

from argparse import ArgumentParser
from pathlib import Path
from random import choice
from string import ascii_letters
from tinydb import TinyDB
from tinydb.middlewares import CachingMiddleware
from tinydb.storages import JSONStorage

from edk2toolext import edk2_logging
from edk2toolext.workspace import reports, parsers
from edk2toolext.environment.uefi_build import UefiBuilder
from edk2toolext.environment import shell_environment
from edk2toolext.invocables.edk2_multipkg_aware_invocable import Edk2MultiPkgAwareInvocable
from edk2toolext.invocables.edk2_multipkg_aware_invocable import MultiPkgAwareSettingsInterface
from edk2toollib.uefi.edk2.path_utilities import Edk2Path
from edk2toollib.utility_functions import locate_class_in_module, import_module_by_file_name


DB_NAME = "DATABASE.db"
TARGET_LIST = ["DEBUG", "RELEASE"]


class ReportSettingsManager(MultiPkgAwareSettingsInterface):
    """Settings to support ReportSettingsManager functionality."""
    pass


class Edk2Report(Edk2MultiPkgAwareInvocable):
    """An invocable used to parse the environment and run reports.

    This invocable is split into two main focuses: Workspace parsing and Report Generation.

    When it comes to workspace parsing, this invocable has the ability to parse both a repo containing generic
    Edk2 packages, and a repo containing platform packages. When the goal is to parse the workspace' Edk2 packages,
    The Edk2Report Generator uses methods from the MultiPkgAwareSettingsInterface, which is most commonly found in
    a CI Settings File. In this scenario, it will either parse all packages defined by `GetPackagesSupported()` or
    a subset of those packages as defined by the -p flag. The same can be said about the architectures by using
    `GetDefinedArchitectures()` and the -a command.

    When the goal is to parse a platform package, the Edk2Report Generator uses methods from the `UefiBuilder`, which
    is most commonly found in the Platform Build File. In this scenario, it will invoking the methods found in
    `UefiBuilder` which are used to build a platform. It will not execute any plugins, build the platform, nor execute
    any functionality normally called after the build command.

    Addionally, any build variables can be overwritten or added via the command line VAR=VALUE functionality.
    """

    def __init__(self):
        """Initializes an Edk2Report Object."""
        super().__init__()
        self.is_uefi_builder = False

    def GetSettingsClass(self):
        """Returns the Settings Manager for the invocable."""
        return ReportSettingsManager

    def ParseCommandLineOptions(self,):
        """Overrides Edk2Invocable's ParseCommandLineOption()."""
        # Add the subcommand agnostic options here.
        parser = ArgumentParser("A tool to generate reports on a edk2 workspace.")
        parser.add_argument('--verbose', '--VERBOSE', '-v', dest="verbose", action='store_true', default=False,
                            help='verbose')
        parser.add_argument('-c', '--platform_module', required=True,
                            dest='platform_module', help='Provide the Platform Module relative to the current working '
                            f' directory. This should contain a {self.GetSettingsClass().__name__} instance.')
        parser.add_argument('-p', '--pkg', '--pkg-dir', dest='package_list', type=str,
                            help='Optional - A package list of packages to parse.'
                            'Can list multiple by doing -p <pkg1>,<pkg2> or -p <pkg3> -p <pkg4>',
                            action="append", default=[])
        parser.add_argument('-a', '--arch', dest="arch_list", type=str, default="",
                            help='Optional - A list of architectures to use when parsing.'
                            'Can list multiple by doing -a <arch1>,<arch2> or -a <arch1> -a <arch2>')
        subparsers = parser.add_subparsers(dest='cmd', required=[])

        # Add the parse subcommand options here.
        parse_parser = subparsers.add_parser("parse", help="Parse the workspace and generate a database.")
        parse_parser.add_argument("-db", "--database", "--Database", "--DATABASE",
                                  dest="database", action="store", help="Set the database rather then parse for one.")
        parse_parser.add_argument('--build-config', dest='build_config', default="",
                                  type=str, help='Provide shell variables in a file')

        # Add all report subcommand options here.
        for report in self.get_reports():
            name, description = report.report_info()
            report_parser = subparsers.add_parser(name, help=description)
            report.add_cli_options(report_parser)

        settings_args, unknown_args = parser.parse_known_args()

        # Set verbosity and remove it from args
        self.Verbose = settings_args.verbose
        del settings_args.verbose

        # Set module and remove it from args
        try:
            self.PlatformModule = import_module_by_file_name(Path(settings_args.platform_module).absolute())
            self.PlatformSettings = locate_class_in_module(self.PlatformModule, self.GetSettingsClass())()
            self.is_uefi_builder = locate_class_in_module(self.PlatformModule, UefiBuilder) is not None
        except:
            e = f'{settings_args.platform_module} does not contain a {self.GetSettingsClass().__name__} instance.'
            logging.error(e)
            raise RuntimeError(e)
        del settings_args.platform_module

        # Save the rest of the arguments
        self.args = settings_args

        # Set Package and architecture if not specified. Not applicable if using a UefiBuilder
        if not self.is_uefi_builder:
            self.args.package_list = self.args.package_list or self.PlatformSettings.GetPackagesSupported()
            self.args.arch_list = self.args.arch_list or self.PlatformSettings.GetArchitecturesSupported()
            self._format_package_and_arch_list(self.args)

        # Parse any build variables added via the command line
        env = shell_environment.GetBuildVars()
        for argument in unknown_args:
            if argument.count('=') == 1:
                tokens = argument.strip().split('=')
                env.SetValue(tokens[0].strip().upper(), tokens[1].strip(), "From Command Line")
            elif argument.count("=") == 0:
                env.SetValue(argument.strip().upper(),
                             ''.join(choice(ascii_letters) for _ in range(20)), "Non valued variable set From cmdLine")
            else:
                raise RuntimeError(f'Unknown variable passed in via CLI: {argument}')

    def GetLoggingFolderRelativeToRoot(self):
        """Returns the folder to place logging files in."""
        return "Report"

    def GetLoggingFileName(self, loggerType):
        """Returns the logging file name for this invocation."""
        return self.args.cmd.upper() + "_LOG"

    # def GetActiveScopes(self):
    #     """Returns the scopes."""
    #     return ("global",)

    def Go(self):
        """Executes the invocable. Runs the subcommand specified by the user."""
        db_path = Path(self.GetWorkspaceRoot()) / self.GetLoggingFolderRelativeToRoot() / DB_NAME
        args = self.args

        # Set commonly used arguments
        args.workspace_root = self.GetWorkspaceRoot()
        args.packages_path_list = list(self.PlatformSettings.GetPackagesPath())

        if args.cmd == 'parse':
            return self.parse_workspace(db_path, args)
        return self.run_report(self.args, db_path)

    def parse_workspace(self, db_path: Path, args):
        """Runs all defined workspace parsers to generate a database."""
        # Delete database if it exists and recreate it.
        db_path.unlink(missing_ok=True)
        db_path.touch()

        # If we are provided a database, copy it to our preferred location.
        if args.database:
            return self.replace_database(db_path, Path(args.database))

        pathobj = Edk2Path(self.GetWorkspaceRoot(), self.GetPackagesPath())
        env = shell_environment.GetBuildVars()

        with TinyDB(db_path, access_mode='r+', storage=CachingMiddleware(JSONStorage)) as db:
            # Run all non-dsc setting specific parsers
            for parser in self.get_parsers(need_dsc=False):
                logging.log(edk2_logging.SECTION, f"[{parser.__class__.__name__}] starting...")
                start = time.time()
                parser.parse_workspace(db, pathobj, env)
                logging.log(edk2_logging.PROGRESS, f"Finished in {round(time.time() - start, 2)} seconds.")

            logging.log(edk2_logging.SECTION, "Preparing environment for running build setting specific parsers.")
            logging.debug(f'Scopes: {self.GetActiveScopes()}')
            if self.is_uefi_builder:
                logging.debug("Setting environment variables with UefiBuilder.")
                return self.parse_with_builder_settings(db, pathobj, env)
            else:
                logging.debug("Setting environment variables from CI settings.")
                return self.parse_with_ci_settings(db, pathobj, env)

    def parse_with_builder_settings(self, db, pathobj, env):
        """Parses the workspace using a uefi builder to setup the environment."""
        # Add environment variables from the build config (If doing UefiBuilder Only)
        build_config = self.args.build_config or Path(self.GetWorkspaceRoot(), "BuildConfig.conf")
        self._add_build_config_env(Path(build_config), env)

        for target in TARGET_LIST:
            shell_environment.CheckpointBuildVars()
            env.SetValue('TARGET', target, "Set automatically.")
            exception_msg = ""
            try:
                if not self.Verbose:
                    logging.disable(logging.CRITICAL)  # Disable logging when running the UefiBuilder.
                platform_module = locate_class_in_module(self.PlatformModule, UefiBuilder)
                if platform_module:
                    build_settings = platform_module()
                    build_settings.Clean = False
                    build_settings.SkipPreBuild = True
                    build_settings.SkipBuild = True
                    build_settings.SkipPostBuild = True
                    build_settings.FlashImage = False
                    build_settings.Go(self.GetWorkspaceRoot(), os.pathsep.join(self.GetPackagesPath()),
                                      self.helper, self.plugin_manager)
                    build_settings.PlatformPreBuild()
            except Exception as e:
                exception_msg = e
            finally:
                if not self.Verbose:
                    logging.disable(logging.NOTSET)
            if exception_msg:
                logging.error("Failed to run UefiBuilder to set the environment.")
                logging.error(exception_msg)
                return -1

            for key, value in (env.GetAllBuildKeyValues() | env.GetAllNonBuildKeyValues()).items():
                logging.debug(f"  {key} = {value}")
            for parser in self.get_parsers(need_dsc=True):
                logging.log(
                    edk2_logging.SECTION,
                    f"[{parser.__class__.__name__}] starting {Path(env.GetValue('ACTIVE_PLATFORM')).stem} "
                    f"[{env.GetValue('TARGET')}][{env.GetValue('TARGET_ARCH')}]: ")
                start = time.time()
                parser.parse_workspace(db, pathobj, env)
                logging.log(edk2_logging.PROGRESS, f"Finished in {round(time.time() - start, 2)} seconds.")
            shell_environment.RevertBuildVars()
        return 0

    def parse_with_ci_settings(self, db, pathobj, env):
        """Parses the workspace using ci settings to setup the environment."""
        for target in ["DEBUG", "RELEASE"]:
            for package in self.args.package_list:
                shell_environment.CheckpointBuildVars()
                env.SetValue("TARGET", target, "Set Automatically")

                pkg_config = self._get_package_config(pathobj, package)
                dsc = pkg_config.get("CompilerPlugin", {"DscPath": ""})["DscPath"]
                if not dsc:
                    return
                dsc = str(Path(package, dsc))

                env.SetValue("ACTIVE_PLATFORM", dsc, "Set Automatically")
                env.SetValue("TARGET_ARCH", ",".join(self.args.arch_list), "Set Automatically")

                # Load the Defines
                for key, value in pkg_config.get("Defines", {}).items():
                    env.SetValue(key, value, "Defined in Package CI yaml")

                # Actually run them
                for parser in self.get_parsers(need_dsc=True):
                    logging.log(
                        edk2_logging.SECTION,
                        f"[{parser.__class__.__name__}] starting {env.GetValue('ACTIVE_PLATFORM')} "
                        f"[{env.GetValue('TARGET')}][{env.GetValue('ARCH')}]: ")
                    start = time.time()
                    parser.parse_workspace(db, pathobj, env)
                    logging.log(edk2_logging.PROGRESS, f"Finished in {round(time.time() - start, 2)} seconds.")
                shell_environment.RevertBuildVars()
        return 0

    def run_report(self, args, db_path):
        """Runs the specified report."""
        with TinyDB(db_path, access_mode='r', storage=CachingMiddleware(JSONStorage)) as db:
            for report in self.get_reports():
                name, _ = report.report_info()
                if name == args.cmd:
                    return report.run_report(db, self.args)
            return -1  # Should never happen as we verify the subcommand when parsing arguments.

    def get_parsers(self, need_dsc=False) -> list:
        """Returns a list of un-instantiated DbDocument subclass parsers."""
        parser_list = []

        # Automatically grab all parsers and filter by the need of a dsc
        for _, obj in inspect.getmembers(parsers):
            if inspect.isclass(obj) and issubclass(obj, parsers.WorkspaceParser) and obj != parsers.WorkspaceParser:
                if need_dsc == obj().is_dsc_scoped():
                    parser_list.append(obj())
        return parser_list

    def get_reports(self) -> list:
        """Returns a list of report generators."""
        report_list = []

        # Automatically grab all report types
        for _, obj in inspect.getmembers(reports):
            if inspect.isclass(obj) and issubclass(obj, reports.WorkspaceReport) and obj != reports.WorkspaceReport:
                report_list.append(obj())
        return report_list

    def replace_database(self, cur_path: Path, replace_path: Path):
        """Replaces the contents of cur_path with replace_path."""
        if not replace_path.is_file():
            e = f'{self.args.database} is not a file.'
            logging.error(e)
            raise ValueError(e)
        else:
            cur_path.write_text(replace_path).read_text()
            return

    def InputParametersConfiguredCallback(self):
        """Perform actions after input parameters have been configured."""
        return

    def _add_build_config_env(self, path: Path, env):
        """Adds build configuration variables to the env."""
        if not path.is_file():
            logging.debug(f"build config [{path}] is not a file.")
            return

        argument_list = []
        with open(path, 'r') as file:
            for line in file:
                stripped_line = line.strip().partition("#")[0]
                if len(stripped_line) == 0:
                    continue
                argument_list.append(stripped_line)

        for argument in argument_list:
            if argument.count('=') == 1:
                tokens = argument.strip().split('=')
                env.SetValue(tokens[0].strip().upper(), tokens[1].strip(), "From Command Line")
            elif argument.count("=") == 0:
                env.SetValue(argument.strip().upper(),
                             ''.join(choice(ascii_letters) for _ in range(20)),
                             "Non valued variable set From cmdLine")
            else:
                raise RuntimeError(f'Unknown variable passed in via CLI: {argument}')

    def _get_package_config(self, pathobj: Edk2Path, pkg) -> str:
        """Gets configuration information for a package from the ci.yaml file."""
        pkg_config_file = pathobj.GetAbsolutePathOnThisSystemFromEdk2RelativePath(
            str(Path(pkg, pkg + ".ci.yaml"))
        )
        if pkg_config_file:
            with open(pkg_config_file, 'r') as f:
                return yaml.safe_load(f)
        else:
            logging.debug(f"No package config file for {pkg}")
            return {}

    def _format_package_and_arch_list(self, args):
        """Flattens the package and arch list.

        These lists can come in the form of ["Arch1", "Arch2", "Arch3"], ["Arch1,Arch2", "Arch3"]
        We transform them to always be ["Arch1", "Arch2", "Arch3"]
        """
        # Parse out the individual packages
        package_list = set()
        for item in args.package_list:
            item_list = item.split(",")
            for individual_item in item_list:
                # in case cmd line caller used Windows folder slashes
                individual_item = individual_item.replace("\\", "/").rstrip("/")
                package_list.add(individual_item.strip())
        args.package_list = list(package_list)

        arch_list = set()
        for item in args.arch_list:
            item_list = item.split(",")
            for individual_item in item_list:
                arch_list.add(individual_item.strip())
        args.arch_list = list(arch_list)


def main():
    """Entry point to invoke Edk2PlatformSetup."""
    Edk2Report().Invoke()
