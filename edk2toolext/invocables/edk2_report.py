import logging
import os
import time
import yaml
from pathlib import Path
from argparse import ArgumentParser

from tinydb import TinyDB
from tinydb.middlewares import CachingMiddleware
from tinydb.storages import JSONStorage
from random import choice
from string import ascii_letters

from edk2toolext import edk2_logging
from edk2toolext.base_abstract_invocable import BaseAbstractInvocable
from edk2toolext.environment.uefi_build import UefiBuilder
from edk2toolext.environment.plugintypes.uefi_helper_plugin import HelperFunctions
from edk2toolext.environment import plugin_manager
from edk2toolext.environment import shell_environment
from edk2toolext.workspace.parsers import *
from edk2toolext.workspace.reports import *
from edk2toolext.invocables.edk2_multipkg_aware_invocable import MultiPkgAwareSettingsInterface, Edk2MultiPkgAwareInvocable

from edk2toollib.uefi.edk2.path_utilities import Edk2Path
from edk2toollib.uefi.edk2.parsers.inf_parser import InfParser
from edk2toollib.uefi.edk2.parsers.dsc_parser import DscParser
from edk2toollib.uefi.edk2.parsers.fdf_parser import FdfParser
from edk2toollib.utility_functions import locate_class_in_module, import_module_by_file_name

class ReportSettingsManager(MultiPkgAwareSettingsInterface):
    pass

class Edk2Report(Edk2MultiPkgAwareInvocable):
    """An invocable used to parse the environment and run reports.
    
    By default, the workspace will be generically parsed and any report generated will use the generic workspace
    information available. To generate Platform / DSC scoped reports, either:
    
    1. Set the DSC via thethe command line when running the invocable:
    
        `stuart_report -c <path/to/settings.py> -dsc <path/to/dsc>`,

    2. Run `stuart_report` using the platform build file:

        `stuart_report -c <path/to/PlatformBuild.py>`
    """
    def __init__(self):
        super().__init__()

    def GetSettingsClass(self):
        return ReportSettingsManager

    def ParseCommandLineOptions(self,):
        """Overrides Edk2Invocable's ParseCommandLineOption()."""
        parser = ArgumentParser("A tool to generate reports on a edk2 workspace.")
        parser.add_argument('--verbose', '--VERBOSE', '-v', dest="verbose", action='store_true', default=False,
                            help='verbose')
        parser.add_argument('-c', '--platform_module', required=True,
                                  dest='platform_module', help='Provide the Platform Module relative to the current working directory.'
                                  f'This should contain a {self.GetSettingsClass().__name__} instance.')
        subparsers = parser.add_subparsers(dest='cmd', required=True)
        
        # Add the parse subcommand
        parse_parser = subparsers.add_parser("parse", help = "Parse the workspace and generate a database.")
        parse_parser.add_argument("-db", "--database", "--Database", "--DATABASE",
                                  dest="database", action="store", help="Set the database rather then parse for one.")
        parse_parser.add_argument('--build-config', dest='build_config', default = "",
                                 type=str, help='Provide shell variables in a file')
        parse_parser.add_argument('-p', '--pkg', '--pkg-dir', dest='packageList', type=str,
                               help='Optional - A package or folder you want to update (workspace relative).'
                               'Can list multiple by doing -p <pkg1>,<pkg2> or -p <pkg3> -p <pkg4>',
                               action="append", default=[])
        parse_parser.add_argument('-a', '--arch', dest="requested_arch", type=str, default=None,
                               help="Optional - CSV of architecutres requested to update. Example: -a X64,AARCH64")
        
        # Add all report subcommands
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
        except:
            e = f'{settings_args.platform_module} does not contain a {self.GetSettingsClass().__name__} instance.'
            logging.error(e)
            raise RuntimeError(e)
        del settings_args.platform_module

        # Save the rest
        self.args = settings_args
        
        # Parse any build variables added via the command line
        env = shell_environment.GetBuildVars()
        for argument in unknown_args:
            if argument.count('=') == 1:
                tokens = argument.strip().split('=')
                env.SetValue(tokens[0].strip().upper(), tokens[1].strip(), "From Command Line")
            elif argument.count("=") == 0:
                env.SetValue(argument.strip().upper(), 
                ''.join(choice(ascii_letters) for _ in range(20)),
                             "Non valued variable set From cmdLine")
            else:
                raise RuntimeError(f'Unknown variable passed in via CLI: {argument}')
        
        unknown_args.clear()  # remove the arguments we've already consumed
        
    def GetLoggingFolderRelativeToRoot(self):
        return "Build"
    
    def GetLoggingFileName(self, loggerType):
        return "REPORT"

    def GetActiveScopes(self):
        return ("global",)

    def Go(self):
        args = self.args
    
        db_path = Path(self.GetWorkspaceRoot()) / "Build" / "DATABASE.db"

        if args.cmd == 'parse':
            return self.parse_workspace(db_path, args)
        
        # Otherwise run the report we care about
        with TinyDB(db_path, access_mode='r', storage=CachingMiddleware(JSONStorage)) as db: 
            self.generate_report(self.args, db)
        return 0
    
    def parse_workspace(self, db_path: Path, args):
        """Runs all defined workspace parsers to generate a database.
        
        !!! note
            If Package information (DSC, FDF) is provided, additional package information will be added to the database.
        """
        # Delete file if it exists and recreate it.
        db_path.unlink(missing_ok = True)
        db_path.touch()

        # If we are provided a database, take a copy of that database and return
        if args.database:
            return self.replace_database(db_path, Path(args.database))
        
        pathobj = Edk2Path(self.GetWorkspaceRoot(), self.GetPackagesPath())
        env = shell_environment.GetBuildVars()
    
        self._verify_package_and_arch(self.args)
        
        # Add environment variables from the build config (If doing UefiBuilder Only)
        # build_config = args.build_config or Path(self.GetWorkspaceRoot(), "BuildConfig.conf")
        # self.add_build_config_env(Path(build_config), env)
        
        with TinyDB(db_path, access_mode='r+', storage=CachingMiddleware(JSONStorage)) as db:
            # Run all workspace parsers
            for parser in self.get_parsers(need_dsc = False):
                logging.log(edk2_logging.SECTION, f"Starting parser: [{parser.__class__.__name__}]")
                start = time.time()
                parser.parse_workspace(db, pathobj, env)
                logging.log(edk2_logging.SECTION, f"Finished in {round(time.time() - start, 2)} seconds.")

            # Run all dsc parsers
            self.requested_package_list = self.requested_package_list or self.PlatformSettings.GetPackagesSupported()
            self.requested_architecture_list = self.requested_architecture_list or self.PlatformSettings.GetArchitecturesSupported()
            for pkg in self.requested_package_list or self.PlatformSettings.GetPackagesSupported():
                shell_environment.CheckpointBuildVars()
                
                # Configure the dsc to parse
                pkg_config = self._get_package_config(pathobj, pkg)
                dsc = pkg_config.get("CompilerPlugin", {"DscPath": ""})["DscPath"]
                if not dsc:
                    continue
                dsc = str(Path(pkg, dsc))
                env.SetValue("ACTIVE_PLATFORM", dsc, "Set Automatically")
                env.SetValue("ARCH", ",".join(self.requested_architecture_list), "Set via command line.")
                env.SetValue("TARGET", "DEBUG", "Set Automatically")

                # Load the Defines
                for key, value in pkg_config.get("Defines", {}).items():
                    env.SetValue(key, value, "Defined in Package CI yaml")

                for parser in self.get_parsers(need_dsc = True):
                    logging.log(edk2_logging.SECTION, f"Starting parser for {dsc}: [{parser.__class__.__name__}]")
                    start = time.time()
                    parser.parse_workspace(db, pathobj, env)
                    logging.log(edk2_logging.SECTION, f"Finished in {round(time.time() - start, 2)} seconds.")
                shell_environment.RevertBuildVars()
        return 0
    
    def generate_report(self, report, db):
        if report:
            for r in self.get_reports():
                if r.report_name() == report:
                    r.generate_report(db, self.env)
                    return

    def _get_package_config(self, pathobj: Edk2Path, pkg) -> str:
        pkg_config_file = pathobj.GetAbsolutePathOnThisSystemFromEdk2RelativePath(
            str(Path(pkg, pkg + ".ci.yaml"))
        )
        if pkg_config_file:
            with open(pkg_config_file, 'r') as f:
                return yaml.safe_load(f)
        else:
            logging.debug(f"No package config file for {pkg}")
            return {}

    def get_parsers(self, need_dsc = False) -> list:
        "Returns a list of un-instantiated DbDocument subclass parsers."
        # TODO: Parse plugins to grab any additional parsing that should be done.
        if need_dsc:
            return [
                DParser(),
            ]
        return [
            #CParser(),
            #IParser()
        ]
    
    def get_reports(self) -> list:
        """Returns a list of report generators."""
        return [
            LicenseReport(),
            LibraryInfReport(),
            CoverageReport(),
        ]

    def replace_database(self, cur_path: Path, replace_path: Path):
        """Replaces the contents of cur_path with replace_path."""
        if not replace_path.is_file():
            e = f'{self.args.database} is not a file.'
            logging.error(e)
            raise ValueError(e)
        else:
            cur_path.write_text(replace_path).read_text()
            return

    def add_build_config_env(self, path: Path, env):
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

    def add_env(self):
        """Parses a DSC / FDF file (if available) to set all env variables."""
        
        # 2: Check if the build module contains a UefiBuilder Object
        # Let the UefiBuilder set the ENV then return the DSC and FDF (if applicable)
        try:
            logging.disable(logging.CRITICAL) # Disable logging when running the UefiBuilder.
            platform_module = locate_class_in_module(self.PlatformModule, UefiBuilder)
            if platform_module:
                build_settings = platform_module()
                build_settings.Clean = False
                build_settings.SkipPreBuild = True
                build_settings.SkipBuild = True
                build_settings.SkipPostBuild = True
                build_settings.FlashImage = False
                build_settings.Go(self.GetWorkspaceRoot(), os.pathsep.join(self.GetPackagesPath()), HelperFunctions(), plugin_manager.PluginManager())
        finally:
            logging.disable(logging.NOTSET)
        return

    def _verify_package_and_arch(self, args):

        packageListSet = set()
        for item in args.packageList:  # Parse out the individual packages
            item_list = item.split(",")
            for individual_item in item_list:
                # in case cmd line caller used Windows folder slashes
                individual_item = individual_item.replace("\\", "/").rstrip("/")
                packageListSet.add(individual_item.strip())
        self.requested_package_list = list(packageListSet)

        if args.requested_arch is not None:
            self.requested_architecture_list = args.requested_arch.upper().split(",")
        else:
            self.requested_architecture_list = []
def main():
    Edk2Report().Invoke()
