# @file edk2_parse.py
# An invocable to run workspace parsers on a workspace and generate a database.
##
# Copyright (c) Microsoft Corporation
#
# SPDX-License-Identifier: BSD-2-Clause-Patent
##
"""An invocable to run workspace parsers on a workspace and generate a database."""
import logging
import os
from pathlib import Path

import yaml
from edk2toollib.database import Edk2DB
from edk2toollib.database.tables import (
    InfTable,
    InstancedFvTable,
    InstancedInfTable,
    PackageTable,
    SourceTable,
)
from edk2toollib.uefi.edk2.path_utilities import Edk2Path
from edk2toollib.utility_functions import locate_class_in_module

from edk2toolext.environment import shell_environment
from edk2toolext.environment.uefi_build import UefiBuilder
from edk2toolext.environment.var_dict import VarDict
from edk2toolext.invocables.edk2_multipkg_aware_invocable import (
    Edk2MultiPkgAwareInvocable,
    MultiPkgAwareSettingsInterface,
)

DB_NAME = "DATABASE.db"


TABLES = [
    PackageTable(),
    SourceTable(),
    InfTable(),
    InstancedInfTable(),
    InstancedFvTable(),
]


class ParseSettingsManager(MultiPkgAwareSettingsInterface):
    """Settings to support ReportSettingsManager functionality."""
    def GetPackagesSupported(self):
        """Returns an iterable of edk2 packages supported by this build."""
        # Re-define and return an empty list instead of raising an exception as this is only needed when parsing
        # based off of a CI Settings File.
        return []
    def GetArchitecturesSupported(self):
        """Returns an iterable of edk2 architectures supported by this build."""
        # Re-define and return an empty list instead of raising an exception as this is only needed when parsing
        # based off of a CI Settings File.
        return []
    def GetTargetsSupported(self):
        """Returns an iterable of edk2 target tags supported by this build."""
        # Re-define and return an empty list instead of raising an exception as this is only needed when parsing
        # based off of a CI Settings File.
        return []


class Edk2Parse(Edk2MultiPkgAwareInvocable):
    """An invocable used to parse the environment and generate a database.

    This invocable has the ability to parse both a repo containing generic Edk2 packages, and a repo containing
    platform packages. When parsing generic packages, The Edk2Report invocable uses methods from the
    MultiPkgAwareSettingsInterface, most commonly found ina CI Settings File. In this scenario, it will either parse
    all packages defined by `GetPackagesSupported()` or a subset of those packages as defined by the -p flag. The same
    can be said about the architectures by using `GetDefinedArchitectures()` and the -a command.

    When the goal is to parse a platform package, the Edk2Report invocable uses methods from the `UefiBuilder`, which
    is most commonly found in the Platform Build File. In this scenario, it will invoke the methods found in the
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
        return ParseSettingsManager

    def AddCommandLineOptions(self, parserObj):
        """Adds the command line options."""
        super().AddCommandLineOptions(parserObj) # Adds the CI Settings File options
        parserObj.add_argument('--clear', '--Clear', "--CLEAR", dest='clear', action='store_true',
                               help="Deletes the database before parsing the environment.")

    def RetrieveCommandLineOptions(self, args):
        """Retrives the command line options."""
        super().RetrieveCommandLineOptions(args) # Stores the CI Settings File options
        self.clear = args.clear
        self.is_uefi_builder = locate_class_in_module(self.PlatformModule, UefiBuilder) is not None

    def GetLoggingFileName(self, loggerType):
        """Returns the logging file name for this invocation."""
        return "PARSE_LOG"

    def Go(self):
        """Executes the invocable. Runs the subcommand specified by the user."""
        db_path = Path(self.GetWorkspaceRoot()) / self.GetLoggingFolderRelativeToRoot() / DB_NAME
        pathobj = Edk2Path(self.GetWorkspaceRoot(), self.GetPackagesPath())
        env = shell_environment.GetBuildVars()

        logging.info(f"Generating database at {db_path}")

        if self.clear:
            db_path.unlink(missing_ok=True)

        with Edk2DB(db_path, pathobj=pathobj) as db:
            db.register(*TABLES)

            # Generate environment aware tables
            if self.is_uefi_builder:
                self.parse_with_builder_settings(db, pathobj, env)
            else:
                self.parse_with_ci_settings(db, pathobj, env)

        return 0

    def parse_with_builder_settings(self, db: Edk2DB, pathobj: Edk2Path, env: VarDict):
        """Parses the workspace using a uefi builder to setup the environment."""
        logging.info("Setting up the environment with the UefiBuilder.")
        exception_msg = ""
        try:
            if not self.Verbose:
                logging.disable(logging.CRITICAL)  # Disable logging when running the UefiBuilder.
            platform_module = locate_class_in_module(self.PlatformModule, UefiBuilder)
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

        # Log the environment for debug purposes
        for key, value in (env.GetAllBuildKeyValues() | env.GetAllNonBuildKeyValues()).items():
            logging.debug(f"  {key} = {value}")

        env_dict = env.GetAllBuildKeyValues() | env.GetAllNonBuildKeyValues()
        logging.info("Running parsers with the following settings:")
        logging.info(f"  TARGET: {env_dict['TARGET']}")
        logging.info(f"  ACTIVE_PLATFORM: {env_dict['ACTIVE_PLATFORM']}")
        logging.info(f"  TARGET_ARCH: {env_dict['TARGET_ARCH']}")
        db.parse(env_dict)
        return 0

    def parse_with_ci_settings(self, db: Edk2DB, pathobj: Edk2Path, env: VarDict):
        """Parses the workspace using ci settings to setup the environment."""
        # Build a list of Parsers to run with the expected settings.
        # The same parser will exist for each package, with that package's settings.
        for package in self.requested_package_list:
            for target in set(self.requested_target_list) & set(["DEBUG", "RELEASE"]):
                logging.info(f"Setting up the environment for {package}.")
                shell_environment.CheckpointBuildVars()

                pkg_config = self._get_package_config(pathobj, package)
                dsc = pkg_config.get("CompilerPlugin", {"DscPath": ""})["DscPath"]
                if not dsc:
                    logging.info("Package skipped! No DSC found in ci.yaml file.")
                    continue
                dsc = str(Path(package, dsc))

                env.SetValue("TARGET", target, "Set via commandline arguments")
                env.SetValue("ACTIVE_PLATFORM", dsc, "Set Automatically.")
                env.SetValue("TARGET_ARCH", " ".join(self.requested_architecture_list), "Set Automatically")
                env.SetValue("PACKAGES_PATH", ";".join(self.GetPackagesPath()), "Set Automatically")

                # Load the Defines
                for key, value in pkg_config.get("Defines", {}).items():
                    env.SetValue(key, value, "Defined in Package CI yaml")

                # Log the environment for debug purposes
                for key, value in (env.GetAllBuildKeyValues() | env.GetAllNonBuildKeyValues()).items():
                    logging.debug(f"  {key} = {value}")

                env_dict = env.GetAllBuildKeyValues() | env.GetAllNonBuildKeyValues()
                logging.info("Running parsers with the following settings:")
                logging.info(f"  TARGET: {target}")
                logging.info(f"  ACTIVE_PLATFORM: {dsc}")
                logging.info(f"  TARGET_ARCH: {' '.join(self.requested_architecture_list)}")
                db.parse(env_dict)
                shell_environment.RevertBuildVars()
        return 0

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


def main():
    """Entry point to invoke Edk2PlatformSetup."""
    Edk2Parse().Invoke()
