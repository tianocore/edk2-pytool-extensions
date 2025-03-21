# @file edk2_pr_eval
# Checks the diff between a branch and head and then identifies
# if the requested packages need to be built.
##
# Copyright (c) Microsoft Corporation
#
# SPDX-License-Identifier: BSD-2-Clause-Patent
##
"""Invocable that checks the diff between a branch and head.

Identifies any packages that needs to be build.

Contains a PrEvalSettingsManager that must be subclassed in a build settings
file. This provides platform specific information to Edk2PrEval invocable
while allowing the invocable itself to remain platform agnostic.
"""

import argparse
import logging
import os
import timeit
from io import StringIO
from pathlib import Path
from typing import Optional

import yaml
from edk2toollib.uefi.edk2 import path_utilities
from edk2toollib.uefi.edk2.parsers.dec_parser import DecParser
from edk2toollib.uefi.edk2.parsers.dsc_parser import DscParser
from edk2toollib.uefi.edk2.parsers.inf_parser import InfParser
from edk2toollib.utility_functions import RunCmd

from edk2toolext import edk2_logging
from edk2toolext.invocables.edk2_multipkg_aware_invocable import (
    Edk2MultiPkgAwareInvocable,
    MultiPkgAwareSettingsInterface,
)


class PrEvalSettingsManager(MultiPkgAwareSettingsInterface):
    """Platform specific Settings for Edk2PrEval.

    provide information necessary for `stuart_pr_eval.exe` or
    `edk2_pr_eval.py` to successfully execute.

    !!! example "Example of Overriding PrEvalSettingsManager"
        ```python
        from edk2toolext.invocables.edk2_pr_eval import PrEvalSettingsManager
        class PrEvalManager(PrEvalSettingsManager):
            def FilterPackagesToTest(self, changedFilesList: list, potentialPackagesList: list) -> list:
                filtered_packages = []
                for file in changedFilesList:
                    for package in potentialPackagesList:
                        if package.startswith(potentialPackagesList):
                            filtered_packages.append(package)

                return list(set(filtered_packages))

            def GetPlatformDscAndConfig(self) -> tuple:
                return None
        ```
    """

    def FilterPackagesToTest(self, changedFilesList: list, potentialPackagesList: list) -> list:
        """Filter potential packages to test based on changed files.

        !!! tip
            Optional Override in a subclass

        Arguments:
            changedFilesList (list): files changed in this PR
            potentialPackagesList (list): packages from `GetPackagesSupported()` or from command line
                option -p, --pkg, --pkg-dir from `Edk2MultiPkgAwareInvocable`

        Returns:
            (list): filtered packages to test

        !!! Note
            Default implementation does zero filtering
        """
        # default implementation does zero filtering.
        return potentialPackagesList

    def GetPlatformDscAndConfig(self) -> tuple:
        """Provide a platform dsc and config.

        If a platform desires to provide its DSC then Policy 4 will evaluate if
        any of the changes will be built in the dsc.

        !!! tip
            Optional Override in a subclass

        Returns:
            (tuple): (workspace relative path to dsc file, input dictionary of dsc key value pairs)
        """
        return None


class Edk2PrEval(Edk2MultiPkgAwareInvocable):
    """Invocable to determine what packages should be tested.

    Evaluate the changes and determine what packages of the supplied packages should
    be tested based on impact from the changes
    """

    def AddCommandLineOptions(self, parserObj: argparse.ArgumentParser) -> None:
        """Adds command line options to the argparser."""
        parserObj.add_argument(
            "--pr-target",
            dest="pr_target",
            type=str,
            default=None,
            help="PR Branch Target.  Allows build optimizations for pull request"
            " validation based on files changed. If a package doesn't need testing then it will"
            " be skipped. Example --pr-target origin/master",
            required=True,
        )
        parserObj.add_argument(
            "--output-csv-format-string",
            dest="output_csv_format_string",
            type=str,
            default=None,
            help="Provide format string that will be output to stdout a full csv of packages"
            " to be tested.  Valid Tokens: {pkgcsv}"
            " Example --output-csv-format-string test={pkgcsv}",
        )
        parserObj.add_argument(
            "--output-count-format-string",
            dest="output_count_format_string",
            type=str,
            default=None,
            help="Provide format string that will be output to stdout the count of"
            " packages to be tested.  Valid Tokens: {pkgcount}"
            " Example --output-count-format-string PackageCount={pkgcount}",
        )
        super().AddCommandLineOptions(parserObj)

    def RetrieveCommandLineOptions(self, args: argparse.Namespace) -> None:
        """Retrieve command line options from the argparser."""
        self.pr_target = args.pr_target
        self.output_csv_format_string = args.output_csv_format_string
        self.output_count_format_string = args.output_count_format_string
        super().RetrieveCommandLineOptions(args)

    def GetVerifyCheckRequired(self) -> bool:
        """Will not call self_describing_environment.VerifyEnvironment because it might not be set up yet."""
        return False

    def GetSettingsClass(self) -> type:
        """Returns the PrEvalSettingsManager class.

        !!! warning
            PrEvalSettingsManager must be subclassed in your platform settings file.
        """
        return PrEvalSettingsManager

    def GetLoggingFileName(self, loggerType: str) -> str:
        """Returns the filename (PREVALLOG) of where the logs for the Edk2CiBuild invocable are stored in."""
        return "PREVALLOG"

    def Go(self) -> int:
        """Executes the core functionality of the Edk2CiBuild invocable."""
        full_start_time = timeit.default_timer()

        # create path obj for resolving paths.  Since PR eval is run early to determine if a build is
        # impacted by the changes of a PR we must ignore any packages path that are not valid due to
        # not having their submodule or folder populated.
        # A packages path is ok to drop for this because if it isn't populated it is assumed outside
        # the repository and thus will not trigger the build.
        self.edk2_path_obj = path_utilities.Edk2Path(
            self.GetWorkspaceRoot(), self.GetPackagesPath(), error_on_invalid_pp=False
        )
        self.logger = logging.getLogger("edk2_pr_eval")
        actualPackagesDict = self.get_packages_to_build(self.requested_package_list)

        #
        # Report the packages that need to be built
        #
        self.logger.log(edk2_logging.SECTION, "Output Results")
        self.logger.critical("Need to Build:")
        if len(actualPackagesDict.keys()) > 0:
            max_pkg_width = max(len(t) for t in actualPackagesDict.keys())
            for key, value in actualPackagesDict.items():
                self.logger.critical(f"{key:{max_pkg_width}}  Reason: {value}")
        else:
            self.logger.critical("None")

        #
        # If requested thru cmd line write to std out in defined format
        # This enabled CI pipelines
        #
        if self.output_csv_format_string is not None:
            pkgcsv = ",".join([x for x in actualPackagesDict.keys()])
            print(self.output_csv_format_string.format(pkgcsv=pkgcsv))

        if self.output_count_format_string is not None:
            pkgcount = len(actualPackagesDict.keys())
            print(self.output_count_format_string.format(pkgcount=pkgcount))

        edk2_logging.perf_measurement("Complete PR Eval", timeit.default_timer() - full_start_time)

        return 0

    def get_packages_to_build(self, possible_packages: list) -> dict:
        """Returns a dictionary of packages to build.

        Args:
            possible_packages: list of possible packages

        Returns:
            (dict): filtered packages to build
        """
        self.parsed_dec_cache = {}
        (rc, files) = self._get_files_that_changed_in_this_pr(self.pr_target)
        if rc != 0:
            return {}

        #
        # Policy 0 - A file outside a package was modified and force build
        #            all packages on a modified file outside a package setting
        #            is enabled.
        #
        for f in files:
            if not self.edk2_path_obj.GetContainingPackage(os.path.abspath(f)):
                return dict.fromkeys(
                    possible_packages, "Policy 0 - Build all packages if a file is modified outside a package."
                )

        remaining_packages = possible_packages.copy()  # start with all possible packages and remove each
        # package once it is determined to be build.  This optimization
        # avoids checking packages that already will be built.

        packages_to_build = {}  # packages to build.  Key = pkg name, Value = 1st reason for build

        #
        # Policy 1 - CI Settings file defined
        #
        after = self.PlatformSettings.FilterPackagesToTest(files, remaining_packages)
        for a in after:
            if a not in remaining_packages:
                raise ValueError(f"PlatformSettings.FilterPackagesToTest returned package not allowed {a}")
            packages_to_build[a] = "Policy 1 - PlatformSettings - Filter Packages"
            remaining_packages.remove(a)

        # No more packages to eval - return the results
        if len(remaining_packages) == 0:
            return packages_to_build

        #
        # Policy 2: Build any package that has changed
        #
        for f in files:
            try:
                pkg = self.edk2_path_obj.GetContainingPackage(os.path.abspath(f))

            except Exception as e:
                self.logger.warning(f"Failed to get package for file {f}.  Exception {e}")
                # Ignore a file in which we fail to get the package
                continue

            if pkg not in packages_to_build.keys() and pkg in remaining_packages:
                packages_to_build[pkg] = "Policy 2 - Build any package that has changed"
                remaining_packages.remove(pkg)

        # No more packages to eval - return the results
        if len(remaining_packages) == 0:
            return packages_to_build

        #
        # Policy 3: If a file change is a public file then build all packages that
        #           are dependent on that package.
        #

        # list of packages with public files that have changed
        public_package_changes = []

        # Get all public files in packages
        for f in files:
            try:
                pkg = self.edk2_path_obj.GetContainingPackage(os.path.abspath(f))

            except Exception as e:
                self.logger.warning(f"Failed to get package for file {f}.  Exception {e}")
                # Ignore a file in which we fail to get the package
                continue

            if self._is_public_file(f):
                public_package_changes.append(pkg)
        # de-duplicate list
        public_package_changes = list(set(public_package_changes))

        # Now check all remaining packages to see if they depend on the set of packages
        # with public file changes.
        # NOTE: future enhancement could be to check actual file dependencies
        for a in public_package_changes:
            for p in remaining_packages[:]:  # slice so we can delete as we go
                if self._does_pkg_depend_on_package(p, a):
                    packages_to_build[p] = f"Policy 3 - Package depends on {a}"
                    remaining_packages.remove(p)  # remove from remaining packages

        # No more packages to eval - return the results
        if len(remaining_packages) == 0:
            return packages_to_build

        #
        # Policy 4: If a file changed in a module and that module is used in the provided dsc file
        # then the package of the dSC file must be built
        #
        PlatformDscInfo = self.PlatformSettings.GetPlatformDscAndConfig()
        if PlatformDscInfo is not None and len(remaining_packages) > 0:
            if len(remaining_packages) != 1:
                raise Exception("Policy 4 can only be used by builds for a single package")

            # files are all the files changed edk2 workspace root relative path
            changed_modules = self._get_unique_module_infs_changed(files)
            changed_modules = [Path(m) for m in changed_modules]

            # now check DSC
            dsc = DscParser().SetEdk2Path(self.edk2_path_obj)
            # given that PR eval runs before dependencies are downloaded we must tolerate errors
            dsc.SetNoFailMode()
            dsc.SetInputVars(PlatformDscInfo[1])
            dsc.ParseFile(PlatformDscInfo[0])
            allinfs = dsc.OtherMods + dsc.ThreeMods + dsc.SixMods + dsc.Libs  # get list of all INF files
            allinfs = [Path(i) for i in allinfs]

            #
            # Note: for now we assume that remaining_packages has only 1 package and that it corresponds
            # to the DSC file provided.
            #
            for p in remaining_packages[:]:  # slice so we can delete as we go
                for cm in changed_modules:
                    if cm in allinfs:  # is the changed module listed in the DSC file?
                        packages_to_build[p] = f"Policy 4 - Package Dsc depends on {str(cm)}"
                        remaining_packages.remove(p)  # remove from remaining packages
                        break

        #
        # Policy 5: If a file changed is a Library INF file, then build all packages that depend on that Library
        # Only supported on packages with a ci.dsc file which contains PrEval.DscPath section.
        #
        for f in filter(lambda f: Path(f).suffix == ".inf", files):
            for p in remaining_packages[:]:
                dsc, defines = self._get_package_ci_information(p)
                if not dsc:
                    logging.debug(
                        f"Policy 5 - Package {p} skipped due to missing ci.dsc file or missing DscPath"
                        "section of the PrEval settings."
                    )
                    continue

                dsc_parser = DscParser()
                dsc_parser.SetNoFailMode()
                dsc_parser.SetEdk2Path(self.edk2_path_obj).SetInputVars(defines)
                dsc_parser.ParseFile(dsc)

                if f in dsc_parser.Libs:
                    packages_to_build[p] = f"Policy 5 - Package depends on Library {f}"
                    remaining_packages.remove(p)

        # All done now return result

        return packages_to_build

    def _get_unique_module_infs_changed(self, files: list) -> list:
        """Returns a list of edk2 relative paths to modules infs that have changed files."""
        modules = []

        for f in files:
            if os.path.splitext(f) in [".txt", ".md"]:  # ignore markdown and txt files
                continue
            try:
                infs = self.edk2_path_obj.GetContainingModules(os.path.abspath(f))
            except Exception as e:
                self.logger.warning(f"Failed to get module for file {f}. Exception: {str(e)}")
                # ignore errors.  These will occur if a module or last file in folder is deleted as part of the PR
                continue

            if len(infs) > 0:  # if this file is part of any INFs
                modules.extend(infs)

        modules = [self.edk2_path_obj.GetEdk2RelativePathFromAbsolutePath(x) for x in set(modules)]
        logging.debug("Changed Modules: " + str(modules))
        return modules

    def _does_pkg_depend_on_package(self, package_to_eval: str, support_package: str) -> bool:
        """Return if any module in package_to_eval depends on public files defined in support_package."""
        # get filesystem path of package_to_eval
        abs_pkg_path = self.edk2_path_obj.GetAbsolutePathOnThisSystemFromEdk2RelativePath(package_to_eval)

        # loop thru all inf files in the package
        inf_files = self._walk_dir_for_filetypes([".inf"], abs_pkg_path)

        # compare if support_pkg in packages section
        # For each INF file
        for f in inf_files:
            ip = InfParser()
            ip.SetEdk2Path(self.edk2_path_obj).ParseFile(f)

            for p in ip.PackagesUsed:
                if p.startswith(support_package):
                    self.logger.info(f"Module: {f} depends on package {support_package}")
                    return True
        # if never found return False
        return False

    def _get_files_that_changed_in_this_pr(self, base_branch: str) -> tuple:
        """Get all the files that changed in this pr.

        Returns:
            (int, list[str]): error code, list of files
        """
        # get file differences between pr and base
        output = StringIO()
        cmd_params = f"diff --name-only HEAD..{base_branch}"
        rc = RunCmd("git", cmd_params, outstream=output)

        if rc == 0:
            self.logger.debug("git diff command returned successfully!")
        else:
            self.logger.critical("git diff returned error return value: %s" % str(rc))
            return (rc, [])

        if output.getvalue() is None:
            self.logger.info("No files listed in diff")
            return (0, [])

        files = output.getvalue().split()
        for f in files:
            self.logger.debug(f"File Changed: {f}")
        return (0, files)

    def _parse_dec_for_package(self, path_to_package: str) -> DecParser:
        """Find DEC for package and parse it."""
        # find DEC file
        path = None
        try:
            allEntries = os.listdir(path_to_package)
            for entry in allEntries:
                if entry.lower().endswith(".dec"):
                    path = os.path.join(path_to_package, entry)
        except Exception:
            self.logger.warning("Exception: Unable to find DEC for package:{0}".format(path_to_package))
            return None

        if path is None:
            self.logger.warning("Unable to find DEC for package:{0}".format(path_to_package))
            return None

        wsr_dec_path = self.edk2_path_obj.GetEdk2RelativePathFromAbsolutePath(path)

        if path is None or wsr_dec_path == "" or not os.path.isfile(path):
            self.logger.warning("Unable to convert path for DEC for package: {0}".format(path_to_package))
            return None

        # parse it
        dec = DecParser()
        dec.SetEdk2Path(self.edk2_path_obj)
        dec.ParseFile(wsr_dec_path)
        return dec

    def _is_public_file(self, filepath: str) -> bool:
        """Returns if file is a public files."""
        fp = filepath.replace("\\", "/")  # make consistant for easy compare

        self.logger.debug("Is public: " + fp)

        if filepath.lower().endswith(".dec"):  # if DEC file then it is public
            return True

        try:
            pkg = self.edk2_path_obj.GetContainingPackage(os.path.abspath(filepath))
        except Exception as e:
            self.logger.warning(f"Failed to get package for {filepath}.  Exception: {str(e)}")
            return False

        dec = None
        if pkg in self.parsed_dec_cache:
            dec = self.parsed_dec_cache[pkg]
        else:
            abs_pkg_path = self.edk2_path_obj.GetAbsolutePathOnThisSystemFromEdk2RelativePath(pkg)
            dec = self._parse_dec_for_package(abs_pkg_path)
            self.parsed_dec_cache[pkg] = dec

        if dec is None:
            return False

        for includepath in dec.IncludePaths:  # if in the include path of a package then it is public
            if (pkg + "/" + includepath + "/") in filepath:
                return True

        return False

    def _walk_dir_for_filetypes(self, extensionlist: list, directory: str, ignorelist: Optional[list] = None) -> list:
        """Walks a directory for all items ending in certain extension."""
        if not isinstance(extensionlist, list):
            raise ValueError("Expected list but got " + str(type(extensionlist)))

        if directory is None:
            raise ValueError("No directory given")

        if not os.path.isabs(directory):
            raise ValueError("Directory not abs path")

        if not os.path.isdir(directory):
            raise ValueError("Invalid find directory to walk")

        if ignorelist is not None:
            ignorelist_lower = list()
            for item in ignorelist:
                ignorelist_lower.append(item.lower())

        extensionlist_lower = list()
        for item in extensionlist:
            extensionlist_lower.append(item.lower())

        returnlist = list()
        for Root, Dirs, Files in os.walk(directory):
            for File in Files:
                for Extension in extensionlist_lower:
                    if File.lower().endswith(Extension):
                        ignoreIt = False
                        if ignorelist is not None:
                            for c in ignorelist_lower:
                                if File.lower().startswith(c):
                                    ignoreIt = True
                                    break
                        if not ignoreIt:
                            logging.debug(os.path.join(Root, File))
                            returnlist.append(os.path.join(Root, File))

        return returnlist

    def _get_package_ci_information(self, pkg_name: str) -> str:
        pkg_path = Path(self.edk2_path_obj.GetAbsolutePathOnThisSystemFromEdk2RelativePath(pkg_name))
        ci_file = pkg_path.joinpath(f"{pkg_name}.ci.yaml")
        dsc = None
        defines = None

        if not ci_file.exists():
            return (None, None)

        with open(ci_file, "r") as f:
            data = yaml.safe_load(f)
            dsc = data.get("PrEval", {"DscPath": None})["DscPath"]
            dsc = str(pkg_path / dsc) if dsc else None
            defines = data.get("Defines", {})
            return (dsc, defines)


def main() -> None:
    """Entry point to invoke Edk2PrEval."""
    Edk2PrEval().Invoke()
