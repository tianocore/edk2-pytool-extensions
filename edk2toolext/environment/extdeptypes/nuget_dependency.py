# @file nuget_dependency.py
# This module implements ExternalDependency for NuGet packages.
#
##
# Copyright (c) Microsoft Corporation
#
# SPDX-License-Identifier: BSD-2-Clause-Patent
##
"""An ExternalDependency subclass able to download from NuGet."""

import logging
import os
import shutil
from io import StringIO
from typing import Optional

import semantic_version
from edk2toollib.utility_functions import GetHostInfo, RemoveTree, RunCmd

from edk2toolext.bin.nuget import DownloadNuget
from edk2toolext.environment.external_dependency import ExternalDependency


class NugetDependency(ExternalDependency):
    """An ExternalDependency subclass able to download from NuGet.

    Attributes:
        source (str): Source of the nuget dependency.
        version (str): Version of the web dependency.

    !!! tip
        The attributes are what must be described in the ext_dep yaml file!
    """

    TypeString = "nuget"

    # Env variable name for path to folder containing NuGet.exe
    NUGET_ENV_VAR_NAME = "NUGET_PATH"

    def __init__(self, descriptor: dict) -> None:
        """Inits a nuget dependency based off the provided descriptor."""
        super().__init__(descriptor)
        self.package = descriptor.get("package", self.name)
        self.nuget_cache_path = None

    @classmethod
    def GetNugetCmd(cls: "NugetDependency") -> list[str]:
        """Appends mono to the command and resolves the full path of the exe for mono.

        Used to add nuget support on posix platforms.
        https://docs.microsoft.com/en-us/nuget/install-nuget-client-tools

        !!! note
            Strings returned might not be pathlike given they may be quoted
            for use on the command line.

        Returns:
            (list): ["nuget.exe"] or ["mono", "/PATH/TO/nuget.exe"]
            (None): none was found
        """
        cmd = []
        if GetHostInfo().os != "Windows":
            cmd += ["mono"]

        nuget_path = os.getenv(cls.NUGET_ENV_VAR_NAME)
        if nuget_path is not None:
            nuget_path = os.path.join(nuget_path, "NuGet.exe")
            if not os.path.isfile(nuget_path):
                logging.info(f"{cls.NUGET_ENV_VAR_NAME} set, but did not exist. Attempting to download.")
                DownloadNuget(nuget_path)
        else:
            nuget_path = DownloadNuget()

        if not os.path.isfile(nuget_path):
            logging.error("We weren't able to find or download NuGet!")
            return None

        # Make sure quoted string if it has spaces
        if " " in nuget_path.strip():
            nuget_path = '"' + nuget_path + '"'

        cmd += [nuget_path]

        return cmd

    @staticmethod
    def normalize_version(version: str, nuget_name: Optional[str] = "") -> str:
        """Normalizes the version as NuGet versioning diverges from Semantic Versioning.

        https://learn.microsoft.com/en-us/nuget/concepts/package-versioning#where-nugetversion-diverges-from-semantic-versioning

        These cases will be handled befpre a Semantic Version Compatible" set
        of data is passed to the Semantic Version checker.
        """
        # 1. NuGetVersion requires the major segment to be defined
        if not version:
            raise ValueError("String is empty. At least major version is required.")

        # 2. NuGetVersion uses case insensitive string comparisons for
        #    pre-release components
        reformed_ver = version.strip().lower()

        tag = None
        parts = version.split(".")

        if "-" in parts[-1]:
            parts[-1], tag = parts[-1].split("-")

        # 3. Drop leading zeroes from individual version parts
        int_parts = tuple([0 if a == "" else int(a) for a in parts])

        # 4. A maximum of 4 version segments are allowed
        if len(int_parts) > 4:
            raise ValueError(f"Maximum of 4 version segments allowed: '{version}'!")

        # 5. Allow a fourth version segment - "Revision" normally not
        #    allowed in Semantic versions but allowed in NuGet versions.
        #
        #    Version in this case is: <Major>.<Minor>.<Patch>.<Revision>

        # 6. Remove trailing zeros (beyond 3 patch segment)
        #    i.e. If Revision is zero, omit from the normalized string
        if len(int_parts) == 4 and int_parts[3] == 0:
            int_parts = int_parts[0:3]

        # 7. Add missing trailing zeros (below 3 elements).
        #    i.e. 1, 1.0, 1.0.0, and 1.0.0.0 are all accepted and
        #    equal.
        if len(int_parts) < 3:
            int_parts = int_parts + (0,) * (3 - len(int_parts))

        # 8. Reassemble the string for final semantic version validation
        reformed_ver = ".".join((str(num) for num in int_parts))
        if tag is not None:
            reformed_ver += "-" + tag

        # 9. Use semantic_version to further validate the version string
        if len(int_parts) == 4:
            nuget_ver = semantic_version.Version.coerce(reformed_ver)

            # A ValueError will be raised if the version string is invalid
            major, minor, patch, prerelease, build = semantic_version.Version.parse(str(nuget_ver))
        else:
            # A ValueError will be raised if the version string is invalid
            nuget_ver = semantic_version.Version(reformed_ver)
            major, minor, patch, prerelease, build = tuple(nuget_ver)

        logging.info(
            f"NuGet version parts:\n"
            f"  Major Version: {major}\n"
            f"  Minor Version: {minor}\n"
            f"  Patch Version: {patch}\n"
            f"  Pre-Release Version {prerelease}\n"
            f"  Revision (Build) Version: {build}"
        )

        return reformed_ver

    def _fetch_from_nuget_cache(self, package_name: str) -> bool:
        result = False

        #
        # We still need to use Nuget to figure out where the
        # "global-packages" cache is on this machine.
        #
        if self.nuget_cache_path is None:
            cmd = NugetDependency.GetNugetCmd()
            cmd += ["locals", "global-packages", "-list"]
            return_buffer = StringIO()
            if RunCmd(cmd[0], " ".join(cmd[1:]), outstream=return_buffer) == 0:
                # Seek to the beginning of the output buffer and capture the output.
                return_buffer.seek(0)
                return_string = return_buffer.read()
                self.nuget_cache_path = return_string.strip().replace("global-packages: ", "")

        if self.nuget_cache_path is None:
            logging.info("Nuget was unable to provide global packages cache location.")
            return False
        #
        # If the path couldn't be found, we can't do anything else.
        #
        if not os.path.isdir(self.nuget_cache_path):
            logging.info("Could not determine Nuget global packages cache location.")
            return False

        #
        # Now, try to locate our actual cache path
        nuget_version = self.version
        try:
            nuget_version = NugetDependency.normalize_version(self.version)
        except ValueError:
            logging.error(f"NuGet dependency {self.package} has an invalid version string: {self.version}")

        cache_search_path = os.path.join(self.nuget_cache_path, package_name.lower(), nuget_version)
        inner_cache_search_path = os.path.join(cache_search_path, package_name)
        if os.path.isdir(cache_search_path):
            # If we found a cache for this version, let's use it.
            if os.path.isdir(inner_cache_search_path):
                logging.info(self.nuget_cache_path)
                logging.info("Local Cache found for Nuget package '%s'. Skipping fetch.", package_name)
                shutil.copytree(inner_cache_search_path, self.contents_dir)
                result = True
            # If this cache doesn't match our heuristic, let's warn the user.
            else:
                logging.warning(
                    "Local Cache found for Nuget package '%s', but could not find contents. Malformed?", package_name
                )

        return result

    def __str__(self) -> str:
        """Return a string representation."""
        return f"NugetDependecy: {self.package}@{self.version}"

    def _attempt_nuget_install(self, install_dir: str, non_interactive: Optional[bool] = True) -> None:
        #
        # fetch the contents of the package.
        #
        package_name = self.package
        cmd = NugetDependency.GetNugetCmd()
        cmd += ["install", package_name]
        cmd += ["-Source", self.source]
        cmd += ["-ExcludeVersion"]
        if non_interactive:
            cmd += ["-NonInteractive"]
        cmd += ["-Version", self.version]
        cmd += ["-Verbosity", "detailed"]
        cmd += ["-OutputDirectory", '"' + install_dir + '"']
        # make sure to capture our output
        output_stream = StringIO()
        ret = RunCmd(cmd[0], " ".join(cmd[1:]), outstream=output_stream)
        output_stream.seek(0)  # return the start of the stream
        # check if we found credential providers
        found_cred_provider = False
        is_unauthorized = False
        for out_line in output_stream:
            line = out_line.strip()
            if line.startswith(("CredentialProvider", "[CredentialProvider")):
                found_cred_provider = True
            if line.endswith("as a credential provider plugin."):
                found_cred_provider = True
            if "401 (Unauthorized)" in line:
                is_unauthorized = True
        # if we fail, then we should retry if we have credential providers
        # we currently steal command input so if we don't have cred providers, we hang
        # this gives cred providers a chance to prompt for input since they don't use stdin
        if ret != 0:
            # If we're in non interactive and we have a credential provider
            if non_interactive and found_cred_provider:  # we should be interactive next time
                self._attempt_nuget_install(install_dir, False)
            else:
                # Only provide this error message if they are not using a credential provider, but receive a 401 error
                if is_unauthorized and not found_cred_provider:
                    logging.warning(
                        "[Nuget] A package requires credentials, but you do not have a credential provider installed."
                    )
                    logging.warning(
                        "[Nuget] Please install a credential provider and try again or run the following "
                        "command in your terminal to install the package manually:"
                    )
                    logging.warning(f"[{' '.join(cmd).replace(' -NonInteractive', '')}]")
                raise RuntimeError(f"[Nuget] We failed to install this version {self.version} of {package_name}")

    def fetch(self) -> None:
        """Fetches the dependency using internal state from the init."""
        package_name = self.package

        # First, check the global cache to see if it's present.
        if super().fetch():
            return

        #
        # Before trying anything with Nuget feeds,
        # check to see whether the package is already in
        # our local cache. If it is, we avoid a lot of
        # time and network cost by copying it directly.
        #
        if self._fetch_from_nuget_cache(package_name):
            self.copy_to_global_cache(self.contents_dir)
            # We successfully found the package in the cache.
            # The published path may change now that the package has been unpacked.
            # Bail.
            self.update_state_file()
            self.published_path = self.compute_published_path()
            return

        #
        # If we are still here, the package wasn't in the cache.
        # We need to ask Nuget to find it.
        #
        temp_directory = self.get_temp_dir()
        self._attempt_nuget_install(temp_directory)

        #
        # Next, copy the contents of the package to the
        # final resting place.
        #
        # Depending on packaging, the package content will be in one of two
        # possible locations:
        # 1. temp_directory\package_name\package_name\
        # 2. temp_directory\package_name\
        #
        source_dir = os.path.join(temp_directory, package_name, package_name)
        if not os.path.isdir(source_dir):
            source_dir = os.path.join(temp_directory, package_name)
        shutil.copytree(source_dir, self.contents_dir)
        self.copy_to_global_cache(self.contents_dir)

        RemoveTree(source_dir)

        #
        # Add a file to track the state of the dependency.
        #
        self.update_state_file()

        #
        # Finally, delete the temp directory.
        #
        RemoveTree(temp_directory)

        # The published path may change now that the package has been unpacked.
        self.published_path = self.compute_published_path()

    def get_temp_dir(self) -> str:
        """Returns the temporary directory the NuGet package is downloaded to."""
        return self.contents_dir + "_temp"

    def clean(self) -> None:
        """Removes the temporary directory the NuGet package is downloaded to."""
        super(NugetDependency, self).clean()
        if os.path.isdir(self.get_temp_dir()):
            RemoveTree(self.get_temp_dir())
