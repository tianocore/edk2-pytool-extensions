# @file nuget_dependency.py
# This module implements ExternalDependency for NuGet packages.
#
##
# Copyright (c) Microsoft Corporation
#
# SPDX-License-Identifier: BSD-2-Clause-Patent
##
import os
import logging
import semantic_version
import shutil
from io import StringIO
from edk2toolext.environment.external_dependency import ExternalDependency
from edk2toollib.utility_functions import RunCmd, RemoveTree
from edk2toollib.utility_functions import GetHostInfo
import pkg_resources
from typing import List


class NugetDependency(ExternalDependency):
    TypeString = "nuget"

    ''' Env variable name for path to folder containing NuGet.exe'''
    NUGET_ENV_VAR_NAME = "NUGET_PATH"

    def __init__(self, descriptor):
        super().__init__(descriptor)
        self.nuget_cache_path = None

    ####
    # Add mono to front of command and resolve full path of exe for mono,
    # Used to add nuget support on posix platforms.
    # https://docs.microsoft.com/en-us/nuget/install-nuget-client-tools
    #
    # Note that the strings returned might not be pathlike given they may be
    # quoted for use on command line
    #
    # @return list containing either ["nuget.exe"] or ["mono", "/PATH/TO/nuget.exe"]
    # @return none if not found
    ####
    @classmethod
    def GetNugetCmd(cls) -> List[str]:
        file_name = "NuGet.exe"
        cmd = []
        if GetHostInfo().os == "Linux":
            cmd += ["mono"]

        nuget_path = os.getenv(cls.NUGET_ENV_VAR_NAME)
        if nuget_path is None:
            # No env variable found.  Get it from our package
            requirement = pkg_resources.Requirement.parse("edk2-pytool-extensions")
            nuget_file_path = os.path.join("edk2toolext", "bin")
            nuget_path = pkg_resources.resource_filename(requirement, nuget_file_path)

        nuget_path = os.path.join(nuget_path, file_name)

        if not os.path.isfile(nuget_path):
            logging.error("We weren't able to find Nuget! Please reinstall your pip environment")
            return None

        # Make sure quoted string if it has spaces
        if " " in nuget_path.strip():
            nuget_path = '"' + nuget_path + '"'

        cmd += [nuget_path]

        return cmd

    def _normalize_version(self):
        # A ValueError will be raised if the version string is invalid
        try:
            return str(semantic_version.Version(self.version))
        except ValueError:
            print(f"NuGet dependency {self.name} has an invalid version "
                  f"string: {self.version}")
            raise

    def _fetch_from_nuget_cache(self, package_name):
        result = False

        #
        # We still need to use Nuget to figure out where the
        # "global-packages" cache is on this machine.
        #
        if self.nuget_cache_path is None:
            cmd = NugetDependency.GetNugetCmd()
            cmd += ["locals", "global-packages", "-list"]
            return_buffer = StringIO()
            if (RunCmd(cmd[0], " ".join(cmd[1:]), outstream=return_buffer) == 0):
                # Seek to the beginning of the output buffer and capture the output.
                return_buffer.seek(0)
                return_string = return_buffer.read()
                self.nuget_cache_path = return_string.strip().strip("global-packages: ")

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
        nuget_version = self._normalize_version()

        cache_search_path = os.path.join(
            self.nuget_cache_path, package_name.lower(), nuget_version)
        inner_cache_search_path = os.path.join(cache_search_path, package_name)
        if os.path.isdir(cache_search_path):
            # If we found a cache for this version, let's use it.
            if os.path.isdir(inner_cache_search_path):
                logging.info(
                    "Local Cache found for Nuget package '%s'. Skipping fetch.", package_name)
                shutil.copytree(inner_cache_search_path, self.contents_dir)
                result = True
            # If this cache doesn't match our heuristic, let's warn the user.
            else:
                logging.warning(
                    "Local Cache found for Nuget package '%s', but could not find contents. Malformed?", package_name)

        return result

    def __str__(self):
        """ return a string representation of this """
        return f"NugetDependecy: {self.name}@{self.version}"

    def _attempt_nuget_install(self, install_dir, non_interactive=True):
        #
        # fetch the contents of the package.
        #
        package_name = self.name
        cmd = NugetDependency.GetNugetCmd()
        cmd += ["install", self.name]
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
        for out_line in output_stream:
            line = out_line.strip()
            if line.startswith("CredentialProvider") or line.startswith("[CredentialProvider"):
                found_cred_provider = True
            if line.endswith("as a credential provider plugin."):
                found_cred_provider = True
        # if we fail, then we should retry if we have credential providers
        # we currently steal command input so if we don't have cred providers, we hang
        # this gives cred providers a chance to prompt for input since they don't use stdin
        if ret != 0:
            # If we're in non interactive and we have a credential provider
            if non_interactive and found_cred_provider:  # we should be interactive next time
                self._attempt_nuget_install(install_dir, False)
            else:
                raise RuntimeError(f"[Nuget] We failed to install this version {self.version} of {package_name}")

    def fetch(self):
        package_name = self.name

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

    def get_temp_dir(self):
        return self.contents_dir + "_temp"

    def clean(self):
        super(NugetDependency, self).clean()
        if os.path.isdir(self.get_temp_dir()):
            RemoveTree(self.get_temp_dir())
