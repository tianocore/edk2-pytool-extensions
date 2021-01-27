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
import shutil
from io import StringIO
from edk2toolext.environment.external_dependency import ExternalDependency
from edk2toollib.utility_functions import RunCmd
from edk2toollib.utility_functions import GetHostInfo
import pkg_resources


class NugetDependency(ExternalDependency):
    TypeString = "nuget"

    def __init__(self, descriptor):
        super().__init__(descriptor)
        self.global_cache_path = None

    ####
    # Add mono to front of command and resolve full path of exe for mono,
    # Used to add nuget support on posix platforms.
    # https://docs.microsoft.com/en-us/nuget/install-nuget-client-tools
    #
    # @return list containing either ["nuget.exe"] or ["mono", "/PATH/TO/nuget.exe"]
    ####
    @staticmethod
    def GetNugetCmd():
        file = "NuGet.exe"
        cmd = []
        if GetHostInfo().os == "Linux":
            cmd += ["mono"]
        # TODO Find the Nuget rom our bin file
        requirement = pkg_resources.Requirement.parse("edk2-pytool-extensions")
        nuget_file_path = os.path.join("edk2toolext", "bin", file)
        nuget_path = pkg_resources.resource_filename(requirement, nuget_file_path)

        # check if we don't have it, look for nuget in the path
        if not os.path.isfile(nuget_path):
            for env_var in os.getenv("PATH").split(os.pathsep):
                env_var = os.path.join(os.path.normpath(env_var), file)
                if os.path.isfile(env_var):
                    nuget_path = '"' + env_var + '"'
                    break
        # we've probably found something by now?
        cmd += [nuget_path]
        # if we're still hosed
        if not os.path.isfile(nuget_path):
            logging.error("We weren't able to find Nuget! Please reinstall your pip environment")
            return None
        return cmd

    @staticmethod
    def normalize_version(version):
        if len(version) == 0:
            raise ValueError("Unparsable version: empty string")

        if str(version).count("-") > 1:
            raise ValueError(f"Unparsable version: '{version}'!")

        tag = None

        parts = version.split(".")
        if "-" in parts[-1]:
            parts[-1], tag = parts[-1].split("-")

        int_parts = tuple([0 if a == "" else int(a) for a in parts])

        if tag not in [None, "beta", "alpha", "rc"]:
            raise ValueError(f"Unparsable version tag: {tag}")

        if len(int_parts) > 4:
            raise ValueError(f"Unparsable version: '{version}'!")

        # Remove extra trailing zeros (beyond 3 elements).
        if len(int_parts) == 4 and int_parts[3] == 0:
            int_parts = int_parts[0:3]  # drop the last item

        # Add missing trailing zeros (below 3 elements).
        if len(int_parts) < 3:
            int_parts = int_parts + (0,) * (3 - len(int_parts))

        # Return reformed version.
        reformed_ints = ".".join((str(num) for num in int_parts))
        if tag is not None:
            reformed_ints += "-" + tag
        return reformed_ints

    def _fetch_from_cache(self, package_name):
        result = False

        #
        # We still need to use Nuget to figure out where the
        # "global-packages" cache is on this machine.
        #
        if self.global_cache_path is None:
            cmd = NugetDependency.GetNugetCmd()
            cmd += ["locals", "global-packages", "-list"]
            return_buffer = StringIO()
            if (RunCmd(cmd[0], " ".join(cmd[1:]), outstream=return_buffer) == 0):
                # Seek to the beginning of the output buffer and capture the output.
                return_buffer.seek(0)
                return_string = return_buffer.read()
                self.global_cache_path = return_string.strip().strip("global-packages: ")

        if self.global_cache_path is None:
            logging.info("Nuget was unable to provide global packages cache location.")
            return False
        #
        # If the path couldn't be found, we can't do anything else.
        #
        if not os.path.isdir(self.global_cache_path):
            logging.info("Could not determine Nuget global packages cache location.")
            return False

        #
        # Now, try to locate our actual cache path
        nuget_version = NugetDependency.normalize_version(self.version)

        cache_search_path = os.path.join(
            self.global_cache_path, package_name.lower(), nuget_version)
        inner_cache_search_path = os.path.join(cache_search_path, package_name)
        if os.path.isdir(cache_search_path):
            # If we found a cache for this version, let's use it.
            if os.path.isdir(inner_cache_search_path):
                logging.info(
                    "Local Cache found for Nuget package '%s'. Skipping fetch.", package_name)
                shutil.copytree(inner_cache_search_path, self.contents_dir)
                self.update_state_file()
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
        #
        # Before trying anything with Nuget feeds,
        # check to see whether the package is already in
        # our local cache. If it is, we avoid a lot of
        # time and network cost by copying it directly.
        #
        if self._fetch_from_cache(package_name):
            # We successfully found the package in the cache.
            # The published path may change now that the package has been unpacked.
            # Bail.
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
        shutil.move(source_dir, self.contents_dir)

        #
        # Add a file to track the state of the dependency.
        #
        self.update_state_file()

        #
        # Finally, delete the temp directory.
        #
        self._clean_directory(temp_directory)

        # The published path may change now that the package has been unpacked.
        self.published_path = self.compute_published_path()

    def get_temp_dir(self):
        return self.contents_dir + "_temp"

    def clean(self):
        super(NugetDependency, self).clean()
        if os.path.isdir(self.get_temp_dir()):
            self._clean_directory(self.get_temp_dir())
