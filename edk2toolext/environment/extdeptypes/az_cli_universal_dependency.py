# @file az_cli_universal_dependency.py
# This module implements ExternalDependency for azure cli universal packages.
# More details here:
# https://docs.microsoft.com/en-us/azure/devops/artifacts/quickstarts/universal-packages?view=azure-devops
#
##
# Copyright (c) Microsoft Corporation
#
# SPDX-License-Identifier: BSD-2-Clause-Patent
##
"""An ExternalDependency subclass able to download from an Azure feed."""

import json
import logging
import os
import shutil
from io import StringIO
from pathlib import Path

from edk2toollib.utility_functions import RemoveTree, RunCmd

from edk2toolext.environment import shell_environment, version_aggregator
from edk2toolext.environment.extdeptypes.web_dependency import WebDependency
from edk2toolext.environment.external_dependency import ExternalDependency


class AzureCliUniversalDependency(ExternalDependency):
    """An ExternalDependency subclass able to download from an Azure feed.

    Attributes:
        feed (str): feed name
        version (str): semantic version <Major.Minor.Patch>
        source (str): url of organization (example: https://dev.azure.com/tianocore)
        project (str): <name of project for project scoped feed.  If missing assume organization scoped>
        name (str): name of artifact
        file-filter (str): <optional> filter for folders and files.
        compression_type (str): <optional> Compression type used, if compressed.
        internal_path (str): <optional> Path inside the compressed file, if the ext_dep is compressed
        pat_var (str): shell_var name for PAT for this ext_dep

    !!! tip
        The attributes are what must be described in the ext_dep yaml file!
    """

    TypeString = "az-universal"

    # https://docs.microsoft.com/en-us/azure/devops/cli/log-in-via-pat?view=azure-devops&tabs=windows
    AZURE_CLI_DEVOPS_ENV_VAR = "AZURE_DEVOPS_EXT_PAT"

    VersionLogged = False

    @classmethod
    def VerifyToolDependencies(cls: "AzureCliUniversalDependency") -> None:
        """Verify any tool environment or dependencies requirements are met.

        Log to Version Aggregator the Tool Versions
        """
        if cls.VersionLogged:
            return
        results = StringIO()
        RunCmd("az", "--version", outstream=results, raise_exception_on_nonzero=True)
        results.seek(0)

        to_find = ["azure-cli", "azure-devops"]  # find these keys in the version output
        found = dict()

        for line in results.readlines():
            if len(to_find) == 0:
                break

            for f in to_find:
                if f in line:
                    found[f] = line.split()[1]
                    to_find.remove(f)
                    break

        # Log the versions found
        for k, v in found.items():
            version_aggregator.GetVersionAggregator().ReportVersion(k, v, version_aggregator.VersionTypes.TOOL)

        # Check requirements

        # 1 - az cli tool missing will raise exception on call to az --version earlier in function

        # 2 - Check for azure-devops extension
        if "azure-devops" not in found.keys():
            logging.critical(
                "Missing required Azure-cli extension azure-devops.\n"
                "Installation instructions: https://learn.microsoft.com/azure/devops/cli"
            )
            raise EnvironmentError("Missing required Azure-cli extension azure-devops")

        cls.VersionLogged = True

    def __init__(self, descriptor: dict) -> None:
        """Inits a Azure CLI dependency based off the provided descriptior."""
        super().__init__(descriptor)
        self.global_cache_path = None
        self.organization = self.source
        self.feed = descriptor.get("feed")
        self.project = descriptor.get("project", None)
        self.file_filter = descriptor.get("file-filter", None)
        self.compression_type = descriptor.get("compression_type", None)
        self.internal_path = descriptor.get("internal_path", "/")
        if self.internal_path:
            self.internal_path = os.path.normpath(self.internal_path)
            self.internal_path = self.internal_path.strip(os.path.sep)
        _pat_var = descriptor.get("pat_var", None)
        self._pat = None

        if _pat_var is not None:
            # Get the PAT or if not defined in shell_var it will return None
            self._pat = shell_environment.GetEnvironment().get_shell_var(_pat_var)

    def _fetch_from_cache(self, package_name: str) -> bool:
        ## AZ tool has no cache feature
        return False

    def __str__(self) -> str:
        """Return a string representation."""
        return f"AzCliUniversalDependency: {self.name}@{self.version}"

    def _attempt_universal_install(self, install_dir: str) -> None:
        #
        # fetch the contents of the package.
        #
        cmd = ["az"]
        cmd += ["artifacts", "universal", "download"]
        cmd += ["--organization", self.organization]
        cmd += ["--feed", self.feed]
        cmd += ["--name", self.name]
        cmd += ["--version", self.version]
        if self.project is not None:
            cmd += ["--project", self.project]
            cmd += ["--scope", "project"]
        if self.file_filter is not None:
            cmd += ["--file-filter", self.file_filter]
        cmd += ["--path", '"' + install_dir + '"']

        # get the shell environment
        e = os.environ.copy()
        # if PAT then add the PAT as special variable
        if self._pat is not None:
            e[self.AZURE_CLI_DEVOPS_ENV_VAR] = self._pat

        results = StringIO()
        ret = RunCmd(cmd[0], " ".join(cmd[1:]), outstream=results, environ=e)
        if ret != 0:
            results.seek(0)
            raise Exception(f'\nCommand "{" ".join(cmd)}" failed with {ret}.\n\n{results.getvalue()}')

        # az tool returns json data that includes the downloaded version
        # lets check it to double confirm
        try:
            result_data = json.loads(results.getvalue())
        except Exception as e:
            logging.info(f"Failed to parse json data from az command output: {e}")

            # Search results to find the json data
            index_start = results.getvalue().find("{")
            index_end = results.getvalue().rfind("}")

            if index_start == -1 or index_end == -1:
                raise ValueError("Failed to find valid json data in az command output")
            results.seek(index_start)
            result_data = json.loads(results.read(index_end - index_start + 1))

        results.close()
        downloaded_version = result_data["Version"]
        if self.version != downloaded_version:
            self.version = downloaded_version  # set it so state file is accurate and will fail on verify
            raise Exception(
                "Download Universal Package version (%s) different than requested (%s)."
                % (downloaded_version, self.version)
            )

    def fetch(self) -> None:
        """Fetches the dependency using internal state from the init."""
        #
        # Before trying anything with we should check
        # to see whether the package is already in
        # our local cache. If it is, we avoid a lot of
        # time and network cost by copying it directly.
        #
        if self._fetch_from_cache(self.name):
            # We successfully found the package in the cache.
            # The published path may change now that the package has been unpacked.
            self.published_path = self.compute_published_path()
            return

        #
        # If we are still here, the package wasn't in the cache.
        # We need to ask Nuget to find it.
        #
        temp_directory = self.get_temp_dir()
        self._attempt_universal_install(temp_directory)

        #
        # if there is a compression type, the only thing downloaded must be the compressed
        # file. If this is true, we will unpack it directly into the the contents
        # directory and delete the temp directory.
        #
        if self.compression_type:
            files = list(Path(temp_directory).iterdir())
            if len(files) != 1:
                raise Exception("Expected only 1 file in the downloaded directory")
            tmp_file_path = files[0]
            WebDependency.unpack(tmp_file_path, temp_directory, self.internal_path, self.compression_type)
            tmp_file_path.unlink()

            source_dir = os.path.join(temp_directory, self.internal_path)
        else:
            source_dir = temp_directory
        #
        # Next, copy the contents of the package to the
        # final resting place.
        #
        shutil.copytree(source_dir, self.contents_dir)

        RemoveTree(temp_directory)

        #
        # Add a file to track the state of the dependency.
        #
        self.update_state_file()

        # The published path may change now that the package has been unpacked.
        self.published_path = self.compute_published_path()

    def get_temp_dir(self) -> str:
        """Returns the temporary directory the Azure CLI feed is downloaded to."""
        return self.contents_dir + "_temp"

    def clean(self) -> None:
        """Removes the temporary directory the NuGet package is downloaded to."""
        super(AzureCliUniversalDependency, self).clean()
        if os.path.isdir(self.get_temp_dir()):
            RemoveTree(self.get_temp_dir())
