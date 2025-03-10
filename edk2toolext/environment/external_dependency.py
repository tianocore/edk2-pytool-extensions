# @file external_dependencies.py
# This module contains helper objects that can manipulate,
# retrieve, validate, and clean external dependencies for the
# build environment.
#
##
# Copyright (c) Microsoft Corporation
#
# SPDX-License-Identifier: BSD-2-Clause-Patent
##
"""This module contains helper object for manipulating external dependencies.

These manipulations include retrieving, validating, and cleaning external
dependencies for the build environment.
"""

import hashlib
import logging
import os
import shutil
from typing import Optional

import yaml
from edk2toollib.utility_functions import GetHostInfo, RemoveTree

from edk2toolext.environment import version_aggregator


class ExternalDependency(object):
    """Baseclass to allow downloading external dependencies during the update phase.

    Specific External dependency types (git, nuget, etc.) are subclassed from
    this class. Additional external dependency types may be created.

    Attributes:
        scope (str): Determines if descriptor is included on a particular build.
        type (str): Type of ext_dep.
        name (str): Name of ext_dep, used to name the folder the ext_dep will be unpacked in to
        source (str): Source to query for ext_dep.
        version (str): Version string to keep track of what version is currently installed.
        flags (list[str]): Flags dictating what actions should be taken once this dependency is resolved
                           More info: (docs/feature_extdep/)
        var_name (str): Used with set_*_var flag. Determines name of var to be set.

    !!! tip
        The attributes are what must be described in the ext_dep yaml file!
    """

    def __init__(self: str, descriptor: dict) -> None:
        """Inits a web dependency based off the provided descriptor."""
        super(ExternalDependency, self).__init__()

        #
        # Set the data for this object.
        #
        self.scope = descriptor["scope"]
        self.type = descriptor["type"]
        self.name = descriptor["name"]
        self.source = descriptor["source"]
        self.version = descriptor["version"]
        self.flags = descriptor.get("flags", None)
        self.var_name = descriptor.get("var_name", None)
        self.error_msg = descriptor.get("error_msg", None)
        self.global_cache_path = None

        self.descriptor_location = os.path.dirname(descriptor["descriptor_file"])
        self.contents_dir = os.path.join(self.descriptor_location, self.name + "_extdep")
        self.state_file_path = os.path.join(self.contents_dir, "extdep_state.yaml")
        self.published_path = self.compute_published_path()

    def set_global_cache_path(self, global_cache_path: str) -> "ExternalDependency":
        """Sets the global cache path to locate already downloaded dependencies.

        Arguments:
            global_cache_path (str): directory of the global cache
        """
        self.global_cache_path = os.path.abspath(global_cache_path)
        return self

    def compute_published_path(self) -> str:
        """Determines the published path."""
        new_published_path = self.contents_dir

        if self.flags and "host_specific" in self.flags and self.verify():
            host = GetHostInfo()

            logging.info("Computing path for {0} located at {1} on {2}".format(self.name, self.contents_dir, str(host)))

            acceptable_names = []

            # we want to list all the possible folders we would be comfortable using
            # and then check if they are present.
            # The "ideal" directory name is OS-ARCH-BIT
            acceptable_names.append("-".join((host.os, host.arch, host.bit)))
            acceptable_names.append("-".join((host.os, host.arch)))
            acceptable_names.append("-".join((host.os, host.bit)))
            acceptable_names.append("-".join((host.arch, host.bit)))
            acceptable_names.append(host.os)
            acceptable_names.append(host.arch)
            acceptable_names.append(host.bit)

            new_published_path = None
            for name in acceptable_names:
                dirname = os.path.join(self.contents_dir, name)
                if os.path.isdir(dirname):
                    logging.info("{0} was found!".format(dirname))
                    new_published_path = dirname
                    break
                logging.debug("{0} does not exist".format(dirname))

            if new_published_path is None:
                logging.error(f"{self.name} is host specific, but does not appear to have support for {str(host)}.")
                logging.error(
                    f"Verify support for detected host: {str(host)} and contact dependency provider to add support."
                )
                logging.error("Otherwise, delete the external dependency directory to reset.")

                new_published_path = self.contents_dir

        if self.flags and "include_separator" in self.flags:
            new_published_path += os.path.sep

        return new_published_path

    def clean(self: str) -> None:
        """Removes the local directory for the external dependency."""
        logging.debug("Cleaning dependency directory for '%s'..." % self.name)
        if os.path.isdir(self.contents_dir):
            RemoveTree(self.contents_dir)

    def determine_cache_path(self) -> Optional[str]:
        """Determines the cache path is global_cache_path is not none."""
        result = None
        if self.global_cache_path is not None and os.path.isdir(self.global_cache_path):
            subpath_calc = hashlib.sha1()
            subpath_calc.update(self.version.encode("utf-8"))
            subpath_calc.update(self.source.encode("utf-8"))
            subpath = subpath_calc.hexdigest()
            result = os.path.join(self.global_cache_path, self.type, self.name, subpath)
        return result

    def fetch(self) -> bool:
        """Fetches the dependency using internal state from the init."""
        cache_path = self.determine_cache_path()
        if cache_path is None or not os.path.isdir(cache_path):
            return False
        logging.debug("Found %s extdep '%s' in global cache." % (self.type, self.name))
        self.copy_from_global_cache(self.contents_dir)
        self.published_path = self.compute_published_path()
        self.update_state_file()
        return True

    def copy_from_global_cache(self, dest_path: str) -> None:
        """Copies the dependency from global cache if present.

        Arguments:
            dest_path (str): path to copy to
        """
        cache_path = self.determine_cache_path()
        if cache_path is None:
            return
        if os.path.isdir(cache_path):
            shutil.copytree(cache_path, dest_path, dirs_exist_ok=True)

    def copy_to_global_cache(self, source_path: str) -> None:
        """Copies the dependency to global cache if present.

        Arguments:
            source_path (str): source to copy into global cache.
        """
        cache_path = self.determine_cache_path()
        if cache_path is None:
            return
        if not os.path.isdir(cache_path):
            os.makedirs(cache_path)
        else:
            shutil.rmtree(cache_path)
        shutil.copytree(source_path, cache_path, dirs_exist_ok=True)

    def verify(self) -> int:
        """Verifies the dependency was successfully downloaded."""
        result = True
        state_data = None

        # See whether or not the state file exists.
        if not os.path.isfile(self.state_file_path):
            result = False

        # Attempt to load the state file.
        if result:
            with open(self.state_file_path, "r") as file:
                try:
                    state_data = yaml.safe_load(file)
                except Exception:
                    pass
        if state_data is None:
            result = False

        # If loaded, check the version.
        if result and state_data["version"] != self.version:
            result = False

        logging.debug("Verify '%s' returning '%s'." % (self.name, result))
        return result

    def report_version(self) -> None:
        """Reports the version of the external dependency."""
        version_aggregator.GetVersionAggregator().ReportVersion(
            self.name, self.version, version_aggregator.VersionTypes.INFO, self.descriptor_location
        )

    def update_state_file(self) -> None:
        """Updates the file representing the state of the dependency."""
        with open(self.state_file_path, "w+") as file:
            yaml.dump({"version": self.version}, file)


def ExtDepFactory(descriptor: dict) -> "ExternalDependency":
    """External Dependency Factory capable of generating each type of dependency.

    !!! Note
        Ensure all external dependencies are imported in this class to avoid errors.
    """
    from edk2toolext.environment.extdeptypes.az_cli_universal_dependency import AzureCliUniversalDependency
    from edk2toolext.environment.extdeptypes.git_dependency import GitDependency
    from edk2toolext.environment.extdeptypes.nuget_dependency import NugetDependency
    from edk2toolext.environment.extdeptypes.web_dependency import WebDependency

    if descriptor["type"] == NugetDependency.TypeString:
        return NugetDependency(descriptor)
    elif descriptor["type"] == WebDependency.TypeString:
        return WebDependency(descriptor)
    elif descriptor["type"] == GitDependency.TypeString:
        return GitDependency(descriptor)
    elif descriptor["type"] == AzureCliUniversalDependency.TypeString:
        AzureCliUniversalDependency.VerifyToolDependencies()
        return AzureCliUniversalDependency(descriptor)

    raise ValueError("Unknown extdep type '%s' requested!" % descriptor["type"])
