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

import os
import logging
import yaml
import hashlib
import shutil
from edk2toolext.environment import version_aggregator
from edk2toollib.utility_functions import GetHostInfo, RemoveTree


class ExternalDependency(object):
    '''
    ext_dep fields:
    - scope: Determines if descriptor is included on a particular build.
    - type: Type of ext_dep.
    - name: Name of ext_dep, used to name the folder the ext_dep will be unpacked in to
    - source: Source to query for ext_dep.
    - version: Version string to keep track of what version is currently installed.
    - flags: Flags dictating what actions should be taken once this dependency is resolved
             More info: (docs/feature_extdep/)
    - var_name: Used with set_*_var flag. Determines name of var to be set.
    '''

    def __init__(self, descriptor):
        super(ExternalDependency, self).__init__()

        #
        # Set the data for this object.
        #
        self.scope = descriptor['scope']
        self.type = descriptor['type']
        self.name = descriptor['name']
        self.source = descriptor['source']
        self.version = descriptor['version']
        self.flags = descriptor.get('flags', None)
        self.var_name = descriptor.get('var_name', None)
        self.error_msg = descriptor.get('error_msg', None)
        self.global_cache_path = None

        self.descriptor_location = os.path.dirname(
            descriptor['descriptor_file'])
        self.contents_dir = os.path.join(
            self.descriptor_location, self.name + "_extdep")
        self.state_file_path = os.path.join(
            self.contents_dir, "extdep_state.json")
        self.published_path = self.compute_published_path()

    def set_global_cache_path(self, global_cache_path):
        self.global_cache_path = os.path.abspath(global_cache_path)
        return self

    def compute_published_path(self):
        new_published_path = self.contents_dir

        if self.flags and "host_specific" in self.flags and self.verify():
            host = GetHostInfo()

            logging.info("Computing path for {0} located at {1} on {2}".format(self.name,
                                                                               self.contents_dir,
                                                                               str(host)))

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
                logging.error("Could not find appropriate folder for {0}. {1}".format(self.name, str(host)))
                new_published_path = self.contents_dir

        if self.flags and "include_separator" in self.flags:
            new_published_path += os.path.sep

        return new_published_path

    def clean(self):
        logging.debug("Cleaning dependency directory for '%s'..." % self.name)
        if os.path.isdir(self.contents_dir):
            RemoveTree(self.contents_dir)

    def determine_cache_path(self):
        result = None
        if self.global_cache_path is not None and os.path.isdir(self.global_cache_path):
            subpath_calc = hashlib.sha1()
            subpath_calc.update(self.version.encode('utf-8'))
            subpath_calc.update(self.source.encode('utf-8'))
            subpath = subpath_calc.hexdigest()
            result = os.path.join(self.global_cache_path, self.type, self.name, subpath)
        return result

    def fetch(self):
        cache_path = self.determine_cache_path()
        if cache_path is None or not os.path.isdir(cache_path):
            return False
        logging.debug("Found %s extdep '%s' in global cache." % (self.type, self.name))
        self.copy_from_global_cache(self.contents_dir)
        self.published_path = self.compute_published_path()
        self.update_state_file()
        return True

    def copy_from_global_cache(self, dest_path: str):
        cache_path = self.determine_cache_path()
        if cache_path is None:
            return
        if os.path.isdir(cache_path):
            shutil.copytree(cache_path, dest_path, dirs_exist_ok=True)

    def copy_to_global_cache(self, source_path: str):
        cache_path = self.determine_cache_path()
        if cache_path is None:
            return
        if not os.path.isdir(cache_path):
            os.makedirs(cache_path)
        else:
            shutil.rmtree(cache_path)
        shutil.copytree(source_path, cache_path, dirs_exist_ok=True)

    def verify(self):
        result = True
        state_data = None

        # See whether or not the state file exists.
        if not os.path.isfile(self.state_file_path):
            result = False

        # Attempt to load the state file.
        if result:
            with open(self.state_file_path, 'r') as file:
                try:
                    state_data = yaml.safe_load(file)
                except Exception:
                    pass
        if state_data is None:
            result = False

        # If loaded, check the version.
        if result and state_data['version'] != self.version:
            result = False

        logging.debug("Verify '%s' returning '%s'." % (self.name, result))
        return result

    def report_version(self):
        version_aggregator.GetVersionAggregator().ReportVersion(self.name,
                                                                self.version,
                                                                version_aggregator.VersionTypes.INFO,
                                                                self.descriptor_location)

    def update_state_file(self):
        with open(self.state_file_path, 'w+') as file:
            yaml.dump({'version': self.version}, file)


def ExtDepFactory(descriptor):
    # Add all supported external dependencies here to avoid import errors.
    from edk2toolext.environment.extdeptypes.web_dependency import WebDependency
    from edk2toolext.environment.extdeptypes.nuget_dependency import NugetDependency
    from edk2toolext.environment.extdeptypes.git_dependency import GitDependency
    if descriptor['type'] == NugetDependency.TypeString:
        return NugetDependency(descriptor)
    elif descriptor['type'] == WebDependency.TypeString:
        return WebDependency(descriptor)
    elif descriptor['type'] == GitDependency.TypeString:
        return GitDependency(descriptor)

    raise ValueError("Unknown extdep type '%s' requested!" % descriptor['type'])
