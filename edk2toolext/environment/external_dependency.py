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
import shutil
import time
import yaml
from edk2toolext.environment import version_aggregator
from edk2toollib.utility_functions import GetHostInfo


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

        self.descriptor_location = os.path.dirname(
            descriptor['descriptor_file'])
        self.contents_dir = os.path.join(
            self.descriptor_location, self.name + "_extdep")
        self.state_file_path = os.path.join(
            self.contents_dir, "extdep_state.json")
        self.published_path = self.compute_published_path()

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

    def _clean_directory(self, dir_path):
        retry = 1
        while True:
            try:
                shutil.rmtree(dir_path)
            except OSError:
                if not retry:
                    # If we're out of retries, bail.
                    raise
                time.sleep(5)
                retry -= 1
                continue
            break

    def clean(self):
        logging.debug("Cleaning dependency directory for '%s'..." % self.name)
        if os.path.isdir(self.contents_dir):
            self._clean_directory(self.contents_dir)

    def fetch(self):
        # The base class does not implement a fetch.
        logging.critical("Fetch() CALLED ON BASE EXTDEP CLASS!")
        pass

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
        version_aggregator.GetVersionAggregator().ReportVersion(self.name, self.version,
                                                                version_aggregator.VersionTypes.INFO)
        return result

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
