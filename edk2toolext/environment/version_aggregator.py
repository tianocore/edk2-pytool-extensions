# @file version_aggregator facilitates the collection of information
# regarding the tools, binaries, submodule configuration used in a build
#
##
# Copyright (c) Microsoft Corporation
#
# SPDX-License-Identifier: BSD-2-Clause-Patent
##

import copy
import logging
from enum import Enum

VERSION_AGGREGATOR = None


class version_aggregator(object):
    def __init__(self):
        super(version_aggregator, self).__init__()
        self._Versions = {}
        self._logger = logging.getLogger("version_aggregator")

    def ReportVersion(self, key, value, versionType, path=None):
        """
        Report the version of something.

        key -- The name of what you are reporting.
        value -- The value of what you are reporting.
        versionType -- The method of categorizing what is being reported. See VersionTypes for details.
        """
        if key in self._Versions:
            old_version = self._Versions[key]
            if old_version["version"] == value and old_version["path"] == path:
                self._logger.info(f"version_aggregator: {key} re-registered at {path}")
                pass
            else:
                error = "version_aggregator: {0} key registered with a different value\n\t" \
                        "Old:{1}@{3}\n\tNew:{2}@{4}\n".format(
                            key, old_version["version"], value, old_version["path"], path)
                self._logger.error(error)
                raise ValueError(error)
            return

        self._Versions[key] = {
            "name": key,
            "version": value,
            "type": versionType.name,
            "path": path
        }
        self._logger.debug("version_aggregator logging version: {0}".format(str(self._Versions[key])))

    def Print(self):
        """ Prints out the current information from the version aggregator """
        for version_key in self._Versions:
            version = self._Versions[version_key]
            print(f"{version['type']} - {version['name']}: {version['version']}")
        if len(self._Versions) == 0:
            print("VERSION AGGREGATOR IS EMPTY")

    def GetAggregatedVersionInformation(self):
        """
        Returns a copy of the aggregated information.
        """
        return copy.deepcopy(self._Versions)

    def Reset(self):
        self._Versions = {}


class VersionTypes(Enum):
    """
    COMMIT is for the commit hash of a repository.
    BINARY is for a pre-packaged binary that is distributed with a version number.
    TOOL is for recording the version number of a tool that was used during the build process.
    INFO is for recording miscellaneous information.
    PIP is for recording a python pip package.
    """
    TOOL = 1
    COMMIT = 2
    BINARY = 3
    INFO = 4
    PIP = 5


def GetVersionAggregator():
    """
    Returns a singleton instance of this class for global use.
    """
    global VERSION_AGGREGATOR

    if VERSION_AGGREGATOR is None:
        logging.debug("Setting up version aggregator")
        VERSION_AGGREGATOR = version_aggregator()

    return VERSION_AGGREGATOR


def ResetVersionAggregator():
    '''
    Resets the version Aggregator singleton
    '''
    GetVersionAggregator().Reset()
