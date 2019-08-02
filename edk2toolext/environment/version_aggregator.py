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
        self.Versions = {}
        self._logger = logging.getLogger("version_aggregator")

    def ReportVersion(self, key, value, versionType):
        """
        Report the version of something.

        key -- The name of what you are reporting.
        value -- The value of what you are reporting.
        versionType -- The method of categorizing what is being reported. See VersionTypes for details.
        """
        if key in self.Versions:
            if self.Versions[key]["version"] == value:
                self._logger.warning("version_aggregator: This {0}:{1} key/value pair "
                                     "was already registered".format(key, value))
            else:
                error = "version_aggregator: {0} key registered with a different value\n\t" \
                        "Old:{1}\n\tNew:{2}".format(key, self.Versions[key]["version"], value)
                self._logger.error(error)
                raise Exception(error)
            return

        self.Versions[key] = {
            "name": key,
            "version": value,
            "type": versionType.name
        }
        self._logger.debug("version_aggregator logging version: {0}".format(str(self.Versions[key])))

    def GetAggregatedVersionInformation(self):
        """
        Returns a copy of the aggregated information.
        """
        return copy.deepcopy(self.Versions)


class VersionTypes(Enum):
    """
    COMMIT is for the commit hash of a repository.
    BINARY is for a pre-packaged binary that is distributed with a version number.
    TOOL is for recording the version number of a tool that was used during the build process.
    INFO is for recording miscellanious information.
    """
    TOOL = 1
    COMMIT = 2
    BINARY = 3
    INFO = 4


def GetVersionAggregator():
    """
    Returns a singleton instance of this class for global use.
    """
    global VERSION_AGGREGATOR

    if VERSION_AGGREGATOR is None:
        logging.debug("Setting up version aggregator")
        VERSION_AGGREGATOR = version_aggregator()

    return VERSION_AGGREGATOR
