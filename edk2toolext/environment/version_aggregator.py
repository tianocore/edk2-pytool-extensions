# @file version_aggregator facilitates the collection of information
# regarding the tools, binaries, submodule configuration used in a build
#
##
# Copyright (c) Microsoft Corporation
#
# SPDX-License-Identifier: BSD-2-Clause-Patent
##
"""Used to facilitate the collection of information.

Used to facilitate the collection of information regarding the tools,
binaries, submodule configuration used in a build.
"""

import copy
import logging
from enum import Enum
from typing import Optional

VERSION_AGGREGATOR = None


class version_aggregator(object):
    """Used to facilitate the collection of information.

    Used to facilitate the collection of information regarding the tools,
    binaries, submodule configuration used in a build.
    """

    def __init__(self) -> None:
        """Inits an empty verion aggregator."""
        super(version_aggregator, self).__init__()
        self._Versions = {}
        self._logger = logging.getLogger("version_aggregator")

    def ReportVersion(self, key: str, value: str, versionType: str, path: Optional[str] = None) -> None:
        """Report the version of something.

        Args:
            key (str): the name of what you are reporting.
            value (str): The value of what you are reporting.
            versionType (str): The method of categorizing what is being reported. See VersionTypes for details.
            path (str): the associated path.
        """
        if key in self._Versions:
            old_version = self._Versions[key]
            if old_version["version"] == value and old_version["path"] == path:
                self._logger.info(f"version_aggregator: {key} re-registered at {path}")
            else:
                error = (
                    "version_aggregator: {0} key registered with a different value\n\t"
                    "Old:{1}@{3}\n\tNew:{2}@{4}\n".format(key, old_version["version"], value, old_version["path"], path)
                )
                self._logger.error(error)
                raise ValueError(error)
            return

        self._Versions[key] = {"name": key, "version": value, "type": versionType.name, "path": path}
        self._logger.debug("version_aggregator logging version: {0}".format(str(self._Versions[key])))

    def Print(self) -> None:
        """Prints out the current information from the version aggregator."""
        for version_key in self._Versions:
            version = self._Versions[version_key]
            print(f"{version['type']} - {version['name']}: {version['version']}")
        if len(self._Versions) == 0:
            print("VERSION AGGREGATOR IS EMPTY")

    def GetAggregatedVersionInformation(self) -> "version_aggregator":
        """Returns a copy of the aggregated information."""
        return copy.deepcopy(self._Versions)

    def Reset(self) -> None:
        """Resets all versions."""
        self._Versions = {}


class VersionTypes(Enum):
    """Enumerator representing the different version types for recording.

    Attributes:
        COMMIT: the commit hash of a repository.
        BINARY: pre-packaged binary that is distributed with a version number.
        TOOL: the version number of a tool that was used during the build process.
        INFO: miscellaneous information.
        PIP: a python pip package.
    """

    TOOL = 1
    COMMIT = 2
    BINARY = 3
    INFO = 4
    PIP = 5


def GetVersionAggregator() -> version_aggregator:
    """Returns a singleton instance of this class for global use."""
    global VERSION_AGGREGATOR

    if VERSION_AGGREGATOR is None:
        logging.debug("Setting up version aggregator")
        VERSION_AGGREGATOR = version_aggregator()

    return VERSION_AGGREGATOR


def ResetVersionAggregator() -> None:
    """Resets the version Aggregator singleton."""
    GetVersionAggregator().Reset()
