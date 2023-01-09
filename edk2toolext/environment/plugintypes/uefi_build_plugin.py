# @file UefiBuildPlugin
# Module to supports Pre and Post Build steps via plugins
##
# Copyright (c) Microsoft Corporation
#
# SPDX-License-Identifier: BSD-2-Clause-Patent
##
"""Module to support Pre and Post Build Steps via plugins."""
from typing import TYPE_CHECKING
if TYPE_CHECKING:
    from edk2toolext.environment.uefi_build import UefiBuilder


class IUefiBuildPlugin(object):
    """Plugin that supports Pre and Post Build Steps."""

    def runs_on(self, build_type: str) -> bool:
        """Describes if the plugin should for a given build type.

        Args:
            build_type (str): type of build being performed

        !!! tip "build_type possible values"
            dsc == building a platform/package that has a dsc file

            inf == building a single module that has an inf

        Returns:
            (bool): if the plugin should run or not
        """
        if build_type == "dsc":
            return True
        return False

    def do_post_build(self, thebuilder: 'UefiBuilder') -> int:
        """Runs Post Build Plugin Operations.

        Args:
            thebuilder (UefiBuilder): UefiBuild object for env information

        Returns:
            (int): 0 or NonZero for success or failure
        """
        return 0

    def do_pre_build(self, thebuilder: 'UefiBuilder') -> int:
        """Runs Pre Build Plugin Operations.

        Args:
            thebuilder (UefiBuilder): UefiBuild object for env information

        Returns:
            (int): 0 or NonZero for success or failure
        """
        return 0
