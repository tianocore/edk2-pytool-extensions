# @file dsc_processor_plugin
# Plugin for parsing DSCs
##
# Copyright (c) Microsoft Corporation
#
# SPDX-License-Identifier: BSD-2-Clause-Patent
##
"""Plugin for parsing DSCs."""

from edk2toollib.uefi.edk2.parsers.dsc_parser import DscParser

from edk2toolext.environment.uefi_build import UefiBuilder


class IDscProcessorPlugin(object):
    """Plugin for parsing DSCs."""

    def do_transform(self, dsc: DscParser, thebuilder: UefiBuilder) -> int:
        """Does the transform on a DSC.

        Args:
            dsc (DscParser): the in-memory model of the DSC
            thebuilder (UefiBuilder): UefiBuild object for env information

        Returns:
            (int): 0 or NonZero for success or failure
        """
        return 0

    def get_level(self, thebuilder: UefiBuilder) -> int:
        """Gets the level that this transform operates at.

        Args:
            thebuilder (UefiBuilder): UefiBuild object for env information

        Returns:
            (int): the level

        """
        return 0
