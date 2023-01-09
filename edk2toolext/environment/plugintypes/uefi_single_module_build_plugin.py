# @file uefi_build_plugin.py
# A Plugin that supports Pre and Post Build steps on a full platform build
##
# Copyright (c) Microsoft Corporation
#
# SPDX-License-Identifier: BSD-2-Clause-Patent
##
"""A Plugin that supports Pre and Post Build Steps on a single module platform build."""


class IUefiSingleModuleBuildPlugin(object):
    """Plugin that supports Pre and Post Build Steps on a single module platform build."""

    def do_post_build(self, thebuilder):
        """Runs Post Build Plugin Operations.

        Args:
            thebuilder (UefiBuilder): UefiBuild object for env information

        Returns:
            (int): 0 or NonZero for success or failure
        """
        return 0

    def do_pre_build(self, thebuilder):
        """Runs Pre Build Plugin Operations.

        Args:
            thebuilder (UefiBuilder): UefiBuild object for env information

        Returns:
            (int): 0 or NonZero for success or failure
        """
        return 0
