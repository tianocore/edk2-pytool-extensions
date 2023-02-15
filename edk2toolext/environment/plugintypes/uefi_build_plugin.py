# @file UefiBuildPlugin
# Plugin that supports Pre and Post Build steps
##
# Copyright (c) Microsoft Corporation
#
# SPDX-License-Identifier: BSD-2-Clause-Patent
##
"""Plugin that supports Pre and Post Build Steps."""


class IUefiBuildPlugin(object):
    """Plugin that supports Pre and Post Build Steps."""

    def runs_on_list(self, thebuilder) -> list[str]:
        """Returns a list of build types this plugin should execute on.

        !!! note "Known build types"
            dsc, inf
        """
        return ["dsc"]

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
