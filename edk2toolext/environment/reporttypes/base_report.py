# @file base_report.py
# An interface to create custom reports with.
##
# Copyright (c) Microsoft Corporation
#
# SPDX-License-Identifier: BSD-2-Clause-Patent
##
"""An interface to create custom reports with."""

from argparse import ArgumentParser, Namespace
from typing import Tuple

from edk2toollib.database import Edk2DB


class Report:
    """The interface to create custom reports."""

    def report_info(self) -> Tuple[str, str]:
        """Returns the report standard information.

        Returns:
            (str, str): A tuple of (name, description)
        """
        raise NotImplementedError

    def add_cli_options(self, parserobj: ArgumentParser) -> None:
        """Configure command line arguments for this report."""
        return

    def run_report(self, db: Edk2DB, args: Namespace) -> None:
        """Generate a report."""
        raise NotImplementedError
