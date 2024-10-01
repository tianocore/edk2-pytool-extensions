# @file codeql.py
#
# Exports functions commonly needed for Stuart-based platforms to easily
# enable CodeQL in their platform build.
#
# Copyright (c) Microsoft Corporation. All rights reserved.
# SPDX-License-Identifier: BSD-2-Clause-Patent
##
"""CodeQL Helper Functions.

Contains functions are intended to ease repo integration with CodeQL, ensure
consistent command-line usage across repos, and define standard scopes that
other plugins and tools can depend on for CodeQL operations.
"""

from argparse import ArgumentParser, Namespace
from typing import Tuple

from edk2toollib.utility_functions import GetHostInfo

from edk2toolext.environment.uefi_build import UefiBuilder


def add_command_line_option(parser: ArgumentParser) -> None:
    """Add the CodeQL command to the platform command line options.

    Args:
        parser (ArgumentParser): The argument parser used in this build.

    """
    parser.add_argument(
        "--codeql",
        dest="codeql",
        action="store_true",
        default=False,
        help="Optional - Produces CodeQL results from the build.",
    )


def get_scopes(codeql_enabled: bool) -> Tuple[str]:
    """Return the active CodeQL scopes for this build.

    Args:
        codeql_enabled (bool): Whether CodeQL is enabled.

    Returns:
        Tuple[str]: A tuple of strings containing scopes that enable the
                    CodeQL plugin.
    """
    active_scopes = ()

    if codeql_enabled:
        if GetHostInfo().os == "Linux":
            active_scopes += ("codeql-linux-ext-dep",)
        else:
            active_scopes += ("codeql-windows-ext-dep",)
        active_scopes += ("codeql-build", "codeql-analyze")

    return active_scopes


def is_codeql_enabled_on_command_line(args: Namespace) -> bool:
    """Return whether CodeQL was enabled on the command line.

    Args:
        args (Namespace): Object holding a string representation of command
                          line arguments.

    Returns:
        bool: True if CodeQL is enabled on the command line. Otherwise, false.
    """
    return args.codeql


def set_audit_only_mode(uefi_builder: UefiBuilder) -> None:
    """Configure the CodeQL plugin to run in audit only mode.

    Args:
        uefi_builder (UefiBuilder): The UefiBuilder object for this platform
                                    build.

    """
    uefi_builder.env.SetValue("STUART_CODEQL_AUDIT_ONLY", "true", "Platform Defined")
