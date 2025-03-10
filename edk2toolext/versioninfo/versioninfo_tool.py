# @file versioninfo_tool.py
# This module contains the CLI interface for easily creating VERSIONINFO resources
# from json files.
#
##
# Copyright (C) Microsoft Corporation
#
# SPDX-License-Identifier: BSD-2-Clause-Patent
##
"""A Command-line tool to generate VERSIONINFO resource files.

Versioninfo Tool is a command-line tool to assist in generating VERSIONINFO
resource files for use with a Resource Compiler. It takes a JSON representing
versioning info and produces a resource file that once compiled will create a
standard resource section.
"""

import argparse
import json
import logging
import os
import sys
import typing

from edk2toolext.versioninfo.versioninfo_helper import PEObject, VERSIONINFOGenerator

TOOL_VERSION = "0.7.0"  # please change this as the tool is updated.

TOOL_DESCRIPTION = """
Versioninfo Tool is a command-line tool to assist in generating VERSIONINFO
resource files for use with a Resource Compiler. It takes a JSON representing
versioning info and produces a resource file that once compiled will create a
standard resource section.

!!! Warning - BETA Feature
This tool is still in early development and may change with
little regard for backward compatibility.

Version: %s

An example to encode json to rc file might look like:
%s -e /path/to/version.JSON /path/to/output

An example to decode a binary efi file and output the rsrc in json might look like:
%s -d /path/to/app.efi /path/to/output.JSON
""" % (TOOL_VERSION, os.path.basename(sys.argv[0]), os.path.basename(sys.argv[0]))


def get_cli_options(args: typing.Sequence[str] = None) -> argparse.Namespace:
    """Parse options from the command line.

    Will parse the primary options from the command line. If provided, will take the options as
    an array in the first parameter
    """
    parser = argparse.ArgumentParser(description=TOOL_DESCRIPTION, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("input_file", type=str, help="a filesystem path to a json/PE file to load")
    parser.add_argument(
        "output_file",
        type=str,
        help="a filesystem path to the output file. if file does not exist, entire directory path will be created. if file does exist, contents will be overwritten",  # noqa
    )  # noqa

    command_group = parser.add_mutually_exclusive_group()
    command_group.add_argument(
        "-e",
        "--encode",
        action="store_const",
        const="e",
        dest="mode",
        help="(default) outputs VERSIONINFO.rc of given json file",
    )
    command_group.add_argument(
        "-d",
        "--dump",
        action="store_const",
        dest="mode",
        const="d",
        help="outputs json file of VERSIONINFO given PE file",
    )
    parser.set_defaults(mode="e")
    return parser.parse_args(args=args)


def decode_version_info(input_file: str) -> dict:
    """Takes in a PE file (input_file) and returns the version dictionary.

    Args:
        input_file (str): path to a PE file

    Returns:
        (dict): version dictionary
    """
    if not os.path.exists(input_file):
        raise FileNotFoundError(input_file)
    pe = PEObject(input_file)
    return pe.get_version_dict()


def decode_version_info_dump_json(input_file: str, output_file: str) -> bool:
    """Takes in a PE file (input_file) and dumps the output as json to (output_file).

    Args:
        input_file (str): Path to a PE file
        output_file (str): Path to json dump

    Returns:
        (bool): result of parsing and dumping
    """
    version_info = decode_version_info(input_file)
    if not version_info:
        logging.error(f"{input_file} doesn't have version info.")
        return False
    with open(output_file, "w") as out:
        json.dump(version_info, out)
    return True


def encode_version_info(input_file: str) -> VERSIONINFOGenerator:
    """Takes in a JSON file (inputfile) and returns an object.

    Args:
        input_file (str): path to JSON File

    Returns:
        (VERSIONINFOGenerator): VERSIONINFO rc file Generator object
    """
    if not os.path.exists(input_file):
        raise FileNotFoundError(input_file)
    return VERSIONINFOGenerator(input_file)


def encode_version_info_dump_rc(input_file: str, output_file: str) -> bool:
    """Takes in a JSON file (input_file) and outputs an RC file(output_file).

    Args:
        input_file (str): path to JSON file
        output_file (str): path to RC file

    Returns:
        (bool): Result of writing to file
    """
    return encode_version_info(input_file).write(output_file, TOOL_VERSION)


def main() -> None:
    """Parse args, executes versioninfo_tool."""
    logging.getLogger().addHandler(logging.StreamHandler())
    args = get_cli_options()
    if not os.path.isfile(args.input_file):
        logging.error("Could not find " + args.input_file)
        sys.exit(1)

    if args.mode == "d":
        # we need to dump
        if not decode_version_info_dump_json(args.input_file, args.output_file):
            sys.exit(1)
    elif args.mode == "e":
        # we need to encode
        if not encode_version_info_dump_rc(args.input_file, args.output_file):
            sys.exit(1)
    else:
        # unknown mode
        logging.error(f"Unknown mode: {args.mode}")
        sys.exit(1)


if __name__ == "__main__":
    main()
