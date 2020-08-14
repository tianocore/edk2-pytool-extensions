# @file versioninfo_tool.py
# This module contains the CLI interface for easily creating VERSIONINFO resources
# from json files.
#
##
# Copyright (C) Microsoft Corporation
#
# SPDX-License-Identifier: BSD-2-Clause-Patent
##


import os
import sys
import argparse
import json
import logging
from edk2toolext.versioninfo.versioninfo_helper import PEObject, VERSIONINFOGenerator

TOOL_DESCRIPTION = """
Versioninfo Tool is a command-line tool to assist in generating VERSIONINFO
resource files for use with Resource Compiler. It takes a JSON representing
versioning info and produces a resource file that satisfies UEFI SBAT requirements
and is compatible with Resource Compiler.

An example call might look like:
%s -o /path/to/version.JSON /path/to/output
""" % (os.path.basename(sys.argv[0]),)


def get_cli_options(args=None):
    '''
    will parse the primary options from the command line. If provided, will take the options as
    an array in the first parameter
    '''
    parser = argparse.ArgumentParser(description=TOOL_DESCRIPTION, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument('input_file', type=str,
                        help='a filesystem path to a json/PE file to load')
    parser.add_argument('output_file', type=str,
                        help='a filesystem path to the output file. if file does not exist, entire directory path will be created. if file does exist, contents will be overwritten') # noqa

    command_group = parser.add_mutually_exclusive_group()
    command_group.add_argument('-e', '--encode', action='store_const', const='e', dest='mode',
                               help='(default) outsputs VERSIONINFO.rc of given json file')
    command_group.add_argument('-d', '--dump', action='store_const', dest='mode', const='d',
                               help='outputs json file of VERSIONINFO given PE file')
    parser.set_defaults(mode='e')
    return parser.parse_args(args=args)


def service_request(args):
    '''given parsed args, executes versioninfo_tool'''
    logging.getLogger().addHandler(logging.StreamHandler())
    if not os.path.isfile(args.input_file):
        logging.error("Could not find " + args.input_file)
        sys.exit(1)

    if args.mode == 'd':
        pe = PEObject(args.input_file)
        generated_dict = pe.get_version_dict()
        if generated_dict:
            with open(args.output_file, "w") as out:
                json.dump(generated_dict, out)
        else:
            sys.exit(1)
    else:
        if not VERSIONINFOGenerator(args.input_file).write(args.output_file):
            sys.exit(1)


def main():
    service_request(get_cli_options())


if __name__ == '__main__':
    main()
