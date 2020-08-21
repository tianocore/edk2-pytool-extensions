# @file
#
# Command-line tool for inspecting UEFI Secure Boot databases
# Requires "pip install edk2-pytool-extensions"
#
# Copyright (c) Microsoft Corporation
#
# SPDX-License-Identifier: BSD-2-Clause-Patent
##

"""
Tool for inspecting UEFI Secure Boot databases (concatenations of EFI_SIGNATURE_LISTS)
The output can be standard human-readable or compact for easier diffing
It can dump the database as-is, or a sorted/deduped/canonical form, or just duplicates found in it
"""

import argparse
from edk2toollib.uefi.authenticated_variables_structure_support import EfiSignatureDatabase


def main():
    """Parses command-line parameters using ArgumentParser, delegating to helper functions to fulfill the requests"""
    parser = argparse.ArgumentParser(description='UEFI Signature database investigator')
    parser.add_argument('--compact', action='store_true', help='Select compact output for easier diff-ing')
    subparsers = parser.add_subparsers(required=True, dest='action')

    parser_dump = subparsers.add_parser('dump', help='Print a UEFI Signature Database in human-readible form "as-is"')

    parser_dump.add_argument('file', type=str, help='The name of the UEFI Signature Database file to dump')

    parser_get_dupes = subparsers.add_parser('get_dupes', help='Print duplicate signature entries found a UEFI"\
        " Signature Database')
    parser_get_dupes.add_argument('file', type=str, help='The name of the UEFI Signature Database file to get_dupes')

    parser_get_canonical = subparsers.add_parser('get_canonical', help='Reduce a UEFI Signature Database to its"\
        " canonical (de-duplicated, sorted) form and print it')
    parser_get_canonical.add_argument('file', type=str,
                                      help='The name of the UEFI Signature Database file to get_canonical')

    options = parser.parse_args()

    # print('Options: ', options)

    try:
        with open(options.file, 'rb') as f:
            esd = EfiSignatureDatabase(f)
            if (options.action == 'get_dupes'):
                esd = esd.GetDuplicates()
            elif (options.action == 'get_canonical'):
                esd = esd.GetCanonical()

            esd.Print(compact=options.compact)

    except FileNotFoundError:
        print('ERROR:  File not found: "{0}"'.format(options.file))


if __name__ == '__main__':
    main()
