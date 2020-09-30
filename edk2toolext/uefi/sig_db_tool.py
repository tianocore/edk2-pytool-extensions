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
Tool for inspecting UEFI Secure Boot databases
The input file is a concatenations of EFI_SIGNATURE_LISTS, as is read by calling GetVariable() on
    Secure Boot variables (i.e. PK, KEK, db, dbx)
The output can be standard human-readable or compact for easier diffing
It can dump the database as-is, or a sorted & deduplicated canonical form, or just duplicates found in it
"""

import argparse
from edk2toollib.uefi.authenticated_variables_structure_support import EfiSignatureDatabase


def main():
    """Parses command-line parameters using ArgumentParser, delegating to helper functions to fulfill the requests"""

    filenameHelp = 'Filename containing a UEFI Signature Database, \
        a concatenation of EFI_SIGNATURE_LISTs as read from GetVariable([PK, KEK, db, dbx])'

    sig_db_examples = '''
examples:

sig_db dump dbx_before.bin

sig_db --compact dump dbx_after.bin

sig_db --compact get_dupes dbx_with_dupes.bin

sig_db --compact get_canonical mixed_up_dbx.bin
'''

    parser = argparse.ArgumentParser(description='UEFI Signature database inspection tool',
                                     formatter_class=argparse.RawDescriptionHelpFormatter,
                                     epilog=sig_db_examples)

    parser.add_argument('--compact', action='store_true',
                        help='Compact, 1 line per data element output for easier diff-ing')

    subparsers = parser.add_subparsers(required=False, dest='action')

    parser_dump = subparsers.add_parser('dump', help='Print a UEFI Signature Database as-is in human-readable form')
    parser_dump.add_argument('file', type=str, help=filenameHelp)

    parser_get_dupes = subparsers.add_parser('get_dupes', help='Find duplicate signature entries in a UEFI Signature \
        Database. The test for duplication ignores SignatureOwner, testing only the SignatureData field. \
        Print them in UEFI Signature Database format, ordering is NOT maintained, output is NOT itself deduplicated')
    parser_get_dupes.add_argument('file', type=str, help='Filename of a UEFI Signature Database \
        (concatenation of EFI_SIGNATURE_LISTs as read from GetVariable() )')

    parser_get_canonical = subparsers.add_parser('get_canonical', help='Reduce a UEFI Signature Database to a \
        canonical (de-duplicated, sorted) form and print it')
    parser_get_canonical.add_argument('file', type=str,
                                      help='The name of the UEFI Signature Database file to get_canonical')

    options = parser.parse_args()

    if options.action is None:
        parser.print_help()
        return

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
