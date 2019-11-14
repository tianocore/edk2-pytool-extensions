# @file capsule_tool.py
# This module contains the CLI interface for easily creating EDK FMP UEFI capsules
# from payload files.
#
##
# Copyright (C) Microsoft Corporation
#
# SPDX-License-Identifier: BSD-2-Clause-Patent
##


import os
import sys
import argparse
import copy
import yaml
import logging

from edk2toolext.capsule import signing_helper, capsule_helper

TOOL_DESCRIPTION = """
EDK Capsule Tool is a command-line tool to assist with the production of UEFI
capsules. It takes in a payload and any number of options to produce a
properly constructed capsule that can be parsed by the EDK2 FMP Capsule
infrastructure.

An example call might look like:
%s -o /path/to/config.yaml -ds key_file="/other/signer/key/file.pfx"
    /path/to/payload.bin /path/to/output
""" % (os.path.basename(sys.argv[0]),)


def get_cli_options(args=None):
    '''
    will parse the primary options from the command line. If provided, will take the options as
    an array in the first parameter
    '''
    parser = argparse.ArgumentParser(description=TOOL_DESCRIPTION, formatter_class=argparse.RawDescriptionHelpFormatter)

    # Add the group for the signer specifier.
    # NOTE: At least one signer type is required!
    signer_group = parser.add_mutually_exclusive_group(required=True)
    signer_group.add_argument(
        '--builtin_signer', choices=[signing_helper.PYOPENSSL_SIGNER, signing_helper.SIGNTOOL_SIGNER])
    signer_group.add_argument(
        '--local_signer', help='a filesystem path to a python module that can be loaded as the active signer')
    signer_group.add_argument(
        '--module_signer', help='a python dot-path to a signer module that can be loaded from the current pypath')

    options_help = 'add an option to the corresponding set. format is <option_name>=<option_value>'
    parser.add_argument('-dc', action='append', dest='capsule_options', type=str, default=[], help=options_help)
    parser.add_argument('-ds', action='append', dest='signer_options', type=str, default=[], help=options_help)

    parser.add_argument('-o', dest='options_file', type=argparse.FileType('r'),
                        help='a filesystem path to a json/yaml file to load with default options. will be overriden by any options parameters') # noqa
    parser.add_argument('-f', dest='save_final_options', default=False, action='store_true',
                        help='optional flag to request that final tool options be saved in a file in the output directory')                     # noqa

    parser.add_argument('capsule_payload', type=argparse.FileType('rb'),
                        help='a filesystem path to the binary payload for the capsule')
    parser.add_argument('output_dir',
                        help='a filesystem path to the directory to save output files. if directory does not exist, entire directory path will be created. if directory does exist, contents will be updated based on the capsule_options') # noqa

    return parser.parse_args(args=args)


def load_options_file(in_file):
    '''
    takes in a string to a file path and loads it as a json-/yaml-encoded options
    file, returning the contents in a dictionary
    '''
    if not hasattr(in_file, 'read'):
        return None

    return yaml.safe_load(in_file)


def update_options(file_options, capsule_options, signer_options):
    '''
    takes in a pre-loaded options dictionary and walks add all corresponding options
    from the command line. Command line options will be organized by type (into capsule_options
    or signer_options) and in lists of strings that look like '<option_name>=<option_value>'
    '''
    if file_options is not None:
        updated_options = copy.copy(file_options)
    else:
        updated_options = {'capsule': {}, 'signer': {}}

    # Update all the capsule options.
    for option in capsule_options:
        (key, value) = option.split('=')
        updated_options['capsule'][key] = value

    # Update all the signer options.
    for option in signer_options:
        (key, value) = option.split('=')
        updated_options['signer'][key] = value

    return updated_options


def main():
    args = get_cli_options()
    final_options = update_options(load_options_file(args.options_file), args.capsule_options, args.signer_options)

    # Verify minimum capsule options.
    required_capsule_options = ('fw_name', 'fw_version', 'lsv_version', 'fw_version_string',
                                'provider_name', 'fw_description', 'esrt_guid')
    missing_capsule_options = tuple(option for option in required_capsule_options
                                    if option not in final_options['capsule'])
    if len(missing_capsule_options) > 0:
        logging.error("Missing required capsule options: " + ", ".join(missing_capsule_options) + "!")
        logging.error("Options MUST be provided in either the options file or on the command line.")
        sys.exit(1)

    # Next, we're gonna need a signer.
    if args.builtin_signer is not None:
        signer = signing_helper.get_signer(args.builtin_signer)
    elif args.module_signer is not None:
        signer = signing_helper.get_signer(signing_helper.PYPATH_MODULE_SIGNER, args.module_signer)
    elif args.local_signer is not None:
        signer = signing_helper.get_signer(signing_helper.LOCAL_MODULE_SIGNER, args.local_signer)

    # Now, build the capsule.
    uefi_capsule_header = capsule_helper.build_capsule(
        args.capsule_payload.read(),
        final_options['capsule'],
        signer,
        final_options['signer']
    )

    # Save the capsule.
    capsule_helper.save_capsule(uefi_capsule_header, final_options['capsule'], args.output_dir)

    # Build the INF file.
    capsule_helper.create_inf_file(final_options['capsule'], args.output_dir)

    # Build the CAT file.
    capsule_helper.create_cat_file(final_options['capsule'], args.output_dir)

    # If requested, save the final options for provenance.
    if args.save_final_options:
        final_options_file = os.path.join(args.output_dir, 'Final_Capsule_Options.yaml')
        with open(final_options_file, 'w') as options_file:
            yaml.dump(final_options, options_file, indent=2)


if __name__ == '__main__':
    main()
