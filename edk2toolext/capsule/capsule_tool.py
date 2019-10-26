import os
import sys
import argparse
import copy
import yaml
import logging

from edk2toolext.capsule import signing_helper, capsule_helper

TOOL_DESCRIPTION = """
EDK Capsule Tool is a command-line tool to assist
with the production of UEFI capsules. It takes in a payload
and any number of options to produce a properly constructed
capsule that can be parsed by the EDK2 FMP Capsule infrastructure.
"""

def get_cli_options(args=None):
    parser = argparse.ArgumentParser(description=TOOL_DESCRIPTION)

    # Add the group for the signer specifier.
    signer_group = parser.add_mutually_exclusive_group(required=True)
    signer_group.add_argument('--builtin_signer', choices=[signing_helper.PYOPENSSL_SIGNER, signing_helper.SIGNTOOL_SIGNER])
    signer_group.add_argument('--local_signer', help='a filesystem path to a python module that can be loaded as the active signer')
    signer_group.add_argument('--module_signer', help='a python dot-path to a signer module that can be loaded from the current pypath')

    options_help = 'add an option to the corresponding set. format is <option_name>=<option_value>'
    parser.add_argument('-dc', action='append', dest='capsule_options', type=str, default=[], help=options_help)
    parser.add_argument('-ds', action='append', dest='signer_options', type=str, default=[], help=options_help)

    parser.add_argument('-o', dest='options_file', type=argparse.FileType('r'), help='a filesystem path to a json/yaml file to load with default options. will be overriden by any options parameters')

    parser.add_argument('capsule_payload', type=argparse.FileType('rb'), help='a filesystem path to the binary payload for the capsule')
    parser.add_argument('output_dir', help='a filesystem path to the directory to save output files. if directory does not exist, entire directory path will be created')

    return parser.parse_args(args=args)


def load_options_file(in_file):
    if not hasattr(in_file, 'read'):
        return None

    return yaml.safe_load(in_file)


def update_options(file_options, capsule_options, signer_options):
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

    # TODO: Determine what kind of signer module to load and load it.
    # TODO: Figure out how to deal with the output files like INF and CAT.
    # Next, we're gonna need a signer.
    if args.builtin_signer is not None:
        signer = signing_helper.get_signer(args.builtin_signer)
    elif args.module_signer is not None:
        signer = signing_helper.get_signer(signing_helper.PYPATH_MODULE_SIGNER, args.module_signer)
    elif args.local_signer is not None:
        signer = signing_helper.get_signer(signing_helper.LOCAL_MODULE_SIGNER, args.local_signer)

    # Now, build the capsule.
    uefi_capsule_header = capsule_helper.build_capsule(args.capsule_payload.read(), final_options['capsule'], signer, final_options['signer'])

    # Save the capsule.
    capsule_helper.save_capsule(uefi_capsule_header, final_options['capsule'], args.output_dir)

    # TODO: Figure out how to deal with the output files like INF and CAT.
    # TODO: Save the final options for provenance?
