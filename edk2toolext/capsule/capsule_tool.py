import os
import sys
import argparse
import copy
import yaml

from edk2toolext.capsule import signing_helper

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
    signer_group.add_argument('--local_signer', dest='signer_path')
    signer_group.add_argument('--module_signer', dest='signer_pypath')

    parser.add_argument('-dc', action='append', dest='capsule_options', type=str, default=[])
    parser.add_argument('-ds', action='append', dest='signer_options', type=str, default=[])

    parser.add_argument('-o', dest='options_file', type=argparse.FileType('r'))

    return parser.parse_args(args=args)


def load_options_file(in_file):
    if not hasattr(in_file, 'read'):
        return None

    return yaml.safe_load(in_file)


def update_options(file_options, capsule_options, signer_options):
    if file_options is not None:
        updated_options = copy.copy(file_options)
    else:
        updated_options = {}

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
    print(args)
