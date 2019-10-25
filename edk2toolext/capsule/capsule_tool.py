import os
import sys
import argparse

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

    return parser.parse_args(args=args)


def load_options_file(filepath):
    return {}


def update_options(file_options, capsule_options, signer_options):
    return file_options


def main():
    args = get_cli_options()
    print(args)
