# @file signtool_signer.py
# This module contains the abstracted signing interface for Windows Signtool.
# This interface abstraction takes in the signature_options and signer_options
# dictionaries that are used by capsule_tool and capsule_helper.
#
# Will attempt to locate a valid installation of Windows Signtool using the
# utility_functions provided by edk2toollib.
#
##
# Copyright (C) Microsoft Corporation
#
# SPDX-License-Identifier: BSD-2-Clause-Patent
##


import os
import tempfile
import warnings

from edk2toollib.windows import locate_tools
from edk2toollib.utility_functions import RunCmd

GLOBAL_SIGNTOOL_PATH = None
SUPPORTED_SIGNATURE_TYPE_OPTIONS = {
    'pkcs7': {'detachedSignedData', 'embedded'}
}


def get_signtool_path():
    '''
    helper function to locate a valid installation of Windows Signtool. Will
    attempt to reuse a previously located version, since this call can be
    lengthy
    '''
    global GLOBAL_SIGNTOOL_PATH

    if GLOBAL_SIGNTOOL_PATH is None:
        GLOBAL_SIGNTOOL_PATH = locate_tools.FindToolInWinSdk('signtool.exe')

    return GLOBAL_SIGNTOOL_PATH


def sign(data: bytes, signature_options: dict, signer_options: dict) -> bytes:
    '''
    primary signing interface. Takes n the signature_options and signer_options
    dictionaries that are used by capsule_tool and capsule_helper
    '''

    # NOTE: Currently, we only support the necessary options for capsules & Windows Firmware Policies

    # The following _if_ clause handles the deprecated signature_option 'sign_alg' for backwards compatibility
    # when the deprecated option is supplied, this code adds the new, required options based on prior code behavior
    if 'sign_alg' in signature_options:
        warnings.warn('Signature_option "sign_alg" is deprecated, use "type"', DeprecationWarning)
        if signature_options['sign_alg'] == 'pkcs12':
            # map legacy behavior to new options and backwards-compatible values
            signature_options['type'] = 'pkcs7'
            signature_options['type_options'] = {'detachedSignedData'}
            signature_options['encoding'] = 'DER'
            signer_options['key_file_format'] = 'pkcs12'
        else:
            raise ValueError(f"Unsupported signature algorithm: {signature_options['sign_alg']}!")

    if signature_options['type'] != 'pkcs7':
        raise ValueError(f"Unsupported signature type: {signature_options['type']}!")
    for opt in signature_options['type_options']:
        if opt not in SUPPORTED_SIGNATURE_TYPE_OPTIONS[signature_options['type']]:
            raise ValueError(f"Unsupported type option: {opt}!  Ensure you have provied a set")
    if 'embedded' in signature_options['type_options']:
        if 'detachedSignedData' in signature_options['type_options']:
            raise ValueError("type_options 'detachedSignedData' and 'embedded' are mutually exclusive")
    if signature_options['encoding'] != 'DER':
        raise ValueError(f"Unsupported signature encoding: {signature_options['type']}!")
    if signature_options['hash_alg'] != 'sha256':
        raise ValueError(f"Unsupported hashing algorithm: {signature_options['hash_alg']}!")
    if 'key_file' not in signer_options:
        raise ValueError("Must supply a key_file in signer_options for Signtool!")
    if signer_options['key_file_format'] != 'pkcs12':
        raise ValueError(f"Unsupported key file format: {signer_options['key_file_format']}!")

    # Set up a temp directory to hold input and output files.
    temp_folder = tempfile.mkdtemp()
    in_file_path = os.path.join(temp_folder, "data_to_sign.bin")

    # Create the input file for Signtool.
    in_file = open(in_file_path, 'wb')
    in_file.write(data)
    in_file.close()

    # Start building the parameters for the call.
    signtool_params = ['sign']
    signtool_params += ['/fd', signature_options['hash_alg']]
    if 'detachedSignedData' in signature_options['type_options']:
        signtool_params += ['/p7ce', 'DetachedSignedData']
    elif 'embedded' in signature_options['type_options']:
        signtool_params += ['/p7ce', 'Embedded']
    else:
        raise ValueError("For pkcs7, type_options must include either embedded or detachedSignedData")
    signtool_params += ['/p7', f'"{temp_folder}"']
    signtool_params += ['/f', f"\"{signer_options['key_file']}\""]
    if 'oid' in signer_options:
        signtool_params += ['/p7co', signer_options['oid']]
    if 'eku' in signer_options:
        signtool_params += ['/u', signer_options['eku']]
    if 'key_pass' in signer_options:
        signtool_params += ['/p', signer_options['key_pass']]
    # Add basic options.
    signtool_params += ['/debug', '/v', f'"{in_file_path}"']

    # Make the call to Signtool.
    ret = RunCmd(get_signtool_path(), " ".join(signtool_params))
    if ret != 0:
        raise RuntimeError(f"Signtool.exe returned with error: {ret}!")

    # Load the data from the output file and return it.
    out_file_path = os.path.join(temp_folder, "data_to_sign.bin.p7")
    out_file = open(out_file_path, 'rb')
    out_data = out_file.read()
    out_file.close()

    return out_data


def sign_in_place(sign_file_path, signature_options, signer_options):
    '''
    alternate module-specific signing interface to support particular signatures associated
    with Windows capsule files (e.g. CAT files). Takes n the signature_options and signer_options
    dictionaries that are used by capsule_tool and capsule_helper
    '''
    # NOTE: Currently, we only support the necessary algorithms for capsules.
    if signature_options['sign_alg'] != 'pkcs12':
        raise ValueError(f"Unsupported signature algorithm: {signature_options['sign_alg']}!")
    if signature_options['hash_alg'] != 'sha256':
        raise ValueError(f"Unsupported hashing algorithm: {signature_options['hash_alg']}!")
    if 'key_file' not in signer_options:
        raise ValueError("Must supply a key_file in signer_options for Signtool!")

    # Start building the parameters for the call.
    signtool_params = ['sign', '/a']
    signtool_params += ['/fd', signature_options['hash_alg']]
    signtool_params += ['/f', f"\"{signer_options['key_file']}\""]
    # if 'oid' in signer_options:
    #     signtool_params += ['/p7co', signer_options['oid']]
    # if 'eku' in signer_options:
    #     signtool_params += ['/u', signer_options['eku']]
    if 'key_pass' in signer_options:
        signtool_params += ['/p', signer_options['key_pass']]
    # Add basic options.
    signtool_params += ['/debug', '/v', f'"{sign_file_path}"']

    # Make the call to Signtool.
    ret = RunCmd(get_signtool_path(), " ".join(signtool_params))
    if ret != 0:
        raise RuntimeError(f"Signtool.exe returned with error: {ret}!")
