# @file signtool_signer.py
# This module contains the abstracted signing interface for Windows Signtool.
# This interface abstraction takes in the signature_options and signer_options
# dictionaries that are used by capsule_tool and capsule_helper.
#
# Will attempt to locate a valid instalation of Windows Signtool using the
# utility_functions provided by edk2toollib.
#
##
# Copyright (C) Microsoft Corporation
#
# All rights reserved.
# Redistribution and use in source and binary forms, with or without
# modification, are permitted provided that the following conditions are met:
# 1. Redistributions of source code must retain the above copyright notice,
# this list of conditions and the following disclaimer.
# 2. Redistributions in binary form must reproduce the above copyright notice,
# this list of conditions and the following disclaimer in the documentation
# and/or other materials provided with the distribution.
#
# THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS" AND
# ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED
# WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE DISCLAIMED.
# IN NO EVENT SHALL THE COPYRIGHT HOLDER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT,
# INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING,
# BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE,
# DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF
# LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE
# OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF
# ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
##


import os
import tempfile

from edk2toollib.windows import locate_tools
from edk2toollib.utility_functions import RunCmd

GLOBAL_SIGNTOOL_PATH = None


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


def sign(data, signature_options, signer_options):
    '''
    primary signing interface. Takes n the signature_options and signer_options
    dictionaries that are used by capsule_tool and capsule_helper
    '''
    # NOTE: Currently, we only support the necessary algorithms for capsules.
    if signature_options['sign_alg'] != 'pkcs12':
        raise ValueError(f"Unsupported signature algorithm: {signature_options['sign_alg']}!")
    if signature_options['hash_alg'] != 'sha256':
        raise ValueError(f"Unsupported hashing algorithm: {signature_options['hash_alg']}!")
    if 'key_file' not in signer_options:
        raise ValueError("Must supply a key_file in signer_options for Signtool!")

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
    signtool_params += ['/p7ce', 'DetachedSignedData']
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
