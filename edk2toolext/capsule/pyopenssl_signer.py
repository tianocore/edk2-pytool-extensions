# @file pyopenssl_signer.py
# This module contains the abstracted signing interface for pyopenssl. This interface
# abstraction takes in the signature_options and signer_options dictionaries that are
# used by capsule_tool and capsule_helper.
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


import logging

from OpenSSL import crypto


def sign(data, signature_options, signer_options):
    '''
    primary signing interface. Takes n the signature_options and signer_options
    dictionaries that are used by capsule_tool and capsule_helper
    '''
    # NOTE: Currently, we only support the necessary algorithms for capsules.
    if signature_options['sign_alg'] != 'pkcs12':
        raise ValueError(f"Unsupported signature algorithm: {signature_options['sign_alg']}")
    if signature_options['hash_alg'] != 'sha256':
        raise ValueError(f"Unsupported hashing algorithm: {signature_options['hash_alg']}")

    logging.debug("Executing PKCS1 Signing")

    # If a key file is provided, use it for signing.
    if 'key_file' in signer_options:
        with open(signer_options['key_file'], 'rb') as key_file:
            signer_options['key_data'] = key_file.read()

    # TODO: Figure out OIDs.
    # TODO: Figure out EKUs.

    pkcs12 = crypto.load_pkcs12(signer_options['key_data'])
    return crypto.sign(pkcs12.get_privatekey(), data, signature_options['hash_alg'])
