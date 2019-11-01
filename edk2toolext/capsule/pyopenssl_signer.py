# @file pyopenssl_signer.py
# This module contains the abstracted signing interface for pyopenssl. This interface
# abstraction takes in the signature_options and signer_options dictionaries that are
# used by capsule_tool and capsule_helper.
#
##
# Copyright (C) Microsoft Corporation
#
# SPDX-License-Identifier: BSD-2-Clause-Patent
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
    # TODO: Figure out EKU.

    pkcs12 = crypto.load_pkcs12(signer_options['key_data'])
    return crypto.sign(pkcs12.get_privatekey(), data, signature_options['hash_alg'])
