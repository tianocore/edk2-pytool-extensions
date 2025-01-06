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
"""Abstracted signing interface for pyopenssl.

This interface abstraction takes in the signature_options and signer_options
dictionaries that are used by capsule_tool and capsule_helper.
"""

import logging
import warnings

from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.primitives.serialization import pkcs12


def sign(data: bytes, signature_options: dict, signer_options: dict) -> bytes:
    """Primary signing interface.

    Takes in the signature_options and signer_options
    dictionaries that are used by capsule_tool and capsule_helper.

    Args:
        data (bytes): data to write into the sign tool.
        signature_options (dict): dictionary containing signature options
        signer_options (dict): dictionary containing signer options

    Raises:
        (ValueError()): Unsupported signature or signer options
        (RuntimeError()): Signtool.exe returned with error

    NOTE: Currently, we only support the necessary algorithms for capsules.
    """
    # The following _if_ clause handles the deprecated signature_option 'sign_alg' for backwards compatibility
    # when the deprecated option is supplied, this code adds the new, required options based on prior code behavior
    if "sign_alg" in signature_options:
        warnings.warn('Signature_option "sign_alg" is deprecated, use "type"', DeprecationWarning)
        if signature_options["sign_alg"] == "pkcs12":
            # map legacy behavior to new options and backwards-compatible values
            signature_options["type"] = "bare"
            signature_options["encoding"] = "binary"
            signer_options["key_file_format"] = "pkcs12"
        else:
            raise ValueError(f"Unsupported signature algorithm: {signature_options['sign_alg']}!")

    """ signature type 'bare' is just a binary signed digest, no PEM headers/footers or ASN """
    if signature_options["type"] != "bare":
        raise ValueError(f"Unsupported signature type: {signature_options['type']}")
    if "type_options" in signature_options:
        raise ValueError("Signature type options not supported")
    if signature_options["encoding"] != "binary":
        raise ValueError(f"Unsupported signature encoding: {signature_options['encoding']}")
    if signer_options["key_file_format"] != "pkcs12":
        raise ValueError(f"Unsupported signer key file format: {signer_options['key_file_format']}")

    match signature_options["hash_alg"]:
        case "sha256":
            algorithm = hashes.SHA256()
        case hash_alg:
            raise ValueError(f"Unsupported hashing algorithm: {hash_alg}")

    logging.debug("Executing PKCS1 Signing")

    # If a key file is provided, use it for signing.
    if "key_file" in signer_options:
        with open(signer_options["key_file"], "rb") as key_file:
            signer_options["key_data"] = key_file.read()

    if not isinstance(signer_options["key_data"], bytes):
        signer_options["key_data"] = signer_options["key_data"].encode()

    password = None
    if "key_file_password" in signer_options:
        password = signer_options["key_file_password"]
        if not isinstance(password, bytes):
            password = password.encode()

    private_key, _, _ = pkcs12.load_key_and_certificates(signer_options["key_data"], password)

    if not private_key:
        raise ValueError("Failed to load private key from PKCS12 data")

    # TODO: Figure out OIDs.
    # TODO: Figure out EKU.

    return private_key.sign(data, padding.PKCS1v15(), algorithm)
