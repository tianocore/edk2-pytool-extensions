# @file test_signtool_signer.py
# This contains unit tests for the signtool binary wrapper
##
# Copyright (c) Microsoft Corporation
#
# SPDX-License-Identifier: BSD-2-Clause-Patent
##
"""Unit test for the signtool_signer module."""

import os
import sys
import unittest

from edk2toolext.capsule import signtool_signer


class Test_signtool_signer(unittest.TestCase):
    """Unit test for the signtool_signer module."""

    @unittest.skipUnless(sys.platform.startswith("win"), "requires Windows")
    def test_get_path(self) -> None:
        """Test that the get_signtool_path function returns a valid path."""
        path = signtool_signer.get_signtool_path()
        self.assertTrue(os.path.exists(path))

    @unittest.skipUnless(sys.platform.startswith("win"), "requires Windows")
    def test_sign_with_bad_options(self) -> None:
        """Test that the sign function raises an error with bad options."""
        signature = {"type": "test"}
        signer = {}
        with self.assertRaises(ValueError):
            signtool_signer.sign(None, signature, signer)

    @unittest.skipUnless(sys.platform.startswith("win"), "requires Windows")
    def test_sign_with_good_options(self) -> None:
        """Test that the sign function works with good options."""
        signature = {"type": "pkcs7", "type_options": ["embedded"], "encoding": "DER", "hash_alg": "sha256"}
        signer = {"key_file": "file.txt", "key_file_format": "pkcs12"}
        with self.assertRaises(RuntimeError):
            signtool_signer.sign(b"data", signature, signer)

    @unittest.skipUnless(sys.platform.startswith("win"), "requires Windows")
    def test_sign_with_mutually_exclusive_options(self) -> None:
        """Test that mutually exclusive options raise an error."""
        signature = {"type": "pkcs7", "type_options": ["embedded", "detachedSignedData"]}
        signer = {}
        with self.assertRaises(ValueError):
            signtool_signer.sign(b"data", signature, signer)

        signature = {"type": "pkcs7", "type_options": ["pkcs7DetachedSignedData", "detachedSignedData"]}
        signer = {}
        with self.assertRaises(ValueError):
            signtool_signer.sign(b"data", signature, signer)

        signature = {"type": "pkcs7", "type_options": ["pkcs7DetachedSignedData", "embedded"]}
        signer = {}
        with self.assertRaises(ValueError):
            signtool_signer.sign(b"data", signature, signer)

        signature = {"type": "pkcs7", "type_options": ["detachedSignedData", "pkcs7DetachedSignedData", "embedded"]}
        signer = {}
        with self.assertRaises(ValueError):
            signtool_signer.sign(b"data", signature, signer)
