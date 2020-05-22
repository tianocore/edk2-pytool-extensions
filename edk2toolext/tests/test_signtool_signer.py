# @file test_signtool_signer.py
# This contains unit tests for the signtool binary wrapper
##
# Copyright (c) Microsoft Corporation
#
# SPDX-License-Identifier: BSD-2-Clause-Patent
##
import unittest
import os
import sys
from edk2toolext.capsule import signtool_signer


class Test_pyopenssl_signer(unittest.TestCase):

    @unittest.skipUnless(sys.platform.startswith("win"), "requires Windows")
    def test_get_path(self):
        path = signtool_signer.get_signtool_path()
        self.assertTrue(os.path.exists(path))

    @unittest.skipUnless(sys.platform.startswith("win"), "requires Windows")
    def test_sign_with_bad_options(self):
        signature = {
            "type": "test"
        }
        signer = {}
        with self.assertRaises(ValueError):
            signtool_signer.sign(None, signature, signer)

    @unittest.skipUnless(sys.platform.startswith("win"), "requires Windows")
    def test_sign_with_good_options(self):
        signature = {
            "type": "pkcs7",
            "type_options": ["embedded"],
            "encoding": "DER",
            "hash_alg": "sha256"
        }
        signer = {
            "key_file": "file.txt",
            "key_file_format": "pkcs12"
        }
        with self.assertRaises(RuntimeError):
            signtool_signer.sign(b"data", signature, signer)

    @unittest.skipUnless(sys.platform.startswith("win"), "requires Windows")
    def test_sign_with_embed_type_and_detached_signdata(self):
        signature = {
            "type": "pkcs7",
            "type_options": ["embedded", "detachedSignedData"]
        }
        signer = {}
        with self.assertRaises(ValueError):
            signtool_signer.sign(b"data", signature, signer)
