# @file test_pyopenssl_signer.py
# This contains unit tests for the pyopenssl binary wrapper
##
# Copyright (c) Microsoft Corporation
#
# SPDX-License-Identifier: BSD-2-Clause-Patent
##
import unittest
from edk2toolext.capsule import pyopenssl_signer
import os


class Test_pyopenssl_signer(unittest.TestCase):

    def test_empty(self):
        with self.assertRaises((KeyError, ValueError)):
            pyopenssl_signer.sign(None, {}, {})

    def test_proper_options_good_key(self):
        # we're going to assume that we're
        signer = {
            'key_file_format': 'pkcs12',
            'key_file': os.path.join(os.path.dirname(__file__), "testdata", "test_cert.pfx")
        }
        signature = {
            'type': 'bare',
            'encoding': 'binary',
            'hash_alg': 'sha256',

        }
        data = "Data for testing signer".encode()
        pyopenssl_signer.sign(data, signature, signer)

    def test_proper_options_bad_key(self):
        # we're going to assume that we're
        with self.assertRaises(ValueError):
            signer = {
                'key_file_format': 'pkcs12',
                'key_data': "hello there"
            }
            signature = {
                'type': 'bare',
                'encoding': 'binary',
                'hash_alg': 'sha256',

            }
            pyopenssl_signer.sign(None, signature, signer)

    def test_invalid_type(self):
        # we're going to assume that we're
        with self.assertRaises(ValueError):
            signature = {
                'type': 'bad_type',
            }
            pyopenssl_signer.sign(None, signature, {})

    def test_invalid_type_options(self):
        # we're going to assume that we're
        with self.assertRaises(ValueError):
            signature = {
                'type': 'bare',
                'type_options': 'not allowed'
            }
            pyopenssl_signer.sign(None, signature, {})
