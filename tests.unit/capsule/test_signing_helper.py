## @file signing_helper_test.py
# This unittest module contains test cases for the signing_helper module.
#
##
# Copyright (C) Microsoft Corporation
#
# SPDX-License-Identifier: BSD-2-Clause-Patent
##


import os
import unittest

from edk2toolext.capsule import signing_helper
from edk2toolext.capsule import pyopenssl_signer


class SignerLocationTests(unittest.TestCase):
    def test_should_be_able_to_fetch_a_builtin_signer_module(self):
        py_signer = signing_helper.get_signer(signing_helper.PYOPENSSL_SIGNER)
        self.assertTrue(hasattr(py_signer, 'sign'))

        signtoolsigner = signing_helper.get_signer(signing_helper.SIGNTOOL_SIGNER)
        self.assertTrue(hasattr(signtoolsigner, 'sign'))

    def test_should_be_able_to_pass_a_signing_module(self):
        py_signer = signing_helper.get_signer(
            signing_helper.PYPATH_MODULE_SIGNER,
            'edk2toolext.capsule.pyopenssl_signer'
        )
        self.assertTrue(hasattr(py_signer, 'sign'))

    def test_should_be_able_to_fetch_a_user_provided_signer_module(self):
        py_signer_path = pyopenssl_signer.__file__
        self.assertTrue(os.path.isfile(py_signer_path))
        py_signer = signing_helper.get_signer(signing_helper.LOCAL_MODULE_SIGNER, py_signer_path)
        self.assertTrue(hasattr(py_signer, 'sign'))

# NOTE: These tests may not run on non-Windows or without the WDK installed.
# class SigntoolSignerModuleTest(unittest.TestCase):
#     def test_module_should_be_able_to_locate_signtool(self):
#         signtoolsigner = signing_helper.get_signer(signing_helper.SIGNTOOL_SIGNER)
#         self.assertTrue(os.path.isfile(signtoolsigner.get_signtool_path()))
