## @file signing_helper_test.py
# This unittest module contains test cases for the signing_helper module.
#
##
# Copyright (C) Microsoft Corporation
#
# SPDX-License-Identifier: BSD-2-Clause-Patent
##
"""Tests for the signing_helper module."""

import os
import unittest

from edk2toolext.capsule import pyopenssl_signer, signing_helper


class SignerLocationTests(unittest.TestCase):
    """Tests for the signing_helper module."""

    def test_should_be_able_to_fetch_a_builtin_signer_module(self) -> None:
        """Test that a built-in module can be loaded."""
        py_signer = signing_helper.get_signer(signing_helper.PYOPENSSL_SIGNER)
        self.assertTrue(hasattr(py_signer, "sign"))

        signtoolsigner = signing_helper.get_signer(signing_helper.SIGNTOOL_SIGNER)
        self.assertTrue(hasattr(signtoolsigner, "sign"))

    def test_should_be_able_to_pass_a_signing_module(self) -> None:
        """Test that a module can be passed directly."""
        py_signer = signing_helper.get_signer(
            signing_helper.PYPATH_MODULE_SIGNER, "edk2toolext.capsule.pyopenssl_signer"
        )
        self.assertTrue(hasattr(py_signer, "sign"))

    def test_should_be_able_to_fetch_a_user_provided_signer_module(self) -> None:
        """Test that a user-provided module can be loaded."""
        py_signer_path = pyopenssl_signer.__file__
        self.assertTrue(os.path.isfile(py_signer_path))
        py_signer = signing_helper.get_signer(signing_helper.LOCAL_MODULE_SIGNER, py_signer_path)
        self.assertTrue(hasattr(py_signer, "sign"))


# NOTE: These tests may not run on non-Windows or without the WDK installed.
# class SigntoolSignerModuleTest(unittest.TestCase):
#     def test_module_should_be_able_to_locate_signtool(self):
#         signtoolsigner = signing_helper.get_signer(signing_helper.SIGNTOOL_SIGNER)
#         self.assertTrue(os.path.isfile(signtoolsigner.get_signtool_path()))
