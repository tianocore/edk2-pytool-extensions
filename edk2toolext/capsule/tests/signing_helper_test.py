import os
import pytest
import unittest
import logging

from edk2toolext.capsule import signing_helper

class SignerLocationTests(unittest.TestCase):
    def test_should_be_able_to_fetch_a_builtin_signer_module(self):
        pysigner = signing_helper.get_signer(signing_helper.PYOPENSSL_SIGNER)
        self.assertTrue(hasattr(pysigner, 'sign'))

        signtoolsigner = signing_helper.get_signer(signing_helper.SIGNTOOL_SIGNER)
        self.assertTrue(hasattr(signtoolsigner, 'sign'))

    def test_should_be_able_to_pass_a_signing_module(self):
        pysigner = signing_helper.get_signer(signing_helper.PYPATH_MODULE_SIGNER, 'edk2toolext.capsule.pyopenssl_signer')
        self.assertTrue(hasattr(pysigner, 'sign'))

    def test_should_be_able_to_fetch_a_user_provided_signer_module(self):
        test_script_path = os.path.dirname(os.path.abspath(__file__))
        pysigner_path = os.path.join(os.path.dirname(test_script_path), 'pyopenssl_signer.py')
        self.assertTrue(os.path.isfile(pysigner_path))
        pysigner = signing_helper.get_signer(signing_helper.LOCAL_MODULE_SIGNER, pysigner_path)
        self.assertTrue(hasattr(pysigner, 'sign'))

# NOTE: These tests may not run on non-Windows or without the WDK installed.
# class SigntoolSignerModuleTest(unittest.TestCase):
#     def test_module_should_be_able_to_locate_signtool(self):
#         signtoolsigner = signing_helper.get_signer(signing_helper.SIGNTOOL_SIGNER)
#         self.assertTrue(os.path.isfile(signtoolsigner.get_signtool_path()))
