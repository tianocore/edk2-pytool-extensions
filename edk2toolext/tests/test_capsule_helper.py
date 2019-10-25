## @file test_capsule_signer.py
# This contains unit tests for the capsule_signer
##
# Copyright (c) Microsoft Corporation
#
# SPDX-License-Identifier: BSD-2-Clause-Patent
##
import os
import unittest
import logging
from edk2toolext.capsule import capsule_helper, signing_helper

TEST_CAPSULE_PATH_1 = "C:\\_uefi\\CapsuleDevTest\\UefiCapsule\\TestCapsulePayload.bin"
TEST_CAPSULE_SIGNER_1 = "C:\\_uefi\\CapsuleDevTest\\TestCapsuleSigner.pfx"

BUILD_CAPSULE_OPTIONS = {"esrt_guid": "80ddc468-57a0-43e5-9594-8ba2ce5c342e", "fw_version": "0x7fff000", "lsv_version": "0x1"}
BUILD_CAPSULE_BINARY_PATH = "C:\\_uefi\\CapsuleDevTest\\RawCapsulePayload_Temp.bin"
TEMP_CAPSULE_BINARY_PATH = "C:\\_uefi\\CapsuleDevTest\\DebugCapsuleOutput.bin"


class CapsuleSignerTest(unittest.TestCase):
    def test_should_pass_wrapped_blob_to_signing_module(self):
        pass

    # def test_should_pass_signer_options_to_signing_module(self):
    #     dummy_signer_options = {
    #         'option_a': 123123,
    #         'option_b': "blash"
    #     }
    #     signer_exec_check = False
    #     def dummy_signer_sign_function(data, signature_options, signer_options):
    #         self.assertEqual(signer_options, dummy_signer_options)
    #         signer_exec_check = True
    #     dummy_signer = Namespace(sign = dummy_signer_sign_function)

    #     capsule_helper.build_capsule(b'030303', {}, dummy_signer, dummy_signer_options)

    #     self.assertTrue(signer_exec_check)

    def test_should_be_able_to_generate_a_production_equivalent_capsule(self):
        with open(BUILD_CAPSULE_BINARY_PATH, 'rb') as data_file:
            capsule_data = data_file.read()

        capsule_options = {
            "esrt_guid": "80ddc468-57a0-43e5-9594-8ba2ce5c342e",
            "fw_version": "0x7fff000",
            "lsv_version": "0x1"
        }
        signer_options = {
            'key_file': TEST_CAPSULE_SIGNER_1,
            'eku': "1.3.6.1.4.1.311.76.9.1.36"
        }
        wdksigner = signing_helper.get_signer(signing_helper.SIGNTOOL_SIGNER)

        final_capsule = capsule_helper.build_capsule(capsule_data, capsule_options, wdksigner, signer_options)

        with open(TEST_CAPSULE_PATH_1, 'rb') as comparison_file:
            comparison_data = comparison_file.read()

        self.assertEqual(final_capsule, comparison_data)


# class SigningHelperTest(unittest.TestCase):
#     def test_should_be_able_to_fetch_a_builtin_signer_module(self):
#         pysigner = signing_helper.get_signer(signing_helper.PYOPENSSL_SIGNER)
#         self.assertTrue(hasattr(pysigner, 'sign'))

#         signtoolsigner = signing_helper.get_signer(signing_helper.SIGNTOOL_SIGNER)
#         self.assertTrue(hasattr(signtoolsigner, 'sign'))

#     def test_should_be_able_to_fetch_a_user_provided_signer_module(self):
#         self.assertTrue(False)

    # def test_should_be_able_to_pass_a_signing_module(self):
    #     self.assertTrue(False)

    # def test_signature_options_should_be_passed_to_signing_module(self):
    #     self.assertTrue(False)

    # def test_signer_options_should_be_passed_to_signing_module(self):
    #     self.assertTrue(False)

# NOTE: These tests may not run on non-Windows or without the WDK installed.
# class SigntoolSignerModuleTest(unittest.TestCase):
#     def test_module_should_be_able_to_locate_signtool(self):
#         signtoolsigner = signing_helper.get_signer(signing_helper.SIGNTOOL_SIGNER)
#         self.assertTrue(os.path.isfile(signtoolsigner.get_signtool_path()))

if __name__ == '__main__':
    unittest.main()
