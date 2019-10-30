## @file capsule_helper_test.py
# This unittest module contains test cases for the capsule_helper module.
# NOTE: Many of these tests require external collateral and as such are commented out for now.
#
##
# Copyright (C) Microsoft Corporation
#
# SPDX-License-Identifier: BSD-2-Clause-Patent
##


# import os
# import uuid
import unittest
# import logging
# from edk2toolext.capsule import capsule_helper, signing_helper

# TEST_CAPSULE_PATH_1 = "C:\\_uefi\\CapsuleDevTest\\UefiCapsule\\TestCapsulePayload.bin"
# TEST_CAPSULE_SIGNER_1 = "C:\\_uefi\\CapsuleDevTest\\TestCapsuleSigner.pfx"

# BUILD_CAPSULE_BINARY_PATH = "C:\\_uefi\\CapsuleDevTest\\RawCapsulePayload_Temp.bin"
# TEMP_CAPSULE_BINARY_PATH = "C:\\_uefi\\CapsuleDevTest\\DebugCapsuleOutput.bin"
# TEMP_CAPSULE_DIRECTORY_PATH = "C:\\_uefi\\CapsuleDevTest"


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

    # def test_should_be_able_to_generate_a_production_equivalent_capsule(self):
    #     with open(BUILD_CAPSULE_BINARY_PATH, 'rb') as data_file:
    #         capsule_data = data_file.read()

    #     capsule_options = {
    #         "esrt_guid": "80ddc468-57a0-43e5-9594-8ba2ce5c342e",
    #         "fw_version": "0x7fff000",
    #         "lsv_version": "0x1"
    #     }
    #     signer_options = {
    #         'key_file': TEST_CAPSULE_SIGNER_1,
    #         'eku': "1.3.6.1.4.1.311.76.9.1.36"
    #     }
    #     wdksigner = signing_helper.get_signer(signing_helper.SIGNTOOL_SIGNER)

    #     final_capsule = capsule_helper.build_capsule(capsule_data, capsule_options, wdksigner, signer_options)

    #     with open(TEST_CAPSULE_PATH_1, 'rb') as comparison_file:
    #         comparison_data = comparison_file.read()

    #     self.assertEqual(final_capsule.Encode(), comparison_data)

    # def test_should_be_able_to_update_the_guid_in_place(self):
    #     with open(BUILD_CAPSULE_BINARY_PATH, 'rb') as data_file:
    #         capsule_data = data_file.read()

    #     capsule_options = {
    #         "esrt_guid": "3624cd98-bdb6-461b-84a3-4f4853efc7e3",
    #         "fw_version": "0x7fff000",
    #         "lsv_version": "0x1"
    #     }
    #     signer_options = {
    #         'key_file': TEST_CAPSULE_SIGNER_1,
    #         'eku': "1.3.6.1.4.1.311.76.9.1.36"
    #     }
    #     wdksigner = signing_helper.get_signer(signing_helper.SIGNTOOL_SIGNER)

    #     final_capsule = capsule_helper.build_capsule(capsule_data, capsule_options, wdksigner, signer_options)

    #     with open(os.path.join(TEMP_CAPSULE_DIRECTORY_PATH, 'Capsule1.bin'), 'wb') as out_file:
    #         out_file.write(final_capsule.Encode())
    #         final_capsule.DumpInfo()

    #     fmp_capsule_image_header = final_capsule.FmpCapsuleHeader.GetFmpCapsuleImageHeader(0)
    #     fmp_capsule_image_header.UpdateImageTypeId = uuid.UUID('80ddc468-57a0-43e5-9594-8ba2ce5c342e')
    #     # WORKAROUND for library bug.
    #     final_capsule.FmpCapsuleHeader._ItemOffsetList = []

    #     with open(os.path.join(TEMP_CAPSULE_DIRECTORY_PATH, 'Capsule2.bin'), 'wb') as out_file:
    #         out_file.write(final_capsule.Encode())
    #         final_capsule.DumpInfo()

    #     self.assertFalse(True)


if __name__ == '__main__':
    unittest.main()
