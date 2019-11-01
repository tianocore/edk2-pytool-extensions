## @file capsule_helper_test.py
# This unittest module contains test cases for the capsule_helper module.
#
##
# Copyright (C) Microsoft Corporation
#
# SPDX-License-Identifier: BSD-2-Clause-Patent
##


import os
# import uuid
import unittest
import tempfile
# import logging

from edk2toollib.uefi.uefi_capsule_header import UefiCapsuleHeaderClass
from edk2toolext.capsule import capsule_helper, signing_helper

DUMMY_OPTIONS = {
    'capsule': {
        'fw_version': '0xDEADBEEF',
        'lsv_version': '0xFEEDF00D',
        'esrt_guid': '00112233-4455-6677-8899-aabbccddeeff'
    },
    'signer': {
        'option2': 'value2',
        'option_not': 'orig_value'
    }
}
DUMMY_OPTIONS_FILE_NAME = 'dummy_options_file'
DUMMY_PAYLOAD_FILE_NAME = 'dummy_payload'


class CapsuleSignerTest(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        # We'll use the one-time setup to create
        # any temporary test files we'll need.
        cls.temp_dir = tempfile.mkdtemp()
        cls.dummy_payload = os.path.join(cls.temp_dir, DUMMY_PAYLOAD_FILE_NAME + ".bin")

        with open(cls.dummy_payload, 'wb') as dummy_file:
            dummy_file.write(b'DEADBEEF')

    def test_should_pass_wrapped_blob_to_signing_module(self):
        dummy_payload = b'This_Is_My_Sample_Payload,ThereAreManyLikeIt;This One Is Mine'
        class DummySigner(object):
            @classmethod
            def sign(cls, data, signature_options, signer_options):
                self.assertTrue(dummy_payload in data)

        capsule_helper.build_capsule(dummy_payload, DUMMY_OPTIONS['capsule'], DummySigner, DUMMY_OPTIONS['signer'])

    def test_should_pass_signer_options_to_signing_module(self):
        class DummySigner(object):
            @classmethod
            def sign(cls, data, signature_options, signer_options):
                self.assertEqual(signer_options, DUMMY_OPTIONS['signer'])

        capsule_helper.build_capsule(b'030303', DUMMY_OPTIONS['capsule'], DummySigner, DUMMY_OPTIONS['signer'])

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
    #     wdk_signer = signing_helper.get_signer(signing_helper.SIGNTOOL_SIGNER)

    #     final_capsule = capsule_helper.build_capsule(capsule_data, capsule_options, wdk_signer, signer_options)

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
    #     wdk_signer = signing_helper.get_signer(signing_helper.SIGNTOOL_SIGNER)

    #     final_capsule = capsule_helper.build_capsule(capsule_data, capsule_options, wdk_signer, signer_options)

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

class FileGenerationTest(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        # We'll use the one-time setup to create
        # any temporary test files we'll need.
        cls.temp_dir = tempfile.mkdtemp()
        cls.dummy_payload = os.path.join(cls.temp_dir, DUMMY_PAYLOAD_FILE_NAME + ".bin")

        with open(cls.dummy_payload, 'wb') as dummy_file:
            dummy_file.write(b'DEADBEEF')

    def test_should_be_able_to_generate_inf(self):
        pass

    def test_should_be_able_to_generate_cat(self):
        pass


if __name__ == '__main__':
    unittest.main()
