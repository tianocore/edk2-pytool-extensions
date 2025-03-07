## @file capsule_helper_test.py
# This unittest module contains test cases for the capsule_helper module.
#
##
# Copyright (C) Microsoft Corporation
#
# SPDX-License-Identifier: BSD-2-Clause-Patent
##
"""Tests for the capsule_helper module."""

import os
import tempfile
import unittest
import uuid

from edk2toolext.capsule import capsule_helper
from edk2toollib.uefi.fmp_capsule_header import FmpCapsuleHeaderClass, FmpCapsuleImageHeaderClass
from edk2toollib.uefi.uefi_capsule_header import UefiCapsuleHeaderClass

DUMMY_OPTIONS = {
    "capsule": {
        "fw_version": "0xDEADBEEF",
        "lsv_version": "0xFEEDF00D",
        "esrt_guid": "00112233-4455-6677-8899-aabbccddeeff",
        "fw_name": "TEST_FW",
        "fw_version_string": "1.2.3",  # deliberately use 3-part version to exercise version normalization.
        "provider_name": "TESTER",
        "fw_description": "TEST FW",
        "fw_integrity_file": "IntegrityFile.bin",
    },
    "signer": {"option2": "value2", "option_not": "orig_value"},
}
DUMMY_OPTIONS_FILE_NAME = "dummy_options_file"
DUMMY_PAYLOAD_FILE_NAME = "dummy_payload"


class CapsuleSignerTest(unittest.TestCase):
    """Tests for the capsule_helper module and CLI routines."""

    @classmethod
    def setUpClass(cls) -> None:
        """Set up the test class."""
        # We'll use the one-time setup to create
        # any temporary test files we'll need.
        cls.temp_dir = tempfile.mkdtemp()
        cls.dummy_payload = os.path.join(cls.temp_dir, DUMMY_PAYLOAD_FILE_NAME + ".bin")

        with open(cls.dummy_payload, "wb") as dummy_file:
            dummy_file.write(b"DEADBEEF")

    def test_should_pass_wrapped_blob_to_signing_module(self) -> None:
        """Test that the payload is passed to the signing module."""
        dummy_payload = b"This_Is_My_Sample_Payload,ThereAreManyLikeIt;This One Is Mine"

        class DummySigner(object):
            @classmethod
            def sign(cls, data: int, signature_options: dict, signer_options: dict) -> None:
                """Dummy signer function."""
                self.assertTrue(dummy_payload in data)

        capsule_helper.build_capsule(dummy_payload, DUMMY_OPTIONS["capsule"], DummySigner, DUMMY_OPTIONS["signer"])

    def test_should_pass_signer_options_to_signing_module(self) -> None:
        """Test that the signer options are passed to the signing module."""

        class DummySigner(object):
            @classmethod
            def sign(cls, data: int, signature_options: dict, signer_options: dict) -> None:
                """Dummy signer function."""
                self.assertEqual(signer_options, DUMMY_OPTIONS["signer"])

        capsule_helper.build_capsule(b"030303", DUMMY_OPTIONS["capsule"], DummySigner, DUMMY_OPTIONS["signer"])

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
    """Tests for the capsule_helper module and CLI routines."""

    @classmethod
    def setUpClass(cls) -> None:
        """Set up the test class."""
        # We'll use the one-time setup to create
        # any temporary test files we'll need.
        cls.temp_dir = tempfile.mkdtemp()
        cls.dummy_payload = os.path.join(cls.temp_dir, DUMMY_PAYLOAD_FILE_NAME + ".bin")

        with open(cls.dummy_payload, "wb") as dummy_file:
            dummy_file.write(b"DEADBEEF")

    def test_should_be_able_to_save_a_capsule(self) -> None:
        """Test that a capsule can be saved."""
        fmp_capsule_image_header = FmpCapsuleImageHeaderClass()
        fmp_capsule_image_header.UpdateImageTypeId = uuid.UUID(DUMMY_OPTIONS["capsule"]["esrt_guid"])
        fmp_capsule_image_header.UpdateImageIndex = 1

        fmp_capsule_header = FmpCapsuleHeaderClass()
        fmp_capsule_header.AddFmpCapsuleImageHeader(fmp_capsule_image_header)

        uefi_capsule_header = UefiCapsuleHeaderClass()
        uefi_capsule_header.FmpCapsuleHeader = fmp_capsule_header
        uefi_capsule_header.PersistAcrossReset = True
        uefi_capsule_header.InitiateReset = True

        capsule_file_path = capsule_helper.save_capsule(uefi_capsule_header, DUMMY_OPTIONS["capsule"], self.temp_dir)

        # Now read the data and check for the GUID.
        with open(capsule_file_path, "rb") as capsule_file:
            capsule_bytes = capsule_file.read()

        self.assertTrue(uuid.UUID(DUMMY_OPTIONS["capsule"]["esrt_guid"]).bytes_le in capsule_bytes)

    def test_should_be_able_to_generate_windows_files(self) -> None:
        """Test that the Windows files can be generated."""
        inf_file_path = capsule_helper.create_inf_file(DUMMY_OPTIONS["capsule"], self.temp_dir)
        self.assertTrue(os.path.isfile(inf_file_path))

    @unittest.skip("test fails in unittest environment. need to debug")
    def test_should_be_able_to_generate_cat(self) -> None:
        """Test that a CAT file can be generated."""
        cat_file_path = capsule_helper.create_cat_file(DUMMY_OPTIONS["capsule"], self.temp_dir)
        self.assertTrue(os.path.isfile(cat_file_path))


class MultiNodeFileGenerationTest(unittest.TestCase):
    """Tests for the capsule_helper module and CLI routines."""

    @staticmethod
    def buildPayload(esrt: str) -> UefiCapsuleHeaderClass:
        """Build a payload for testing."""
        fmp_capsule_image_header = FmpCapsuleImageHeaderClass()
        fmp_capsule_image_header.UpdateImageTypeId = uuid.UUID(esrt)
        fmp_capsule_image_header.UpdateImageIndex = 1

        fmp_capsule_header = FmpCapsuleHeaderClass()
        fmp_capsule_header.AddFmpCapsuleImageHeader(fmp_capsule_image_header)

        uefi_capsule_header = UefiCapsuleHeaderClass()
        uefi_capsule_header.FmpCapsuleHeader = fmp_capsule_header
        uefi_capsule_header.PersistAcrossReset = True
        uefi_capsule_header.InitiateReset = True

        return uefi_capsule_header

    @classmethod
    def setUpClass(cls) -> None:
        """Set up the test class."""
        cls.temp_dir = tempfile.mkdtemp()
        cls.temp_output_dir = tempfile.mkdtemp()

        cls.capsule = capsule_helper.Capsule(
            version_string="1.2.3",
            name="TEST_FW",
            provider_name="Tester",
        )

        cls.capsule.payloads.append(
            capsule_helper.CapsulePayload(
                cls.buildPayload("ea5c13fe-cac9-4fd7-ac30-37709bd668f2"),
                "test1.bin",
                uuid.UUID("ea5c13fe-cac9-4fd7-ac30-37709bd668f2"),
                0xDEADBEEF,
                "TEST FW",
            )
        )

        cls.capsule.payloads.append(
            capsule_helper.CapsulePayload(
                cls.buildPayload("43e67b4e-b2f1-4891-9ff2-a6acd9c74cbd"),
                "test2.bin",
                uuid.UUID("43e67b4e-b2f1-4891-9ff2-a6acd9c74cbd"),
                0xDEADBEEF,
                "TEST FW",
            )
        )

    def test_should_be_able_to_save_a_multi_node_capsule(self) -> None:
        """Test that a multi-node capsule can be saved."""
        capsule_file_path = capsule_helper.save_multinode_capsule(self.capsule, self.temp_output_dir)

        # make sure all the files we expect got created
        for payload in self.capsule.payloads:
            payload_file = os.path.join(capsule_file_path, payload.payload_filename)
            self.assertTrue(os.path.isfile(payload_file))
            with open(payload_file, "rb") as fh:
                capsule_bytes = fh.read()
            self.assertIn(payload.esrt_guid.bytes_le, capsule_bytes)

    def test_should_be_able_to_save_a_multi_node_capsule_with_integrity(self) -> None:
        """Test that a multi-node capsule with integrity data can be saved."""
        self.capsule.payloads[0].integrity_data = uuid.UUID("ea5c13fe-cac9-4fd7-ac30-37709bd668f2").bytes
        self.capsule.payloads[0].integrity_filename = "integrity1.bin"

        self.capsule.payloads[1].integrity_data = uuid.UUID("43e67b4e-b2f1-4891-9ff2-a6acd9c74cbd").bytes
        self.capsule.payloads[1].integrity_filename = "integrity2.bin"

        capsule_file_path = capsule_helper.save_multinode_capsule(self.capsule, self.temp_output_dir)

        for payload in self.capsule.payloads:
            payload_file = os.path.join(capsule_file_path, payload.payload_filename)
            self.assertTrue(os.path.isfile(payload_file))
            with open(payload_file, "rb") as fh:
                capsule_bytes = fh.read()
            self.assertIn(payload.esrt_guid.bytes_le, capsule_bytes)

            integrityFile = os.path.join(capsule_file_path, payload.integrity_filename)
            self.assertTrue(os.path.isfile(integrityFile))
            with open(integrityFile, "rb") as fh:
                integrity_bytes = fh.read()
            self.assertIn(payload.integrity_data, integrity_bytes)

        self.capsule.payloads[0].integrity_data = None
        self.capsule.payloads[0].integrity_filename = None

        self.capsule.payloads[1].integrity_data = None
        self.capsule.payloads[1].integrity_filename = None

    def test_should_be_able_to_generate_multi_node_inf_file(self) -> None:
        """Test that the INF file can be generated for a multi-node capsule."""
        inf_file_path = capsule_helper.create_multinode_inf_file(self.capsule, self.temp_output_dir)
        self.assertTrue(os.path.isfile(inf_file_path))


if __name__ == "__main__":
    unittest.main()
