# @file test_repo_resolver.py
# This contains unit tests for repo resolver
#
##
# Copyright (c) Microsoft Corporation
#
# SPDX-License-Identifier: BSD-2-Clause-Patent
##

import os
import unittest
import json
import tempfile

from edk2toolext.windows.secureboot.secureboot_audit import (
    generate_dbx_report,
    filter_revocation_list_by_arch,
    convert_uefi_org_revocation_file_to_dict,
    write_xlsx_file,
    write_json_file,
)

# Setup the test directory path
TEST_DATA_PARENT_DIRECTORY = os.path.join(
    os.path.dirname(os.path.abspath(__file__)),  # Test folder is relative to the test
    "testdata",
    "secureboot_audit",
)
TEST_HASH = "80B4D96931BF0D02FD91A61E19D14F1DA452E66DB2408CA8604D411F92659F0A"


class TestSecureBootReport(unittest.TestCase):
    def test_parse_dbx(self):
        """Test that we can parse the dbx file"""
        dbx_file = os.path.join(TEST_DATA_PARENT_DIRECTORY, "dbx.bin")
        revocations_file = os.path.join(TEST_DATA_PARENT_DIRECTORY, "uefi_org_revocations.json")

        with open(revocations_file, "rb") as rev_fs:
            revocations = json.load(rev_fs)

            with open(dbx_file, "rb") as dbx_fs:
                report = generate_dbx_report(dbx_fs, revocations)
                self.assertEqual(len(report), 3)

                self.assertEqual("identified" in report, True)
                self.assertEqual("missing_protections" in report, True)
                self.assertEqual("not_found" in report, True)

                self.assertEqual(len(report["identified"]["dict"]), 183)
                self.assertEqual(len(report["missing_protections"]["dict"]), 54)
                self.assertEqual(len(report["not_found"]["list"]), 84)

                revocation = report["identified"]["dict"][TEST_HASH]
                self.assertEqual(revocation["authority"], "Microsoft Corporation UEFI CA 2011")
                self.assertEqual(revocation["arch"], "x86_64")

    def test_filter_list_by_arch(self):
        """Test that we can filter the revocation list by architecture"""
        revocations_file = os.path.join(TEST_DATA_PARENT_DIRECTORY, "uefi_org_revocations.json")

        with open(revocations_file, "rb") as rev_fs:
            revocations = json.load(rev_fs)
            filtered_revocations = filter_revocation_list_by_arch(revocations, "x86_64")

            for rev in filtered_revocations:
                self.assertEqual(filtered_revocations[rev]["arch"], "x86_64")

            filtered_revocations = filter_revocation_list_by_arch(revocations, "x86")

            for rev in filtered_revocations:
                self.assertEqual(filtered_revocations[rev]["arch"], "x86")

            filtered_revocations = filter_revocation_list_by_arch(revocations, "arm")

            for rev in filtered_revocations:
                self.assertEqual(filtered_revocations[rev]["arch"], "arm")

            filtered_revocations = filter_revocation_list_by_arch(revocations, "arm64")

            for rev in filtered_revocations:
                self.assertEqual(filtered_revocations[rev]["arch"], "arm64")

    def test_convert_uefi_org_revocation_file_to_dict1(self):
        """Test that we can convert the uefi.org revocation file to a dict"""
        xlsx_file = os.path.join(TEST_DATA_PARENT_DIRECTORY, "dbx_info_2020_2023_uefiorg_v3.xlsx")

        revocations = convert_uefi_org_revocation_file_to_dict(xlsx_file)

        revocations_file = os.path.join(TEST_DATA_PARENT_DIRECTORY, "uefi_org_revocations.json")

        with open(revocations_file, "rb") as rev_fs:
            expected_revocations = json.load(rev_fs)

            self.assertEqual(revocations, expected_revocations)

    def test_convert_uefi_org_revocation_file_to_dict2(self):
        """Test that we can convert the uefi.org revocation file to a dict"""
        csv_file = os.path.join(TEST_DATA_PARENT_DIRECTORY, "dbx_info_2020_2023_uefiorg_v3.csv")

        revocations = convert_uefi_org_revocation_file_to_dict(csv_file)

        with open("uefi_org_revocations2.json", "w") as rev_fs:
            json.dump(revocations, rev_fs)

        revocations_file = os.path.join(TEST_DATA_PARENT_DIRECTORY, "uefi_org_revocations.json")

        with open(revocations_file, "rb") as rev_fs:
            expected_revocations = json.load(rev_fs)

            self.assertEqual(revocations, expected_revocations)

    def test_write_xlsx_file(self):
        """Test that we can write a xlsx file"""
        dbx_report_file = os.path.join(TEST_DATA_PARENT_DIRECTORY, "dbx_report.json")

        with open(dbx_report_file, "rb") as dbx_fs:
            dbx_report = json.load(dbx_fs)

            with tempfile.TemporaryDirectory() as td:
                test_file = os.path.join(td, "test.xlsx")
                write_xlsx_file(dbx_report, test_file)

                self.assertEqual(os.path.exists(test_file), True)

    def test_write_json_file(self):
        """Test that we can write a json file"""
        dbx_report_file = os.path.join(TEST_DATA_PARENT_DIRECTORY, "dbx_report.json")

        with open(dbx_report_file, "rb") as dbx_fs:
            dbx_report = json.load(dbx_fs)

            with tempfile.TemporaryDirectory() as td:
                test_file = os.path.join(td, "test.json")
                write_json_file(dbx_report, test_file)

                self.assertEqual(os.path.exists(test_file), True)

                with open(test_file, "rb") as test_fs:
                    test_report = json.load(test_fs)

                    self.assertEqual(test_report, dbx_report)


if __name__ == "__main__":
    unittest.main()
