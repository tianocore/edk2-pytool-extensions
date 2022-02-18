# @file test_image_validation.py
# This contains unit tests for the image validation tool.
##
# Copyright (c) Microsoft Corporation
#
# SPDX-License-Identifier: BSD-2-Clause-Patent
##
import unittest
import logging
from edk2toolext.image_validation import Result, TestManager, TestSectionAlignment
from edk2toolext.image_validation import TestSubsystemValue, TestWriteExecuteFlags


class Section:
    def __init__(self, name, characteristics=None):
        self.Characteristics = characteristics
        self.Name = name


class OptionalHeader:
    def __init__(self, SectionAlignment=None, Subsystem=None):
        self.SectionAlignment = SectionAlignment
        self.Subsystem = Subsystem


class PE:
    def __init__(self, sections=None, optional_header=None):
        self.sections = sections
        self.OPTIONAL_HEADER = optional_header


# def subTest(self, msg=_subtest_msg_sentinel, **params):
class Test_image_validation(unittest.TestCase):

    def test_add_test(self):

        test_manager = TestManager()
        self.assertEqual(len(test_manager.tests), 0)
        test_manager.add_test(TestSectionAlignment())
        self.assertEqual(len(test_manager.tests), 1)

    def test_add_tests(self):
        test_manager = TestManager()
        self.assertEqual(len(test_manager.tests), 0)
        test_manager.add_tests([TestSectionAlignment(), TestSubsystemValue()])
        self.assertEqual(len(test_manager.tests), 2)

    def test_write_execute_flags_test(self):
        """
        TestWriteExecuteFlags follows the following logic:
        1. If test requirement is not specified, or equal to false, return Result.SKIP
        3. Return Result.PASS / Result.FAIL returned based on Characteristic value
        """
        TEST_PE0 = PE(sections=[
            Section("S1.1".encode("utf-8"), characteristics=0x80000000),
            Section("S1.2".encode("utf-8"), characteristics=0x20000000),
            Section("S1.3".encode("utf-8"), characteristics=0x00000000)])

        TEST_PE1 = PE(sections=[
            Section("S2.1".encode("utf-8"), characteristics=0xA0000000),
            Section("S2.2".encode("utf-8"), characteristics=0x20000000),
            Section("S2.3".encode("utf-8"), characteristics=0x00000000)])

        TEST_PE2 = PE(sections=[
            Section("S3.1".encode("utf-8"), characteristics=0x20000000),
            Section("S3.2".encode("utf-8"), characteristics=0x80000000),
            Section("S3.3".encode("utf-8"), characteristics=0xC0000000)])

        TEST_PE3 = PE(sections=[
            Section("S4.1".encode("utf-8"), characteristics=0xE0000000)])

        test_write_execute_flags = TestWriteExecuteFlags()
        tests = [(TEST_PE0, Result.PASS), (TEST_PE1, Result.FAIL), (TEST_PE2, Result.PASS), (TEST_PE3, Result.FAIL)]

        config_data0 = {
            "TARGET_REQUIREMENTS": {"DATA_CODE_SEPARATION": True}
        }
        for i in range(len(tests)):
            with self.subTest("test@config=True", i=i):
                pe, result = tests[i]
                self.assertEqual(test_write_execute_flags.execute(pe, config_data0), result)

        config_data1 = {
            "TARGET_REQUIREMENTS": {"DATA_CODE_SEPARATION": False}
        }
        for i in range(len(tests)):
            with self.subTest("test@config=False", i=i):
                pe, _ = tests[i]
                self.assertEqual(test_write_execute_flags.execute(pe, config_data1), Result.SKIP)

        config_data2 = {"TARGET_REQUIREMENTS": {}}
        for i in range(len(tests)):
            with self.subTest("test@config=False", i=i):
                pe, _ = tests[i]
                self.assertEqual(test_write_execute_flags.execute(pe, config_data2), Result.SKIP)

    def test_section_alignment_test(self):
        """
        TestSectionAlignment follows the following logic:
        1. If requirements are not specified, or is empty, return Result.SKIP
        2. If SectionAlignment is not present, or is 0, return Result.WARN
        3. Return Result.PASS / Result.FAIL returned based on alignment requirements
        """

        config_data0 = {
            "TARGET_REQUIREMENTS": {},
            "TARGET_INFO": {"MACHINE_TYPE": "", "PROFILE": {}}
        }
        config_data1 = {
            "TARGET_REQUIREMENTS": {"ALIGNMENT": []},
            "TARGET_INFO": {"MACHINE_TYPE": "", "PROFILE": {}}
        }
        config_data2 = {
            "TARGET_REQUIREMENTS": {"ALIGNMENT": [{"COMPARISON": ">=", "VALUE": 0}]},
            "TARGET_INFO": {"MACHINE_TYPE": "", "PROFILE": {}}
        }

        config_data3 = {
            "TARGET_REQUIREMENTS": {"ALIGNMENT": [{"COMPARISON": "==", "VALUE": 1}]},
            "TARGET_INFO": {"MACHINE_TYPE": "", "PROFILE": {}}
        }

        config_data4 = {
            "TARGET_REQUIREMENTS": {"ALIGNMENT": [
                {"COMPARISON": ">=", "VALUE": 0},
                {"COMPARISON": ">=", "VALUE": 64},
                {"COMPARISON": "<=", "VALUE": 8192}],
                "ALIGNMENT_LOGIC_SEP": "AND"},
            "TARGET_INFO": {}
        }

        config_data5 = {
            "TARGET_REQUIREMENTS": {"ALIGNMENT": [
                {"COMPARISON": ">=", "VALUE": 0},
                {"COMPARISON": ">=", "VALUE": 64},
                {"COMPARISON": "!=", "VALUE": 4096}],
                "ALIGNMENT_LOGIC_SEP": "AND"},
            "TARGET_INFO": {"MACHINE_TYPE": "", "PROFILE": {}}
        }

        TEST_PE0 = PE(optional_header=OptionalHeader(SectionAlignment=4096))
        test_section_alignment_test = TestSectionAlignment()
        tests0 = [(config_data0, Result.SKIP), (config_data1, Result.SKIP),
                  (config_data2, Result.PASS), (config_data3, Result.FAIL),
                  (config_data4, Result.PASS), (config_data5, Result.FAIL)]
        for i in range(len(tests0)):
            with self.subTest("test_section_alignment_test0", i=i):
                config, result = tests0[i]
                self.assertEqual(test_section_alignment_test.execute(TEST_PE0, config), result)

        TEST_PE1 = PE(optional_header=OptionalHeader(SectionAlignment=0))
        tests1 = [(config_data0, Result.SKIP), (config_data1, Result.SKIP),
                  (config_data2, Result.WARN), (config_data3, Result.WARN),
                  (config_data4, Result.WARN), (config_data5, Result.WARN)]

        for i in range(len(tests1)):
            with self.subTest("test_section_alignment_test1", i=i):
                config, result = tests1[i]
                self.assertEqual(test_section_alignment_test.execute(TEST_PE1, config), result)

        TEST_PE2 = PE(optional_header=None)
        for i in range(len(tests1)):
            with self.subTest("test_section_alignment_test2", i=i):
                config, result = tests1[i]
                self.assertEqual(test_section_alignment_test.execute(TEST_PE2, config), result)

    def test_section_alignment_test2(self):

        target_config0 = {
            "TARGET_REQUIREMENTS": {
                "ALIGNMENT": [
                    {"COMPARISON": ">=", "VALUE": 0},
                    {"COMPARISON": "<=", "VALUE": 8192}],
                "ALIGNMENT_LOGIC_SEP": "AND"},
            "TARGET_INFO": {"MACHINE_TYPE": "", "PROFILE": {}}
        }

        target_config1 = {
            "TARGET_REQUIREMENTS": {
                "ALIGNMENT": [
                    {"COMPARISON": "==", "VALUE": 0},
                    {"COMPARISON": "<=", "VALUE": 8192}],
                "ALIGNMENT_LOGIC_SEP": "AND"},
            "TARGET_INFO": {"MACHINE_TYPE": "", "PROFILE": {}}
        }

        target_config2 = {
            "TARGET_REQUIREMENTS": {
                "ALIGNMENT": [
                    {"COMPARISON": "==", "VALUE": 32},
                    {"COMPARISON": "==", "VALUE": 4096}],
                "ALIGNMENT_LOGIC_SEP": "OR"},
            "TARGET_INFO": {"MACHINE_TYPE": "", "PROFILE": {}}
        }

        target_config3 = {
            "TARGET_REQUIREMENTS": {
                "ALIGNMENT": [
                    {"COMPARISON": "==", "VALUE": 31},
                    {"COMPARISON": "==", "VALUE": 61}],
                "ALIGNMENT_LOGIC_SEP": "OR"},
            "TARGET_INFO": {"MACHINE_TYPE": "", "PROFILE": {}}
        }

        target_config4 = {
            "TARGET_REQUIREMENTS": {
                "ALIGNMENT": [
                    {"COMPARISON": "==", "VALUE": 32},
                    {"COMPARISON": "==", "VALUE": 64}]},
            "TARGET_INFO": {"MACHINE_TYPE": "", "PROFILE": {}}
        }

        target_config5 = {
            "TARGET_REQUIREMENTS": {
                "ALIGNMENT": [
                    {"COMPARISON": "==", "VALUE": 32},
                    {"COMPARISON": "==", "VALUE": 64}],
                "ALIGNMENT_LOGIC_SEP": "AR"},
            "TARGET_INFO": {"MACHINE_TYPE": "", "PROFILE": {}}
        }

        test_section_alignment_test = TestSectionAlignment()
        pe = PE(optional_header=OptionalHeader(SectionAlignment=4096))
        tests = [(target_config0, Result.PASS), (target_config1, Result.FAIL), (target_config2, Result.PASS),
                 (target_config3, Result.FAIL), (target_config4, Result.FAIL), (target_config5, Result.FAIL)]

        for i in range(len(tests)):
            with self.subTest("test_section_alignment_and_or_logic", i=i):
                config, result = tests[i]
                self.assertEqual(test_section_alignment_test.execute(pe, config), result)

    test_pe_and = PE(optional_header=OptionalHeader(SectionAlignment=4096))

    def test_subsystem_value_test(self):
        """
        TestSubsystemValue follows the following logic:
        1. If Allowed Subsystems are not specified, or empty, return Result.SKIP
        2. If subsystem type is not present, return Result.WARN
        3. If subsystem type is invalid, return Result.FAIL
        3. return Result.PASS / Result.FAIL returned based on subsystem value
        """
        config_data0 = {
            "TARGET_REQUIREMENTS": {}
        }
        config_data1 = {
            "TARGET_REQUIREMENTS": {"ALLOWED_SUBSYSTEMS": []}
        }
        config_data2 = {
            "TARGET_REQUIREMENTS": {"ALLOWED_SUBSYSTEMS": ["IMAGE_SUBSYSTEM_EFI_BOOT_SERVICE_DRIVER"]}
        }
        config_data3 = {
            "TARGET_REQUIREMENTS": {"ALLOWED_SUBSYSTEMS":
                                    ["IMAGE_SUBSYSTEM_EFI_BOOT_SERVICE_DRIVER",
                                     "IMAGE_SUBSYSTEM_EFI_APPLICATION"]}
        }

        test_subsystem_value_test = TestSubsystemValue()

        TEST_PE0 = PE(optional_header=OptionalHeader(Subsystem=10))
        tests0 = [(config_data0, Result.SKIP), (config_data1, Result.SKIP),
                  (config_data2, Result.FAIL), (config_data3, Result.PASS)]

        for i in range(len(tests0)):
            with self.subTest("test_subsystem_value0", i=i):
                config, result = tests0[i]
                self.assertEqual(test_subsystem_value_test.execute(TEST_PE0, config), result)

        TEST_PE1 = PE(optional_header=OptionalHeader(Subsystem="UEFI_"))
        tests1 = [(config_data0, Result.SKIP), (config_data1, Result.SKIP),
                  (config_data2, Result.FAIL), (config_data3, Result.FAIL)]

        for i in range(len(tests1)):
            with self.subTest("test_subsystem_value1", i=i):
                config, result = tests1[i]
                self.assertEqual(test_subsystem_value_test.execute(TEST_PE1, config), result)

        TEST_PE2 = PE(optional_header=OptionalHeader(Subsystem=None))
        tests2 = [(config_data0, Result.SKIP), (config_data1, Result.SKIP),
                  (config_data2, Result.WARN), (config_data3, Result.WARN)]

        for i in range(len(tests2)):
            with self.subTest("test_subsystem_value2", i=i):
                config, result = tests2[i]
                self.assertEqual(test_subsystem_value_test.execute(TEST_PE2, config), result)
