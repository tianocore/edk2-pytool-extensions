# @file test_image_validation.py
# This contains unit tests for the image validation tool.
##
# Copyright (c) Microsoft Corporation
#
# SPDX-License-Identifier: BSD-2-Clause-Patent
##
import unittest
from edk2toolext.image_validation import Result, TestManager, TestSectionAlignment
from edk2toolext.image_validation import TestSubsystemValue, TestWriteExecuteFlags
from edk2toolext.image_validation import set_bit, clear_bit, has_characteristic
from edk2toolext.image_validation import TestInterface, fill_missing_requirements


class Section:
    def __init__(self, name, characteristics=None):
        self.Characteristics = characteristics
        self.Name = name


class OptionalHeader:
    def __init__(self, SectionAlignment=None, Subsystem=None):
        self.SectionAlignment = SectionAlignment
        self.Subsystem = Subsystem


class FileHeader:
    def __init__(self):
        self.Machine = 0x8664


class PE:
    def __init__(self, sections=None, optional_header=None):
        self.sections = sections
        self.OPTIONAL_HEADER = optional_header
        self.FILE_HEADER = FileHeader()


# def subTest(self, msg=_subtest_msg_sentinel, **params):
class TestImageValidationInterface(unittest.TestCase):

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

    def test_test_manager(self):
        config_data = {
            "TARGET_ARCH": {
                "X64": "IMAGE_FILE_MACHINE_AMD64"
            },
            "IMAGE_FILE_MACHINE_AMD64": {
                "DEFAULT": {
                    "DATA_CODE_SEPARATION": False
                }
            }
        }
        test_manager = TestManager(config_data=config_data)
        self.assertEqual(test_manager.config_data, config_data)

        pe = PE(sections=[Section("S1.1".encode("utf-8"), characteristics=0x80000000)])
        test_manager.add_test(TestWriteExecuteFlags())
        result = test_manager.run_tests(pe, "BAD_PROFILE")
        self.assertEqual(result, Result.PASS)

    def test_write_execute_flags_test(self):
        """
        TestWriteExecuteFlags follows the following logic:
        1. If test requirement is not specified, or equal to false, return Result.SKIP
        3. Return Result.PASS / Result.FAIL returned based on Characteristic value
        """
        test_pe0 = PE(sections=[
            Section("S1.1".encode("utf-8"), characteristics=0x80000000),
            Section("S1.2".encode("utf-8"), characteristics=0x20000000),
            Section("S1.3".encode("utf-8"), characteristics=0x00000000)])

        test_pe1 = PE(sections=[
            Section("S2.1".encode("utf-8"), characteristics=0xA0000000),
            Section("S2.2".encode("utf-8"), characteristics=0x20000000),
            Section("S2.3".encode("utf-8"), characteristics=0x00000000)])

        test_pe2 = PE(sections=[
            Section("S3.1".encode("utf-8"), characteristics=0x20000000),
            Section("S3.2".encode("utf-8"), characteristics=0x80000000),
            Section("S3.3".encode("utf-8"), characteristics=0xC0000000)])

        test_pe3 = PE(sections=[
            Section("S4.1".encode("utf-8"), characteristics=0xE0000000)])

        config_data1 = {
            "TARGET_REQUIREMENTS": {"DATA_CODE_SEPARATION": False}
        }

        config_data2 = {"TARGET_REQUIREMENTS": {}}

        test_write_execute_flags = TestWriteExecuteFlags()
        tests = [(test_pe0, Result.PASS), (test_pe1, Result.FAIL), (test_pe2, Result.PASS), (test_pe3, Result.FAIL)]

        config_data0 = {
            "TARGET_REQUIREMENTS": {"DATA_CODE_SEPARATION": True}
        }

        # Test set 1
        for i in range(len(tests)):
            with self.subTest("test_write_execute1", i=i):
                pe, result = tests[i]
                self.assertEqual(test_write_execute_flags.execute(pe, config_data0), result)

        # Test set 2
        for i in range(len(tests)):
            with self.subTest("test_write_execute2", i=i):
                pe, _ = tests[i]
                self.assertEqual(test_write_execute_flags.execute(pe, config_data1), Result.SKIP)

        # Test set 3
        for i in range(len(tests)):
            with self.subTest("test_write_execute3", i=i):
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

        test_pe0 = PE(optional_header=OptionalHeader(SectionAlignment=4096))
        test_pe1 = PE(optional_header=OptionalHeader(SectionAlignment=0))
        test_pe2 = PE(optional_header=None)

        test_section_alignment_test = TestSectionAlignment()
        tests0 = [(config_data0, Result.SKIP), (config_data1, Result.SKIP),
                  (config_data2, Result.PASS), (config_data3, Result.FAIL),
                  (config_data4, Result.PASS), (config_data5, Result.FAIL)]

        # Test set 1
        for i in range(len(tests0)):
            with self.subTest("test_section_alignment_test0", i=i):
                config, result = tests0[i]
                self.assertEqual(test_section_alignment_test.execute(test_pe0, config), result)

        tests1 = [(config_data0, Result.SKIP), (config_data1, Result.SKIP),
                  (config_data2, Result.WARN), (config_data3, Result.WARN),
                  (config_data4, Result.WARN), (config_data5, Result.WARN)]

        # Test set 2
        for i in range(len(tests1)):
            with self.subTest("test_section_alignment_test1", i=i):
                config, result = tests1[i]
                self.assertEqual(test_section_alignment_test.execute(test_pe1, config), result)

        # Test set 3
        for i in range(len(tests1)):
            with self.subTest("test_section_alignment_test2", i=i):
                config, result = tests1[i]
                self.assertEqual(test_section_alignment_test.execute(test_pe2, config), result)

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

    def test_helper_functions(self):

        data = 0b00000000
        results = [1, 2, 4, 8, 16, 32, 64]

        for i in range(len(results)):
            with self.subTest("test_set_bit1", i=i):
                self.assertEqual(set_bit(data, i), results[i])

        data = 0b11111111
        result = 255
        for i in range(7):
            with self.subTest("test_set_bit2", i=i):
                self.assertEqual(set_bit(data, i), result)

        data = 0b11111111
        result = [254, 253, 251, 247, 239, 223, 191, 127]

        for i in range(len(result)):
            with self.subTest("test_clear_bit1", i=i):
                self.assertEqual(clear_bit(data, i), result[i])

        data = 0b00000000
        result = 0

        for i in range(7):
            with self.subTest("test_clear_bit2", i=i):
                self.assertEqual(clear_bit(data, i), result)

        data = 0b11001101
        masks = [0b10100000, 0b10000001, 0b10101010, 0b11110000, 0b00000001]
        result = [False, True, False, False, True]

        for i in range(len(result)):
            with self.subTest("test_has_characteristic", i=i):
                self.assertEqual(has_characteristic(data, masks[i]), result[i])

        default_config = {
            "T1": "T",
            "T2": "T",
            "T3": "T",
        }
        target_config = {
            "T2": "F"
        }
        final_config = {
            "T1": "T",
            "T2": "F",
            "T3": "T"
        }

        self.assertEqual(fill_missing_requirements(default_config, target_config), final_config)

    def test_test_interface(self):
        c = TestInterface()

        with self.assertRaises(NotImplementedError):
            c.name()
        with self.assertRaises(NotImplementedError):
            c.execute(1, 2)
