# @file test_image_validation.py
# This contains unit tests for the image validation tool.
##
# Copyright (c) Microsoft Corporation
#
# SPDX-License-Identifier: BSD-2-Clause-Patent
##
"""Unit test for the image validation tool."""

import unittest
from typing import Optional

import edk2toolext.image_validation as IV


class Section:
    """Dummy class to represent a Section."""

    def __init__(self, name: str, characteristics: Optional[int] = None) -> None:
        """Dummy class to represent a Section."""
        self.Characteristics = characteristics
        self.Name = name


class OptionalHeader:
    """Dummy class to represent an OptionalHeader."""

    def __init__(
        self,
        SectionAlignment: Optional[int] = None,
        Subsystem: Optional[int] = None,
        DllCharacteristics: Optional[int] = None,
    ) -> None:
        """Dummy class to represent an OptionalHeader."""
        self.SectionAlignment = SectionAlignment
        self.Subsystem = Subsystem
        self.DllCharacteristics = DllCharacteristics


class FileHeader:
    """Dummy class to represent a FileHeader."""

    def __init__(self) -> None:
        """Dummy class to represent a FileHeader."""
        self.Machine = 0x8664


class PE:
    """Dummy class to represent a PE."""

    def __init__(self, sections: Optional[Section] = None, optional_header: Optional[OptionalHeader] = None) -> None:
        """Dummy class to represent a PE."""
        self.sections = sections
        self.OPTIONAL_HEADER = optional_header
        self.FILE_HEADER = FileHeader()

    def merge_modified_section_data(self) -> None:
        """Dummy function to merge modified section data."""


class TestImageValidationInterface(unittest.TestCase):
    """Unit test for the image validation tool."""

    def test_add_test(self) -> None:
        """Test the add_test function in the image validation tool."""
        test_manager = IV.TestManager()
        self.assertEqual(len(test_manager.tests), 0)
        test_manager.add_test(IV.TestSectionAlignment())
        self.assertEqual(len(test_manager.tests), 1)

    def test_add_tests(self) -> None:
        """Test the add_tests function in the image validation tool."""
        test_manager = IV.TestManager()
        self.assertEqual(len(test_manager.tests), 0)
        test_manager.add_tests([IV.TestSectionAlignment(), IV.TestSubsystemValue()])
        self.assertEqual(len(test_manager.tests), 2)

    def test_test_manager(self) -> None:
        """Test the TestManager class in the image validation tool."""
        config_data = {
            "TARGET_ARCH": {"X64": "IMAGE_FILE_MACHINE_AMD64"},
            "IMAGE_FILE_MACHINE_AMD64": {"DEFAULT": {"DATA_CODE_SEPARATION": False}},
        }
        test_manager = IV.TestManager(config_data=config_data)
        self.assertEqual(test_manager.config_data, config_data)

        pe = PE(sections=[Section("S1.1".encode("utf-8"), characteristics=0x80000000)])
        test_manager.add_test(IV.TestWriteExecuteFlags())
        result = test_manager.run_tests(pe, "BAD_PROFILE")
        self.assertEqual(result, IV.Result.FAIL)

        result = test_manager.run_tests(pe)
        self.assertEqual(result, IV.Result.PASS)

    def test_write_execute_flags_test(self) -> None:
        """TestWriteExecuteFlags follows the following logic.

        1. If test requirement is not specified, or equal to false, return Result.SKIP
        3. Return Result.PASS / Result.FAIL returned based on Characteristic value
        """
        test_pe0 = PE(
            sections=[
                Section("S1.1".encode("utf-8"), characteristics=0x80000000),
                Section("S1.2".encode("utf-8"), characteristics=0x20000000),
                Section("S1.3".encode("utf-8"), characteristics=0x00000000),
            ]
        )

        test_pe1 = PE(
            sections=[
                Section("S2.1".encode("utf-8"), characteristics=0xA0000000),
                Section("S2.2".encode("utf-8"), characteristics=0x20000000),
                Section("S2.3".encode("utf-8"), characteristics=0x00000000),
            ]
        )

        test_pe2 = PE(
            sections=[
                Section("S3.1".encode("utf-8"), characteristics=0x20000000),
                Section("S3.2".encode("utf-8"), characteristics=0x80000000),
                Section("S3.3".encode("utf-8"), characteristics=0xC0000000),
            ]
        )

        test_pe3 = PE(sections=[Section("S4.1".encode("utf-8"), characteristics=0xE0000000)])

        config_data1 = {"TARGET_REQUIREMENTS": {"DATA_CODE_SEPARATION": False}}

        config_data2 = {"TARGET_REQUIREMENTS": {}}

        test_write_execute_flags = IV.TestWriteExecuteFlags()
        tests = [
            (test_pe0, IV.Result.PASS),
            (test_pe1, IV.Result.FAIL),
            (test_pe2, IV.Result.PASS),
            (test_pe3, IV.Result.FAIL),
        ]

        config_data0 = {"TARGET_REQUIREMENTS": {"DATA_CODE_SEPARATION": True}}

        # Test set 1
        for i in range(len(tests)):
            with self.subTest("test_write_execute1", i=i):
                pe, result = tests[i]
                self.assertEqual(test_write_execute_flags.execute(pe, config_data0), result)

        # Test set 2
        for i in range(len(tests)):
            with self.subTest("test_write_execute2", i=i):
                pe, _ = tests[i]
                self.assertEqual(test_write_execute_flags.execute(pe, config_data1), IV.Result.SKIP)

        # Test set 3
        for i in range(len(tests)):
            with self.subTest("test_write_execute3", i=i):
                pe, _ = tests[i]
                self.assertEqual(test_write_execute_flags.execute(pe, config_data2), IV.Result.SKIP)

    def test_section_alignment_test(self) -> None:
        """TestSectionAlignment follows the following logic.

        1. If requirements are not specified, or is empty, return Result.SKIP
        2. If SectionAlignment is not present, or is 0, return Result.WARN
        3. Return Result.PASS / Result.FAIL returned based on alignment requirements
        """
        config_data0 = {"TARGET_REQUIREMENTS": {}, "TARGET_INFO": {"MACHINE_TYPE": "", "PROFILE": {}}}
        config_data1 = {"TARGET_REQUIREMENTS": {"ALIGNMENT": []}, "TARGET_INFO": {"MACHINE_TYPE": "", "PROFILE": {}}}
        config_data2 = {
            "TARGET_REQUIREMENTS": {"ALIGNMENT": [{"COMPARISON": ">=", "VALUE": 0}]},
            "TARGET_INFO": {"MACHINE_TYPE": "", "PROFILE": {}},
        }

        config_data3 = {
            "TARGET_REQUIREMENTS": {"ALIGNMENT": [{"COMPARISON": "==", "VALUE": 1}]},
            "TARGET_INFO": {"MACHINE_TYPE": "", "PROFILE": {}},
        }

        config_data4 = {
            "TARGET_REQUIREMENTS": {
                "ALIGNMENT": [
                    {"COMPARISON": ">=", "VALUE": 0},
                    {"COMPARISON": ">=", "VALUE": 64},
                    {"COMPARISON": "<=", "VALUE": 8192},
                ],
                "ALIGNMENT_LOGIC_SEP": "AND",
            },
            "TARGET_INFO": {},
        }

        config_data5 = {
            "TARGET_REQUIREMENTS": {
                "ALIGNMENT": [
                    {"COMPARISON": ">=", "VALUE": 0},
                    {"COMPARISON": ">=", "VALUE": 64},
                    {"COMPARISON": "!=", "VALUE": 4096},
                ],
                "ALIGNMENT_LOGIC_SEP": "AND",
            },
            "TARGET_INFO": {"MACHINE_TYPE": "", "PROFILE": {}},
        }

        test_pe0 = PE(optional_header=OptionalHeader(SectionAlignment=4096))
        test_pe1 = PE(optional_header=OptionalHeader(SectionAlignment=0))
        test_pe2 = PE(optional_header=None)

        test_section_alignment_test = IV.TestSectionAlignment()
        tests0 = [
            (config_data0, IV.Result.SKIP),
            (config_data1, IV.Result.SKIP),
            (config_data2, IV.Result.PASS),
            (config_data3, IV.Result.FAIL),
            (config_data4, IV.Result.PASS),
            (config_data5, IV.Result.FAIL),
        ]

        # Test set 1
        for i in range(len(tests0)):
            with self.subTest("test_section_alignment_test0", i=i):
                config, result = tests0[i]
                self.assertEqual(test_section_alignment_test.execute(test_pe0, config), result)

        tests1 = [
            (config_data0, IV.Result.SKIP),
            (config_data1, IV.Result.SKIP),
            (config_data2, IV.Result.WARN),
            (config_data3, IV.Result.WARN),
            (config_data4, IV.Result.WARN),
            (config_data5, IV.Result.WARN),
        ]

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

    def test_section_alignment_test2(self) -> None:
        """Test section algnment."""
        target_config0 = {
            "TARGET_REQUIREMENTS": {
                "ALIGNMENT": [{"COMPARISON": ">=", "VALUE": 0}, {"COMPARISON": "<=", "VALUE": 8192}],
                "ALIGNMENT_LOGIC_SEP": "AND",
            },
            "TARGET_INFO": {"MACHINE_TYPE": "", "PROFILE": {}},
        }

        target_config1 = {
            "TARGET_REQUIREMENTS": {
                "ALIGNMENT": [{"COMPARISON": "==", "VALUE": 0}, {"COMPARISON": "<=", "VALUE": 8192}],
                "ALIGNMENT_LOGIC_SEP": "AND",
            },
            "TARGET_INFO": {"MACHINE_TYPE": "", "PROFILE": {}},
        }

        target_config2 = {
            "TARGET_REQUIREMENTS": {
                "ALIGNMENT": [{"COMPARISON": "==", "VALUE": 32}, {"COMPARISON": "==", "VALUE": 4096}],
                "ALIGNMENT_LOGIC_SEP": "OR",
            },
            "TARGET_INFO": {"MACHINE_TYPE": "", "PROFILE": {}},
        }

        target_config3 = {
            "TARGET_REQUIREMENTS": {
                "ALIGNMENT": [{"COMPARISON": "==", "VALUE": 31}, {"COMPARISON": "==", "VALUE": 61}],
                "ALIGNMENT_LOGIC_SEP": "OR",
            },
            "TARGET_INFO": {"MACHINE_TYPE": "", "PROFILE": {}},
        }

        target_config4 = {
            "TARGET_REQUIREMENTS": {
                "ALIGNMENT": [{"COMPARISON": "==", "VALUE": 32}, {"COMPARISON": "==", "VALUE": 64}]
            },
            "TARGET_INFO": {"MACHINE_TYPE": "", "PROFILE": {}},
        }

        target_config5 = {
            "TARGET_REQUIREMENTS": {
                "ALIGNMENT": [{"COMPARISON": "==", "VALUE": 32}, {"COMPARISON": "==", "VALUE": 64}],
                "ALIGNMENT_LOGIC_SEP": "AR",
            },
            "TARGET_INFO": {"MACHINE_TYPE": "", "PROFILE": {}},
        }

        test_section_alignment_test = IV.TestSectionAlignment()
        pe = PE(optional_header=OptionalHeader(SectionAlignment=4096))
        tests = [
            (target_config0, IV.Result.PASS),
            (target_config1, IV.Result.FAIL),
            (target_config2, IV.Result.PASS),
            (target_config3, IV.Result.FAIL),
            (target_config4, IV.Result.FAIL),
            (target_config5, IV.Result.FAIL),
        ]

        for i in range(len(tests)):
            with self.subTest("test_section_alignment_and_or_logic", i=i):
                config, result = tests[i]
                self.assertEqual(test_section_alignment_test.execute(pe, config), result)

    def test_subsystem_value_test(self) -> None:
        """TestSubsystemValue follows the following logic.

        1. If Allowed Subsystems are not specified, or empty, return Result.SKIP
        2. If subsystem type is not present, return Result.WARN
        3. If subsystem type is invalid, return Result.FAIL
        3. return Result.PASS / Result.FAIL returned based on subsystem value
        """
        config_data0 = {"TARGET_REQUIREMENTS": {}}
        config_data1 = {"TARGET_REQUIREMENTS": {"ALLOWED_SUBSYSTEMS": []}}
        config_data2 = {"TARGET_REQUIREMENTS": {"ALLOWED_SUBSYSTEMS": ["IMAGE_SUBSYSTEM_EFI_BOOT_SERVICE_DRIVER"]}}
        config_data3 = {
            "TARGET_REQUIREMENTS": {
                "ALLOWED_SUBSYSTEMS": ["IMAGE_SUBSYSTEM_EFI_BOOT_SERVICE_DRIVER", "IMAGE_SUBSYSTEM_EFI_APPLICATION"]
            }
        }

        test_subsystem_value_test = IV.TestSubsystemValue()

        TEST_PE0 = PE(optional_header=OptionalHeader(Subsystem=10))
        tests0 = [
            (config_data0, IV.Result.SKIP),
            (config_data1, IV.Result.SKIP),
            (config_data2, IV.Result.FAIL),
            (config_data3, IV.Result.PASS),
        ]

        for i in range(len(tests0)):
            with self.subTest("test_subsystem_value0", i=i):
                config, result = tests0[i]
                self.assertEqual(test_subsystem_value_test.execute(TEST_PE0, config), result)

        TEST_PE1 = PE(optional_header=OptionalHeader(Subsystem="UEFI_"))
        tests1 = [
            (config_data0, IV.Result.SKIP),
            (config_data1, IV.Result.SKIP),
            (config_data2, IV.Result.FAIL),
            (config_data3, IV.Result.FAIL),
        ]

        for i in range(len(tests1)):
            with self.subTest("test_subsystem_value1", i=i):
                config, result = tests1[i]
                self.assertEqual(test_subsystem_value_test.execute(TEST_PE1, config), result)

        TEST_PE2 = PE(optional_header=OptionalHeader(Subsystem=None))
        tests2 = [
            (config_data0, IV.Result.SKIP),
            (config_data1, IV.Result.SKIP),
            (config_data2, IV.Result.WARN),
            (config_data3, IV.Result.WARN),
        ]

        for i in range(len(tests2)):
            with self.subTest("test_subsystem_value2", i=i):
                config, result = tests2[i]
                self.assertEqual(test_subsystem_value_test.execute(TEST_PE2, config), result)

    def test_helper_functions(self) -> None:
        """Test the helper functions in the image validation tool."""
        data = 0b00000000
        results = [1, 2, 4, 8, 16, 32, 64]

        for i in range(len(results)):
            with self.subTest("test_set_bit1", i=i):
                self.assertEqual(IV.set_bit(data, i), results[i])

        data = 0b11111111
        result = 255
        for i in range(7):
            with self.subTest("test_set_bit2", i=i):
                self.assertEqual(IV.set_bit(data, i), result)

        data = 0b11111111
        result = [254, 253, 251, 247, 239, 223, 191, 127]

        for i in range(len(result)):
            with self.subTest("test_clear_bit1", i=i):
                self.assertEqual(IV.clear_bit(data, i), result[i])

        data = 0b00000000
        result = 0

        for i in range(7):
            with self.subTest("test_clear_bit2", i=i):
                self.assertEqual(IV.clear_bit(data, i), result)

        data = 0b11001101
        masks = [0b10100000, 0b10000001, 0b10101010, 0b11110000, 0b00000001]
        result = [False, True, False, False, True]

        for i in range(len(result)):
            with self.subTest("test_has_characteristic", i=i):
                self.assertEqual(IV.has_characteristic(data, masks[i]), result[i])

        default_config = {
            "T1": "T",
            "T2": "T",
            "T3": "T",
        }
        target_config = {"T2": "F"}
        final_config = {"T1": "T", "T2": "F", "T3": "T"}

        self.assertEqual(IV.fill_missing_requirements(default_config, target_config), final_config)

    def test_test_interface(self) -> None:
        """Test that the TestInterface class raises NotImplementedError."""
        c = IV.TestInterface()

        with self.assertRaises(NotImplementedError):
            c.name()
        with self.assertRaises(NotImplementedError):
            c.execute(1, 2)

    def test_get_cli_args(self) -> None:
        """Test that we can parse CLI arguments."""
        test1 = ["-i", "file.efi"]
        test2 = ["-i", "file.efi", "-d"]
        test3 = ["-i", "file.efi", "-p", "APP"]
        test4 = ["--file", "file.efi", "--set-nx-compat"]
        test5 = ["--file", "file.efi", "--get-nx-compat"]
        test6 = ["--file", "file.efi", "--clear-nx-compat"]

        args = IV.get_cli_args(test1)
        self.assertEqual(args.file, "file.efi")
        self.assertEqual(args.debug, False)
        self.assertEqual(args.profile, None)

        args = IV.get_cli_args(test2)
        self.assertEqual(args.file, "file.efi")
        self.assertEqual(args.debug, True)
        self.assertEqual(args.profile, None)

        args = IV.get_cli_args(test3)
        self.assertEqual(args.file, "file.efi")
        self.assertEqual(args.debug, False)
        self.assertEqual(args.profile, "APP")

        args = IV.get_cli_args(test4)
        self.assertEqual(args.file, "file.efi")
        self.assertEqual(args.set_nx_compat, True)
        self.assertEqual(args.get_nx_compat, False)
        self.assertEqual(args.clear_nx_compat, False)

        args = IV.get_cli_args(test5)
        self.assertEqual(args.file, "file.efi")
        self.assertEqual(args.set_nx_compat, False)
        self.assertEqual(args.get_nx_compat, True)
        self.assertEqual(args.clear_nx_compat, False)

        args = IV.get_cli_args(test6)
        self.assertEqual(args.file, "file.efi")
        self.assertEqual(args.set_nx_compat, False)
        self.assertEqual(args.get_nx_compat, False)
        self.assertEqual(args.clear_nx_compat, True)

    def test_nx_flag_commands(self) -> None:
        """Test that we can set, get, and clear the NX compatibility flag."""
        pe = PE(optional_header=OptionalHeader(DllCharacteristics=0x0100))
        pe = IV.clear_nx_compat_flag(pe)
        self.assertEqual(pe.OPTIONAL_HEADER.DllCharacteristics, 0x0)
        self.assertEqual(IV.get_nx_compat_flag(pe), 0)

        pe = PE(optional_header=OptionalHeader(DllCharacteristics=0x0000))
        pe = IV.set_nx_compat_flag(pe)
        self.assertEqual(pe.OPTIONAL_HEADER.DllCharacteristics, 0x0100)
        self.assertEqual(IV.get_nx_compat_flag(pe), 1)
