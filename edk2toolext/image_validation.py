# @file image_validation.py
# This tool allows a user validate an PE/COFF file
# against specific requirements
##
# Copyright (c) Microsoft Corporation
#
# SPDX-License-Identifier: BSD-2-Clause-Patent
##
"""This tool allows the user to validate a PE/COFF file against specific requirements.

It also provides CLI functions to set and clear the nx_compat flag.
"""

import argparse
import logging
import os
import sys
from typing import Optional, Sequence

from pefile import MACHINE_TYPE, PE, SECTION_CHARACTERISTICS, SUBSYSTEM_TYPE

from edk2toolext import edk2_logging

########################
#    Helper Functions  #
########################


def has_characteristic(data: int, mask: int) -> bool:
    """Checks if data has a specific mask."""
    return (data & mask) == mask


def set_bit(data: int, bit: int) -> int:
    """Sets a specific bit."""
    return data | (1 << bit)


def clear_bit(data: int, bit: int) -> int:
    """Clears a specific bit."""
    return data & ~(1 << bit)


def set_nx_compat_flag(pe: PE) -> PE:
    """Sets the nx_compat flag to 1 in the PE/COFF file."""
    dllchar = pe.OPTIONAL_HEADER.DllCharacteristics
    dllchar = set_bit(dllchar, 8)  # 8th bit is the nx_compat_flag
    pe.OPTIONAL_HEADER.DllCharacteristics = dllchar
    pe.merge_modified_section_data()
    return pe


def get_nx_compat_flag(pe: PE) -> PE:
    """Reads the nx_compat flag of the PE/COFF file."""
    dllchar = pe.OPTIONAL_HEADER.DllCharacteristics

    if has_characteristic(dllchar, 256):  # 256 (8th bit) is the mask
        logging.info("True")
        return 1
    else:
        logging.info("False")
        return 0


def clear_nx_compat_flag(pe: PE) -> PE:
    """Sets the nx_compat flag to 0 in the PE/COFF file."""
    dllchar = pe.OPTIONAL_HEADER.DllCharacteristics
    dllchar = clear_bit(dllchar, 8)  # 8th bit is the nx_compat_flag
    pe.OPTIONAL_HEADER.DllCharacteristics = dllchar
    pe.merge_modified_section_data()
    return pe


def fill_missing_requirements(default: dict, target: dict) -> dict:
    """Fills missing requirements for a specific test config with default config.

    As an example, If there are specific requirements for an APP PE/COFF, those
    will take override the default requirements.Any requirement not specified
    by the APP config will be filled by the DEFAULT config.
    """
    for key in default:
        if key not in target:
            target[key] = default[key]
    return target


class Result:
    """Test results."""

    PASS = "[PASS]"
    WARN = "[WARNING]"
    SKIP = "[SKIP]"
    FAIL = "[FAIL]"


class TestInterface:
    """Interface for creating tests to execute on parsed PE/COFF files."""

    def name(self) -> str:
        """Returns the name of the test.

        "WARNING: Implement in a subclass.
        """
        raise NotImplementedError("Must Override Test Interface")

    def execute(self, pe: PE, config_data: dict) -> Result:
        """Executes the test on the pefile.

        Arguments:
            pe (PE): a parsed PE/COFF image file
            config_data (dict): config data for the test

        Returns:
            (Result): SKIP, WARN, FAIL, PASS

        WARNING: Implement in a subclass.
        """
        raise NotImplementedError("Must Override Test Interface")


class TestManager(object):
    """Manager responsible for executing all tests on all parsed PE/COFF files."""

    def __init__(self, config_data: Optional[dict] = None) -> None:
        """Inits the TestManager with configuration data.

        Args:
            config_data (dict, optional): the configuration data, loads default
                data if not provided.
        """
        self.tests = []
        if config_data:
            self.config_data = config_data
        else:
            self.config_data = {
                "TARGET_ARCH": {
                    "X64": "IMAGE_FILE_MACHINE_AMD64",
                    "IA32": "IMAGE_FILE_MACHINE_I386",
                    "AARCH64": "IMAGE_FILE_MACHINE_ARM64",
                    "ARM": "IMAGE_FILE_MACHINE_ARM",
                },
                "IMAGE_FILE_MACHINE_AMD64": {
                    "DEFAULT": {
                        "DATA_CODE_SEPARATION": True,
                        "ALLOWED_SUBSYSTEMS": ["IMAGE_SUBSYSTEM_EFI_BOOT_SERVICE_DRIVER", "IMAGE_SUBSYSTEM_EFI_ROM"],
                        "ALIGNMENT": [{"COMPARISON": "==", "VALUE": 4096}],
                    },
                    "APP": {"ALLOWED_SUBSYSTEMS": ["IMAGE_SUBSYSTEM_EFI_APPLICATION"]},
                    "DRIVER": {
                        "ALLOWED_SUBSYSTEMS": [
                            "IMAGE_SUBSYSTEM_EFI_BOOT_SERVICE_DRIVER",
                            "IMAGE_SUBSYSTEM_EFI_RUNTIME_DRIVERIMAGE_SUBSYSTEM_EFI_ROM",
                        ]
                    },
                },
                "IMAGE_FILE_MACHINE_ARM": {
                    "DEFAULT": {
                        "DATA_CODE_SEPARATION": True,
                        "ALLOWED_SUBSYSTEMS": ["IMAGE_SUBSYSTEM_EFI_BOOT_SERVICE_DRIVER", "IMAGE_SUBSYSTEM_EFI_ROM"],
                        "ALIGNMENT": [{"COMPARISON": "==", "VALUE": 4096}],
                    },
                    "APP": {
                        "ALLOWED_SUBSYSTEMS": ["IMAGE_SUBSYSTEM_EFI_APPLICATION"],
                    },
                    "DRIVER": {
                        "ALLOWED_SUBSYSTEMS": [
                            "IMAGE_SUBSYSTEM_EFI_BOOT_SERVICE_DRIVER",
                            "IMAGE_SUBSYSTEM_EFI_RUNTIME_DRIVER",
                            "IMAGE_SUBSYSTEM_EFI_ROM",
                        ]
                    },
                },
                "IMAGE_FILE_MACHINE_ARM64": {
                    "DEFAULT": {
                        "DATA_CODE_SEPARATION": True,
                        "ALLOWED_SUBSYSTEMS": ["IMAGE_SUBSYSTEM_EFI_BOOT_SERVICE_DRIVER", "IMAGE_SUBSYSTEM_EFI_ROM"],
                        "ALIGNMENT": [{"COMPARISON": "==", "VALUE": 4096}],
                    },
                    "APP": {"ALLOWED_SUBSYSTEMS": ["IMAGE_SUBSYSTEM_EFI_APPLICATION"]},
                    "DRIVER": {
                        "ALLOWED_SUBSYSTEMS": [
                            "IMAGE_SUBSYSTEM_EFI_BOOT_SERVICE_DRIVER",
                            "IMAGE_SUBSYSTEM_EFI_RUNTIME_DRIVER",
                            "IMAGE_SUBSYSTEM_EFI_ROM",
                        ]
                    },
                },
                "IMAGE_FILE_MACHINE_I386": {
                    "DEFAULT": {
                        "DATA_CODE_SEPARATION": True,
                        "ALLOWED_SUBSYSTEMS": ["IMAGE_SUBSYSTEM_EFI_BOOT_SERVICE_DRIVER", "IMAGE_SUBSYSTEM_EFI_ROM"],
                        "ALIGNMENT": [{"COMPARISON": "==", "VALUE": 4096}],
                    },
                    "APP": {"ALLOWED_SUBSYSTEMS": ["IMAGE_SUBSYSTEM_EFI_APPLICATION"]},
                    "DRIVER": {
                        "ALLOWED_SUBSYSTEMS": [
                            "IMAGE_SUBSYSTEM_EFI_BOOT_SERVICE_DRIVER",
                            "IMAGE_SUBSYSTEM_EFI_RUNTIME_DRIVERIMAGE_SUBSYSTEM_EFI_ROM",
                        ]
                    },
                },
            }

    def add_test(self, test: TestInterface) -> None:
        """Adds a test to the test manager.

        Will be executed in the order added.

        Args:
            test (TestInterface): A subclasses of the TestInterface
        """
        self.tests.append(test)

    def add_tests(self, tests: list[TestInterface]) -> None:
        """Adds multiple test to the test manager.

        Tests will be executed in the order added.

        Args:
            tests (List[TestInterface]): A list of subclasses of the TestInterface
        """
        self.tests.extend(tests)

    def run_tests(self, pe: PE, profile: str = "DEFAULT") -> Result:
        """Runs all tests that have been added to the test manager.

        Tests will be executed in the order added

        Args:
            pe (PE): The parsed pe
            profile (str):  profile to lookup in the config data

        Returns:
            (Result.PASS): All tests passed successfully (including warnings)
            (Result.SKIP): There is no information in the config file for the target and fv file type
            (Result.FAIL): At least one test failed. Error messages can be found in the log
        """
        # Catch any invalid profiles
        machine_type = MACHINE_TYPE[pe.FILE_HEADER.Machine]
        if not self.config_data[machine_type].get(profile):
            logging.error(f"Profile type {profile} is invalid. Exiting...")
            return Result.FAIL

        # Fill any missing configurations for the specific module type with the default
        default = self.config_data[machine_type]["DEFAULT"]
        target = self.config_data[machine_type][profile]
        target_requirements = fill_missing_requirements(default, target)

        target_info = {"MACHINE_TYPE": machine_type, "PROFILE": profile}
        test_config_data = {"TARGET_INFO": target_info, "TARGET_REQUIREMENTS": target_requirements}

        logging.debug(f"Executing tests with settings [{machine_type}][{profile}]")
        overall_result = Result.PASS
        for test in self.tests:
            logging.debug(f"Starting test: [{test.name()}]")

            result = test.execute(pe, test_config_data)

            # Overall Result can only go lower (Pass -> Warn -> Fail)
            if result == Result.PASS:
                logging.debug(f"{result}")
            elif result == Result.SKIP:
                logging.debug(f"{result}: No Requirements for [{machine_type}][{profile}]")
            elif overall_result == Result.PASS:
                overall_result = result
            elif overall_result == Result.WARN and result == Result.FAIL:
                overall_result = result

        return overall_result


###########################
#       TESTS START       #
###########################
class TestWriteExecuteFlags(TestInterface):
    """Section data / code separation verification Test.

    This test ensures that each section of the binary is not both
    write-able and execute-able. Sections can only be one or the other
    (or neither).This test is done by iterating over each section and
    checking the characteristics label for the Write Mask (0x80000000)
    and Execute Mask (0x20000000).

    Output:
        @Success: Only one (or neither) of the two masks (Write, Execute) are
            present
        @Skip: Test Skipped per config
        @Fail: Both the Write and Execute flags are present
            Possible Solution:

    Possible Solution:
        Update the failed section's characteristics to ensure it is either
        Write-able or Read-able, but not both.
    """

    def name(self) -> str:
        """Returns the name of the test."""
        return "Section data / code separation verification"

    def execute(self, pe: PE, config_data: dict) -> Result:
        """Executes the test on the pefile.

        Arguments:
            pe (PE): a parsed PE/COFF image file
            config_data (dict): config data for the test

        Returns:
            (Result): SKIP, WARN, FAIL, PASS
        """
        target_requirements = config_data["TARGET_REQUIREMENTS"]

        if target_requirements.get("DATA_CODE_SEPARATION", False) is False:
            return Result.SKIP

        for section in pe.sections:
            if has_characteristic(
                section.Characteristics, SECTION_CHARACTERISTICS["IMAGE_SCN_MEM_EXECUTE"]
            ) and has_characteristic(section.Characteristics, SECTION_CHARACTERISTICS["IMAGE_SCN_MEM_WRITE"]):
                logging.error(
                    f"[{Result.FAIL}]: Section [{section.Name.decode().strip()}] \
                              should not be both Write and Execute"
                )
                return Result.FAIL
        return Result.PASS


class TestSectionAlignment(TestInterface):
    """Section alignment verification Test.

    Checks the section alignment of the binary by accessing the optional
    header, then the section alignment. This value must meet the
    requirements specified in the config file.

    Output:
        @Success: Image alignment meets the requirement specified in the
            config file
        @Warn: Image Alignment value is not found in the Optional Header or
            set to 0
        @Skip: No Alignment requirements specified in the config file
        @Fail: Image alignment does not meet the requirements specified in
            the config file

    Possible Solution:
        Update the section alignment of the binary to match the
        requirements specified in the config file
    """

    def name(self) -> str:
        """Returns the name of the test."""
        return "Section alignment verification"

    def execute(self, pe: PE, config_data: dict) -> Result:
        """Executes the test on the pefile.

        Arguments:
            pe (PE): a parsed PE/COFF image file
            config_data (dict): config data for the test

        Returns:
            (Result): SKIP, WARN, FAIL, PASS
        """
        target_requirements = config_data["TARGET_REQUIREMENTS"]
        target_info = config_data["TARGET_INFO"]

        alignments = target_requirements.get("ALIGNMENT")
        if alignments is None or len(alignments) == 0:
            return Result.SKIP

        try:
            alignment = pe.OPTIONAL_HEADER.SectionAlignment
        except Exception:
            logging.warning("Section Alignment is not present")
            return Result.WARN

        if alignment is None or alignment == 0:
            return Result.WARN

        if len(alignments) > 1:
            logical_separator = target_requirements.get("ALIGNMENT_LOGIC_SEP")

            if logical_separator is None:
                logging.error("Multiple alignment requirements exist, but no logical separator provided")
                return Result.FAIL
            elif logical_separator == "AND":
                result = True
                for reqs in alignments:
                    result = result and eval(f"{alignment} {reqs['COMPARISON']} {reqs['VALUE']}")
            elif logical_separator == "OR":
                result = False
                for reqs in alignments:
                    result = result or eval(f"{alignment} {reqs['COMPARISON']} {reqs['VALUE']}")
            else:
                logging.error("Invalid logical separator provided")
                return Result.FAIL
        else:
            req = alignments[0]
            result = eval(f"{alignment} {req['COMPARISON']} {req['VALUE']}")
        if result is False:
            logging.error(
                f"[{Result.FAIL}]: Section Alignment Required: \
                            [{target_info['MACHINE_TYPE']}] \
                            [{target_info['PROFILE']}]: \
                            [(Detected): {alignment}]"
            )
            return Result.FAIL

        return Result.PASS


class TestSubsystemValue(TestInterface):
    """Subsystem type verification Test.

    Checks the subsystem value by accessing the optional header, then
    subsystem value. This value must match one of the allowed subsystem
    described in the config file

    Output:
        @Success: Subsystem type found in the optional header matches one of
            the allowed subsystems
        @Warn   : Subsystem type is not found in the optional header
        @Skip   : No subsystem type restrictions specified
        @Fail   : Subsystem type found in the optional header does not match
            one of the allowed subsystems

    Possible Solution:
        Update the subsystem type in the source code.
    """

    def name(self) -> str:
        """Returns the name of the test."""
        return "Subsystem type verification"

    def execute(self, pe: PE, config_data: dict) -> Result:
        """Executes the test on the pefile.

        Arguments:
            pe (PE): a parsed PE/COFF image file
            config_data (dict): config data for the test

        Returns:
            (Result): SKIP, WARN, FAIL, PASS
        """
        target_requirements = config_data["TARGET_REQUIREMENTS"]

        subsystems = target_requirements.get("ALLOWED_SUBSYSTEMS")
        if subsystems is None or len(subsystems) == 0:
            return Result.SKIP

        try:
            subsystem = pe.OPTIONAL_HEADER.Subsystem
        except Exception:
            logging.warn("Section Alignment is not present")
            return Result.WARN

        if subsystem is None:
            logging.warning(f"[{Result.WARN}]: Subsystem type is not present in the optional header.")
            return Result.WARN

        actual_subsystem = SUBSYSTEM_TYPE.get(subsystem)

        if actual_subsystem is None:
            logging.error(f"[{Result.WARN}]: Invalid Subsystem present")
            return Result.FAIL

        if actual_subsystem in subsystems:
            return Result.PASS
        else:
            logging.error(f"{Result.FAIL}: Submodule Type [{actual_subsystem}] not allowed.")
            return Result.FAIL


###########################
#        TESTS END        #
###########################


def get_cli_args(args: Sequence[str]) -> argparse.Namespace:
    """Adds CLI arguments for using the image validation tool."""
    parser = argparse.ArgumentParser(description="A Image validation tool for memory mitigation")

    parser.add_argument("-i", "--file", type=str, required=True, help="path to the image that needs validated.")
    parser.add_argument("-d", "--debug", action="store_true", default=False)

    parser.add_argument(
        "-p",
        "--profile",
        type=str,
        default=None,
        help="the profile config to be verified against. \
                            Will use the default, if not provided",
    )

    group = parser.add_mutually_exclusive_group()

    group.add_argument("--set-nx-compat", action="store_true", default=False, help="sets the NX_COMPAT flag")

    group.add_argument("--clear-nx-compat", action="store_true", default=False, help="clears the NX_COMPAT flag")

    group.add_argument(
        "--get-nx-compat", action="store_true", default=False, help="returns the value of the NX_COMPAT flag"
    )

    return parser.parse_args(args)


def main() -> None:
    """Main entry point into the image validation tool."""
    # setup main console as logger
    logger = logging.getLogger("")
    logger.setLevel(logging.INFO)
    console = edk2_logging.setup_console_logging(False)
    logger.addHandler(console)

    args = get_cli_args(sys.argv[1:])

    if args.debug is True:
        console.setLevel(logging.DEBUG)

    # Set the nx compatability flag and exit
    if args.set_nx_compat is True:
        pe = PE(args.file)
        set_nx_compat_flag(pe)
        os.remove(args.file)
        pe.write(args.file)
        exit(0)

    # clear the nx compatability flag and exit
    if args.clear_nx_compat is True:
        pe = PE(args.file)
        clear_nx_compat_flag(pe)
        os.remove(args.file)
        pe.write(args.file)
        exit(0)

    # exit with status equal to if nx compatability is present or not
    if args.get_nx_compat is True:
        pe = PE(args.file)
        exit(get_nx_compat_flag(pe))

    test_manager = TestManager()
    test_manager.add_test(TestWriteExecuteFlags())
    test_manager.add_test(TestSectionAlignment())
    test_manager.add_test(TestSubsystemValue())

    pe = PE(args.file)
    if not args.profile:
        result = test_manager.run_tests(pe)
    else:
        result = test_manager.run_tests(pe, args.profile)

    logging.info(f"Overall Result: {result}")
    if result == Result.SKIP:
        logging.info("No Test requirements in the config file for this file.")
    elif result == Result.PASS or result == Result.WARN:
        sys.exit(0)
    else:
        sys.exit(1)


if __name__ == "__main__":
    main()
