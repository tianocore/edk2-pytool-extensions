# @file image_validation.py
# This tool allows a user validate an PE/COFF file
# against specific requirements
##
# Copyright (c) Microsoft Corporation
#
# SPDX-License-Identifier: BSD-2-Clause-Patent
##

import os
from pefile import PE, SECTION_CHARACTERISTICS, MACHINE_TYPE, SUBSYSTEM_TYPE
import logging
import argparse
import sys

from edk2toolext import edk2_logging

########################
#    Helper Functions  #
########################


def has_characteristic(data, mask):
    return ((data & mask) == mask)


def set_bit(data, bit):
    return data | (1 << bit)


def clear_bit(data, bit):
    return data & ~(1 << bit)


def set_nx_compat_flag(pe):
    dllchar = pe.OPTIONAL_HEADER.DllCharacteristics
    dllchar = set_bit(dllchar, 8)  # 8th bit is the nx_compat_flag
    pe.OPTIONAL_HEADER.DllCharacteristics = dllchar
    pe.merge_modified_section_data()
    return pe


def get_nx_compat_flag(pe):
    dllchar = pe.OPTIONAL_HEADER.DllCharacteristics

    if has_characteristic(dllchar, 256):  # 256 (8th bit) is the mask
        logging.info('True')
        return 1
    else:
        logging.info('False')
        return 0


def clear_nx_compat_flag(pe):
    dllchar = pe.OPTIONAL_HEADER.DllCharacteristics
    dllchar = clear_bit(dllchar, 8)  # 8th bit is the nx_compat_flag
    pe.OPTIONAL_HEADER.DllCharacteristics = dllchar
    pe.merge_modified_section_data()
    return pe


def fill_missing_requirements(default, target):
    for key in default:
        if key not in target:
            target[key] = default[key]
    return target


class Result:
    PASS = '[PASS]'
    WARN = '[WARNING]'
    SKIP = '[SKIP]'
    FAIL = '[FAIL]'


class TestInterface:

    def name(self):
        """Returns the name of the test"""
        raise NotImplementedError("Must Override Test Interface")

    def execute(self, pe, config_data):
        """
        Executes the test

        @param pe: The parser pefile
        @param config_data: Configuration data for the specific target machine
            and profile
        """
        raise NotImplementedError("Must Override Test Interface")


class TestManager(object):
    def __init__(self, config_data=None):
        self.tests = []
        if config_data:
            self.config_data = config_data
        else:
            self.config_data = {
                "TARGET_ARCH": {
                    "X64": "IMAGE_FILE_MACHINE_AMD64",
                    "IA32": "IMAGE_FILE_MACHINE_I386",
                    "AARCH64": "IMAGE_FILE_MACHINE_ARM64",
                    "ARM": "IMAGE_FILE_MACHINE_ARM"
                },
                "IMAGE_FILE_MACHINE_AMD64": {
                    "DEFAULT": {
                        "DATA_CODE_SEPARATION": True,
                        "ALLOWED_SUBSYSTEMS": [
                            "IMAGE_SUBSYSTEM_EFI_BOOT_SERVICE_DRIVER",
                            "IMAGE_SUBSYSTEM_EFI_ROM"
                        ],
                        "ALIGNMENT": [
                            {
                                "COMPARISON": "==",
                                "VALUE": 4096
                            }
                        ]
                    },
                    "APP": {
                        "ALLOWED_SUBSYSTEMS": [
                            "IMAGE_SUBSYSTEM_EFI_APPLICATION"
                        ]
                    },
                    "DRIVER": {
                        "ALLOWED_SUBSYSTEMS": [
                            "IMAGE_SUBSYSTEM_EFI_BOOT_SERVICE_DRIVER",
                            "IMAGE_SUBSYSTEM_EFI_RUNTIME_DRIVER"
                            "IMAGE_SUBSYSTEM_EFI_ROM"
                        ]
                    },
                },
                "IMAGE_FILE_MACHINE_ARM": {
                    "DEFAULT": {
                        "DATA_CODE_SEPARATION": True,
                        "ALLOWED_SUBSYSTEMS": [
                            "IMAGE_SUBSYSTEM_EFI_BOOT_SERVICE_DRIVER",
                            "IMAGE_SUBSYSTEM_EFI_ROM"
                        ],
                        "ALIGNMENT": [
                            {
                                "COMPARISON": "==",
                                "VALUE": 4096
                            }
                        ]
                    },
                    "APP": {
                        "ALLOWED_SUBSYSTEMS": [
                            "IMAGE_SUBSYSTEM_EFI_APPLICATION"
                        ],
                    },
                    "DRIVER": {
                        "ALLOWED_SUBSYSTEMS": [
                            "IMAGE_SUBSYSTEM_EFI_BOOT_SERVICE_DRIVER",
                            "IMAGE_SUBSYSTEM_EFI_RUNTIME_DRIVER",
                            "IMAGE_SUBSYSTEM_EFI_ROM"
                        ]}
                },
                "IMAGE_FILE_MACHINE_ARM64": {
                    "DEFAULT": {
                        "DATA_CODE_SEPARATION": True,
                        "ALLOWED_SUBSYSTEMS": [
                            "IMAGE_SUBSYSTEM_EFI_BOOT_SERVICE_DRIVER",
                            "IMAGE_SUBSYSTEM_EFI_ROM"
                        ],
                        "ALIGNMENT": [
                            {
                                "COMPARISON": "==",
                                "VALUE": 4096
                            }
                        ]
                    },
                    "APP": {
                        "ALLOWED_SUBSYSTEMS": [
                            "IMAGE_SUBSYSTEM_EFI_APPLICATION"
                        ]
                    },
                    "DRIVER": {
                        "ALLOWED_SUBSYSTEMS": [
                            "IMAGE_SUBSYSTEM_EFI_BOOT_SERVICE_DRIVER",
                            "IMAGE_SUBSYSTEM_EFI_RUNTIME_DRIVER",
                            "IMAGE_SUBSYSTEM_EFI_ROM"
                        ]
                    }
                },
                "IMAGE_FILE_MACHINE_I386": {
                    "DEFAULT": {
                        "DATA_CODE_SEPARATION": True,
                        "ALLOWED_SUBSYSTEMS": [
                            "IMAGE_SUBSYSTEM_EFI_BOOT_SERVICE_DRIVER",
                            "IMAGE_SUBSYSTEM_EFI_ROM"
                        ],
                        "ALIGNMENT": [
                            {
                                "COMPARISON": "==",
                                "VALUE": 4096
                            }
                        ]
                    },
                    "APP": {
                        "ALLOWED_SUBSYSTEMS": [
                            "IMAGE_SUBSYSTEM_EFI_APPLICATION"
                        ]
                    },
                    "DRIVER": {
                        "ALLOWED_SUBSYSTEMS": [
                            "IMAGE_SUBSYSTEM_EFI_BOOT_SERVICE_DRIVER",
                            "IMAGE_SUBSYSTEM_EFI_RUNTIME_DRIVER"
                            "IMAGE_SUBSYSTEM_EFI_ROM"
                        ]
                    }
                }
            }

    def add_test(self, test):
        """
        Adds a test to the test manager. Will be executed in the order added

        @param test: [Test(TestInterface)] A class that inherits and overrides
            the TestInterface class
        """
        self.tests.append(test)

    def add_tests(self, tests):
        """
        Adds multiple test to the test manager. Tests will be executed in the
        order added.

        @param test: [List[Test(TestInterface)]] A list of classes that
            inherits and overrides the TestInterface class
        """
        self.tests.extend(tests)

    def run_tests(self, pe, profile="DEFAULT"):
        """
        Runs all tests that have been added to the test manager. Tests will be
        executed in the order added

        @param pe         : [PE] The parsed pe
        @param target_info: [Dict] A Dict that contains MACHINE_TYPE and
            PROFILE information. If MachineType is not present, it will be
            pulled from the parsed pe, however the user must provide the Module
            Type

        @return Result.PASS : All tests passed successfully (including warnings)
        @return Result.SKIP : There is no information in the config file for the target and fv file type
        @return Result.ERROR: At least one test failed. Error messages can be found in the log
        """

        # Catch any invalid profiles
        machine_type = MACHINE_TYPE[pe.FILE_HEADER.Machine]
        if not self.config_data[machine_type].get(profile):
            logging.error(f'Profile type {profile} is invalid. Exiting...')
            return Result.FAIL

        # Fill any missing configurations for the specific module type with the default
        default = self.config_data[machine_type]["DEFAULT"]
        target = self.config_data[machine_type][profile]
        target_requirements = fill_missing_requirements(default, target)

        target_info = {
            "MACHINE_TYPE": machine_type,
            "PROFILE": profile
        }
        test_config_data = {
            "TARGET_INFO": target_info,
            "TARGET_REQUIREMENTS": target_requirements
        }

        logging.debug(f'Executing tests with settings [{machine_type}][{profile}]')
        overall_result = Result.PASS
        for test in self.tests:
            logging.debug(f'Starting test: [{test.name()}]')

            result = test.execute(pe, test_config_data)

            # Overall Result can only go lower (Pass -> Warn -> Fail)
            if result == Result.PASS:
                logging.debug(f'{result}')
            elif result == Result.SKIP:
                logging.debug(f'{result}: No Requirements for [{machine_type}][{profile}]')
            elif overall_result == Result.PASS:
                overall_result = result
            elif overall_result == Result.WARN and result == Result.FAIL:
                overall_result = result

        return overall_result


###########################
#       TESTS START       #
###########################
class TestWriteExecuteFlags(TestInterface):
    """
    Test: Section data / code separation verification

    Detailed Description:
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

    def name(self):
        return 'Section data / code separation verification'

    def execute(self, pe, config_data):
        target_requirements = config_data["TARGET_REQUIREMENTS"]

        if target_requirements.get("DATA_CODE_SEPARATION", False) is False:
            return Result.SKIP

        for section in pe.sections:
            if (has_characteristic(section.Characteristics, SECTION_CHARACTERISTICS["IMAGE_SCN_MEM_EXECUTE"])
               and has_characteristic(section.Characteristics, SECTION_CHARACTERISTICS["IMAGE_SCN_MEM_WRITE"])):

                logging.error(f'[{Result.FAIL}]: Section [{section.Name.decode().strip()}] \
                              should not be both Write and Execute')
                return Result.FAIL
        return Result.PASS


class TestSectionAlignment(TestInterface):
    """
    Test: Section alignment verification

    Detailed Description:
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

    def name(self):
        return 'Section alignment verification'

    def execute(self, pe, config_data):
        target_requirements = config_data["TARGET_REQUIREMENTS"]
        target_info = config_data["TARGET_INFO"]

        alignments = target_requirements.get("ALIGNMENT")
        if alignments is None or len(alignments) == 0:
            return Result.SKIP

        try:
            alignment = pe.OPTIONAL_HEADER.SectionAlignment
        except:
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
                    result = result and eval(f'{alignment} {reqs["COMPARISON"]} {reqs["VALUE"]}')
            elif logical_separator == "OR":
                result = False
                for reqs in alignments:
                    result = result or eval(f'{alignment} {reqs["COMPARISON"]} {reqs["VALUE"]}')
            else:
                logging.error("Invalid logical separator provided")
                return Result.FAIL
        else:
            req = alignments[0]
            result = eval(f'{alignment} {req["COMPARISON"]} {req["VALUE"]}')
        if result is False:
            logging.error(f'[{Result.FAIL}: Section Alignment Required: \
                            [{target_info["MACHINE_TYPE"]}] \
                            [{target_info["PROFILE"]}]: \
                            [(Detected): {alignment}]')
            return Result.FAIL

        return Result.PASS


class TestSubsystemValue(TestInterface):
    """
    Test: Subsystem type verification

    Detailed Description:
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

    def name(self):
        return 'Subsystem type verification'

    def execute(self, pe, config_data):
        target_requirements = config_data["TARGET_REQUIREMENTS"]

        subsystems = target_requirements.get("ALLOWED_SUBSYSTEMS")
        if subsystems is None or len(subsystems) == 0:
            return Result.SKIP

        try:
            subsystem = pe.OPTIONAL_HEADER.Subsystem
        except:
            logging.warn("Section Alignment is not present")
            return Result.WARN

        if subsystem is None:
            logging.warning(f'[{Result.WARN}]: Subsystem type is not present in the optional header.')
            return Result.WARN

        actual_subsystem = SUBSYSTEM_TYPE.get(subsystem)

        if actual_subsystem is None:
            logging.error(f'[{Result.WARN}]: Invalid Subsystem present')
            return Result.FAIL

        if actual_subsystem in subsystems:
            return Result.PASS
        else:
            logging.error(f'{Result.FAIL}: Submodule Type [{actual_subsystem}] not allowed.')
            return Result.FAIL
###########################
#        TESTS END        #
###########################


#
# Command Line Interface configuration
#
def get_cli_args(args):
    parser = argparse.ArgumentParser(description='A Image validation tool for memory mitigation')

    parser.add_argument('-i', '--file',
                        type=str,
                        required=True,
                        help='path to the image that needs validated.')
    parser.add_argument('-d', '--debug',
                        action='store_true',
                        default=False)

    parser.add_argument('-p', '--profile',
                        type=str,
                        default=None,
                        help='the profile config to be verified against. \
                            Will use the default, if not provided')

    group = parser.add_mutually_exclusive_group()

    group.add_argument('--set-nx-compat',
                       action='store_true',
                       default=False,
                       help='sets the NX_COMPAT flag')

    group.add_argument('--clear-nx-compat',
                       action='store_true',
                       default=False,
                       help='clears the NX_COMPAT flag')

    group.add_argument('--get-nx-compat',
                       action='store_true',
                       default=False,
                       help='returns the value of the NX_COMPAT flag')

    return parser.parse_args(args)


def main():
    # setup main console as logger
    logger = logging.getLogger('')
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

    logging.info(f'Overall Result: {result}')
    if result == Result.SKIP:
        logging.info('No Test requirements in the config file for this file.')
    elif result == Result.PASS or result == Result.WARN:
        sys.exit(0)
    else:
        sys.exit(1)


if __name__ == '__main__':
    main()
