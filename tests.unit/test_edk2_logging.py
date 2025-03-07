## @file test_edk2_logging.py
# This contains unit tests for the edk2_logging
##
# Copyright (c) Microsoft Corporation
#
# SPDX-License-Identifier: BSD-2-Clause-Patent
##
import io
import logging
import os
import tempfile
import unittest

from edk2toolext import edk2_logging


class Test_edk2_logging(unittest.TestCase):
    def test_can_create_console_logger(self):
        console_logger = edk2_logging.setup_console_logging(False, False)
        self.assertIsNot(console_logger, None, "We created a console logger")
        edk2_logging.stop_logging(console_logger)

    def test_can_create_txt_logger(self):
        test_dir = tempfile.mkdtemp()
        location, txt_logger = edk2_logging.setup_txt_logger(test_dir, "test_txt")
        logging.info("Testing")
        self.assertTrue(os.path.isfile(location), "We should have created a file")
        self.assertIsNot(txt_logger, None, "We created a txt logger")
        edk2_logging.stop_logging(txt_logger)

    def test_none_to_close(self):
        edk2_logging.stop_logging(None)

    def test_can_close_logger(self):
        test_dir = tempfile.mkdtemp()
        location, txt_logger = edk2_logging.setup_txt_logger(test_dir, "test_close")
        logging.critical("Testing")
        self.assertTrue(os.path.isfile(location), "We should have created a file")
        file = open(location, "r")
        num_lines = len(file.readlines())
        file.close()
        self.assertEqual(num_lines, 1, "We should only have one line")
        edk2_logging.stop_logging(txt_logger)
        logging.critical("Test 2")
        file = open(location, "r")
        num_lines2 = len(file.readlines())
        file.close()
        self.assertEqual(num_lines, num_lines2, "We should only have one line")

    def test_scan_compiler_output_generic(self):
        # Input with compiler errors and warnings
        output_stream = io.StringIO(
            "<source_file>error A1: error 1 details\n"
            "<source_file>warning B2: warning 2 details\n"
            "<source_file>error C3: error 3 details\n"
            "<source_file>warning D4: warning 4 details\n"
            "<source_file>fatal error: details\n"
        )
        expected_output = [
            (logging.ERROR, "Compiler #1 from <source_file> error 1 details"),
            (logging.WARNING, "Compiler #2 from <source_file> warning 2 details"),
            (logging.ERROR, "Compiler #3 from <source_file> error 3 details"),
            (logging.WARNING, "Compiler #4 from <source_file> warning 4 details"),
            (logging.ERROR, "<source_file>fatal error: details"),
        ]
        self.assertEqual(edk2_logging.scan_compiler_output(output_stream), expected_output)

        # Input with no issue (empty string)
        output_stream = io.StringIO("")
        expected_output = []
        self.assertEqual(edk2_logging.scan_compiler_output(output_stream), expected_output)

        # Input with no issue (string has content but not expected to match)
        output_stream = io.StringIO("Some debug message string.")
        expected_output = []
        self.assertEqual(edk2_logging.scan_compiler_output(output_stream), expected_output)

        # Input with no issue (string that mentions an error but does not match)
        output_stream = io.StringIO("An error and warning occurred in x.")
        expected_output = []
        self.assertEqual(edk2_logging.scan_compiler_output(output_stream), expected_output)

        # Input with only compiler warnings
        output_stream = io.StringIO(
            "<source_file.c>warning C8: warning details...\n<source_file.h>warning D10: info about the issue\n"
        )
        expected_output = [
            (logging.WARNING, "Compiler #8 from <source_file.c> warning details..."),
            (logging.WARNING, "Compiler #10 from <source_file.h> info about the issue"),
        ]
        self.assertEqual(edk2_logging.scan_compiler_output(output_stream), expected_output)

        # Input with only compiler errors
        output_stream = io.StringIO(
            "dir/file.c error T4: uninitialized variable c...\n"
            "dir1/dir2/file1.c error B2: duplicate symbol xyz.\n"
            "dir1/file_2.h error 5: header file problem"
        )
        expected_output = [
            (logging.ERROR, "Compiler #4 from dir/file.c uninitialized variable c..."),
            (logging.ERROR, "Compiler #2 from dir1/dir2/file1.c duplicate symbol xyz."),
            (logging.ERROR, "Compiler #5 from dir1/file_2.h header file problem"),
        ]
        self.assertEqual(edk2_logging.scan_compiler_output(output_stream), expected_output)

        # Input with near matches that should not match
        output_stream = io.StringIO(
            "source.c error A1 error 1 details.\n"
            "source warning D6 warning 6 details\n"
            "source.obj LNK4: linker 4 details\n"
            "script.py 5E: build 5 details\n"
        )
        expected_output = []
        self.assertEqual(edk2_logging.scan_compiler_output(output_stream), expected_output)

        # Test input with different error types
        output_stream = io.StringIO(
            "source.c error A1: error 1 details\n"
            "source.c warning B2: warning 2 details\n"
            "source.dsc error F3: error 3 details\n"
            "source.obj error LNK4: linker 4 details\n"
            "script.py error 5E: build 5 details\n"
        )
        expected_output = [
            (logging.ERROR, "Compiler #1 from source.c error 1 details"),
            (logging.WARNING, "Compiler #2 from source.c warning 2 details"),
            (logging.ERROR, "EDK2 #3 from source.dsc error 3 details"),
            (logging.ERROR, "Linker #4 from source.obj linker 4 details"),
            (logging.ERROR, "Build.py #5 from script.py build 5 details"),
        ]
        self.assertEqual(edk2_logging.scan_compiler_output(output_stream), expected_output)

    def test_scan_compiler_output_vs_actual(self):
        output_stream = io.StringIO("""
            "C:\\Program Files\\Microsoft Visual Studio\\2022\\Enterprise\\VC\\Tools\\MSVC\\14.34.31933\\bin\\Hostx86\\x64\\cl.exe" /Fod:\\a\\1\\s\\Build\\SetupDataPkg\\DEBUG_VS2022\\X64\\SetupDataPkg\\ConfApp\\ConfApp\\OUTPUT\\SvdUsb\\ /showIncludes /nologo /c /WX /GS /W4 /Gs32768 /D UNICODE /O1b2s /GL /Gy /FIAutoGen.h /EHs-c- /GR- /GF /Z7 /Gw -D DISABLE_NEW_DEPRECATED_INTERFACES /Id:\\a\\1\\s\\SetupDataPkg\\ConfApp\\SvdUsb  /Id:\\a\\1\\s\\SetupDataPkg\\ConfApp  /Id:\\a\\1\\s\\Build\\SetupDataPkg\\DEBUG_VS2022\\X64\\SetupDataPkg\\ConfApp\\ConfApp\\DEBUG  /Id:\\a\\1\\s\\MU_BASECORE\\MdePkg  /Id:\\a\\1\\s\\MU_BASECORE\\MdePkg\\Include  /Id:\\a\\1\\s\\MU_BASECORE\\MdePkg\\Test\\UnitTest\\Include  /Id:\\a\\1\\s\\MU_BASECORE\\MdePkg\\Include\\X64  /Id:\\a\\1\\s\\MU_BASECORE\\MdeModulePkg  /Id:\\a\\1\\s\\MU_BASECORE\\MdeModulePkg\\Include  /Id:\\a\\1\\s\\SetupDataPkg  /Id:\\a\\1\\s\\SetupDataPkg\\Include  /Id:\\a\\1\\s\\SetupDataPkg\\Test\\Include  /Id:\\a\\1\\s\\Common\\MU_PLUS\\PcBdsPkg  /Id:\\a\\1\\s\\Common\\MU_PLUS\\PcBdsPkg\\Include  /Id:\\a\\1\\s\\Common\\MU_PLUS\\MsCorePkg  /Id:\\a\\1\\s\\Common\\MU_PLUS\\MsCorePkg\\Include  /Id:\\a\\1\\s\\Common\\MU_PLUS\\XmlSupportPkg  /Id:\\a\\1\\s\\Common\\MU_PLUS\\XmlSupportPkg\\Include  /Id:\\a\\1\\s\\Common\\MU_TIANO_PLUS\\SecurityPkg  /Id:\\a\\1\\s\\Common\\MU_TIANO_PLUS\\SecurityPkg\\Include  /Id:\\a\\1\\s\\MU_BASECORE\\PolicyServicePkg  /Id:\\a\\1\\s\\MU_BASECORE\\PolicyServicePkg\\Include d:\\a\\1\\s\\SetupDataPkg\\ConfApp\\SvdUsb\\SvdUsb.c
            SvdUsb.c
            "C:\\Program Files\\Microsoft Visual Studio\\2022\\Enterprise\\VC\\Tools\\MSVC\\14.34.31933\\bin\\Hostx86\\x64\\lib.exe" /NOLOGO /LTCG /OUT:d:\\a\\1\\s\\Build\\SetupDataPkg\\DEBUG_VS2022\\X64\\SetupDataPkg\\ConfApp\\ConfApp\\OUTPUT\\ConfApp.lib @d:\\a\\1\\s\\Build\\SetupDataPkg\\DEBUG_VS2022\\X64\\SetupDataPkg\\ConfApp\\ConfApp\\OUTPUT\\object_files.lst
            INFO - 	"C:\\Program Files\\Microsoft Visual Studio\\2022\\Enterprise\\VC\\Tools\\MSVC\\14.34.31933\\bin\\Hostx86\\x64\\link.exe" /OUT:d:\\a\\1\\s\\Build\\SetupDataPkg\\DEBUG_VS2022\\X64\\SetupDataPkg\\ConfApp\\ConfApp\\DEBUG\\ConfApp.dll /NOLOGO /NODEFAULTLIB /IGNORE:4001 /IGNORE:4281 /OPT:REF /OPT:ICF=10 /MAP /ALIGN:32 /SECTION:.xdata,D /SECTION:.pdata,D /Machine:X64 /LTCG /DLL /ENTRY:_ModuleEntryPoint /SUBSYSTEM:CONSOLE /SAFESEH:NO /BASE:0 /DRIVER /DEBUG /ALIGN:4096 /DLL /NXCOMPAT   @d:\\a\\1\\s\\Build\\SetupDataPkg\\DEBUG_VS2022\\X64\\SetupDataPkg\\ConfApp\\ConfApp\\OUTPUT\\static_library_files.lst
            UefiApplicationEntryPoint.lib(ApplicationEntryPoint.obj) : error LNK2001: unresolved external symbol __security_check_cookie
            ConfApp.lib(SetupConf.obj) : error LNK2001: unresolved external symbol __report_rangecheckfailure
            d:\\a\\1\\s\\Build\\SetupDataPkg\\DEBUG_VS2022\\X64\\SetupDataPkg\\ConfApp\\ConfApp\\DEBUG\\ConfApp.dll : fatal error LNK1120: 2 unresolved externals
            NMAKE : fatal error U1077: '"C:\\Program Files\\Microsoft Visual Studio\\2022\\Enterprise\\VC\\Tools\\MSVC\\14.34.31933\\bin\\Hostx86\\x64\\link.exe"' : return code '0x460'
            Stop.


            build.py...
            : error 7000: Failed to execute command
                C:\\Program Files\\Microsoft Visual Studio\\2022\\Enterprise\\VC\\Tools\\MSVC\\14.34.31933\\bin\\Hostx86\\x86\\nmake.exe /nologo tbuild [d:\\a\\1\\s\\Build\\SetupDataPkg\\DEBUG_VS2022\\X64\\SetupDataPkg\\ConfApp\\ConfApp]


            build.py...
            : error F002: Failed to build module
                d:\\a\\1\\s\\SetupDataPkg\\ConfApp\\ConfApp.inf [X64, VS2022, DEBUG]
            """)  # noqa: E501

        expected_output = [
            (
                logging.ERROR,
                "Linker #2001 from UefiApplicationEntryPoint.lib(ApplicationEntryPoint.obj) : unresolved external symbol __security_check_cookie",
            ),  # noqa: E501
            (
                logging.ERROR,
                "Linker #2001 from ConfApp.lib(SetupConf.obj) : unresolved external symbol __report_rangecheckfailure",
            ),  # noqa: E501
            (
                logging.ERROR,
                "Linker #1120 from d:\\a\\1\\s\\Build\\SetupDataPkg\\DEBUG_VS2022\\X64\\SetupDataPkg\\ConfApp\\ConfApp\\DEBUG\\ConfApp.dll : fatal 2 unresolved externals",
            ),  # noqa: E501
            (
                logging.ERROR,
                "Compiler #1077 from NMAKE : fatal '\"C:\\Program Files\\Microsoft Visual Studio\\2022\\Enterprise\\VC\\Tools\\MSVC\\14.34.31933\\bin\\Hostx86\\x64\\link.exe\"' : return code '0x460'",
            ),  # noqa: E501
            (logging.ERROR, "Compiler #7000 from : Failed to execute command"),  # noqa: E501
            (logging.ERROR, "EDK2 #002 from : Failed to build module"),
        ]
        self.assertEqual(edk2_logging.scan_compiler_output(output_stream), expected_output)

    def test_scan_compiler_output_vs_linker_actual(self):
        output_stream = io.StringIO("""
                copy /y d:/a/1/s/Build/MdeModule/RELEASE_VS2022/IA32/MdeModulePkg/Universal/LegacyRegion2Dxe/LegacyRegion2Dxe/DEBUG/*.map d:/a/1/s/Build/MdeModule/RELEASE_VS2022/IA32/MdeModulePkg/Universal/LegacyRegion2Dxe/LegacyRegion2Dxe/OUTPUT
            SdMmcPciHcPei.lib(SdMmcPciHcPei.obj) : error LNK2001: unresolved external symbol _SafeUint8Add
            d:/a/1/s/Build/MdeModule/RELEASE_VS2022/IA32/MdeModulePkg/Bus/Pci/SdMmcPciHcPei/SdMmcPciHcPei/DEBUG/SdMmcPciHcPei.dll : fatal error LNK1120: 1 unresolved externals
            d:/a/1/s/Build/MdeModule/RELEASE_VS2022/IA32/MdeModulePkg/Universal/LegacyRegion2Dxe/LegacyRegion2Dxe/DEBUG/LegacyRegion2Dxe.map
                    1 file(s) copied.
                copy /y d:/a/1/s/Build/MdeModule/RELEASE_VS2022/IA32/MdeModulePkg/Universal/LegacyRegion2Dxe/LegacyRegion2Dxe/DEBUG/*.pdb d:/a/1/s/Build/MdeModule/RELEASE_VS2022/IA32/MdeModulePkg/Universal/LegacyRegion2Dxe/LegacyRegion2Dxe/OUTPUT
            NMAKE : fatal error U1077: '"C:/Program Files/Microsoft Visual Studio/2022/Enterprise/VC/Tools/MSVC/14.34.31933/bin/Hostx86/x86/link.exe"' : return code '0x460'
            """)  # noqa: E501

        expected_output = [
            (
                logging.ERROR,
                "Linker #2001 from SdMmcPciHcPei.lib(SdMmcPciHcPei.obj) : unresolved external symbol _SafeUint8Add",
            ),  # noqa: E501
            (
                logging.ERROR,
                "Linker #1120 from d:/a/1/s/Build/MdeModule/RELEASE_VS2022/IA32/MdeModulePkg/Bus/Pci/SdMmcPciHcPei/SdMmcPciHcPei/DEBUG/SdMmcPciHcPei.dll : fatal 1 unresolved externals",
            ),  # noqa: E501
            (
                logging.ERROR,
                "Compiler #1077 from NMAKE : fatal '\"C:/Program Files/Microsoft Visual Studio/2022/Enterprise/VC/Tools/MSVC/14.34.31933/bin/Hostx86/x86/link.exe\"' : return code '0x460'",
            ),
        ]  # noqa: E501
        self.assertEqual(edk2_logging.scan_compiler_output(output_stream), expected_output)

    def test_scan_compiler_output_gcc_mixed_actual(self):
        # Test input with all types of issues (errors and warnings)
        output_stream = io.StringIO("""
            "/usr/bin/aarch64-linux-gnu-gcc"   -g -Os -fshort-wchar -fno-builtin -fno-strict-aliasing -Wall -Werror -Wno-array-bounds -include AutoGen.h -fno-common -ffunction-sections -fdata-sections -DSTRING_ARRAY_NAME=BaseLibStrings -g -Os -fshort-wchar -fno-builtin -fno-strict-aliasing -Wall -Werror -Wno-array-bounds -include AutoGen.h -fno-common -mlittle-endian -fno-short-enums -fverbose-asm -funsigned-char -ffunction-sections -fdata-sections -Wno-address -fno-asynchronous-unwind-tables -fno-unwind-tables -fno-pic -fno-pie -ffixed-x18 -mcmodel=small -flto -Wno-unused-but-set-variable -Wno-unused-const-variable -D DISABLE_NEW_DEPRECATED_INTERFACES -mstrict-align -mgeneral-regs-only -c -o /__w/1/s/Build/SetupDataPkg/DEBUG_GCC5/AARCH64/MdePkg/Library/BaseLib/BaseLib/OUTPUT/./FilePaths.obj -I/__w/1/s/MU_BASECORE/MdePkg/Library/BaseLib/AArch64 -I/__w/1/s/MU_BASECORE/MdePkg/Library/BaseLib/Arm -I/__w/1/s/MU_BASECORE/MdePkg/Library/BaseLib -I/__w/1/s/Build/SetupDataPkg/DEBUG_GCC5/AARCH64/MdePkg/Library/BaseLib/BaseLib/DEBUG -I/__w/1/s/MU_BASECORE/MdePkg -I/__w/1/s/MU_BASECORE/MdePkg/Include -I/__w/1/s/MU_BASECORE/MdePkg/Test/UnitTest/Include -I/__w/1/s/MU_BASECORE/MdePkg/Include/AArch64 /__w/1/s/MU_BASECORE/MdePkg/Library/BaseLib/FilePaths.c
            "/usr/bin/aarch64-linux-gnu-gcc"   -g -Os -fshort-wchar -fno-builtin -fno-strict-aliasing -Wall -Werror -Wno-array-bounds -include AutoGen.h -fno-common -ffunction-sections -fdata-sections -DSTRING_ARRAY_NAME=BaseLibStrings -g -Os -fshort-wchar -fno-builtin -fno-strict-aliasing -Wall -Werror -Wno-array-bounds -include AutoGen.h -fno-common -mlittle-endian -fno-short-enums -fverbose-asm -funsigned-char -ffunction-sections -fdata-sections -Wno-address -fno-asynchronous-unwind-tables -fno-unwind-tables -fno-pic -fno-pie -ffixed-x18 -mcmodel=small -flto -Wno-unused-but-set-variable -Wno-unused-const-variable -D DISABLE_NEW_DEPRECATED_INTERFACES -mstrict-align -mgeneral-regs-only -c -o /__w/1/s/Build/SetupDataPkg/DEBUG_GCC5/AARCH64/MdePkg/Library/BaseLib/BaseLib/OUTPUT/./GetPowerOfTwo32.obj -I/__w/1/s/MU_BASECORE/MdePkg/Library/BaseLib/AArch64 -I/__w/1/s/MU_BASECORE/MdePkg/Library/BaseLib/Arm -I/__w/1/s/MU_BASECORE/MdePkg/Library/BaseLib -I/__w/1/s/Build/SetupDataPkg/DEBUG_GCC5/AARCH64/MdePkg/Library/BaseLib/BaseLib/DEBUG -I/__w/1/s/MU_BASECORE/MdePkg -I/__w/1/s/MU_BASECORE/MdePkg/Include -I/__w/1/s/MU_BASECORE/MdePkg/Test/UnitTest/Include -I/__w/1/s/MU_BASECORE/MdePkg/Include/AArch64 /__w/1/s/MU_BASECORE/MdePkg/Library/BaseLib/GetPowerOfTwo32.c
            /__w/1/s/SetupDataPkg/Library/ConfigVariableListLib/ConfigVariableListLib.c:20:1: error: conflicting types for `ConvertVariableListToVariableEntry`; have `EFI_STATUS(const void *, UINTN *, CONFIG_VAR_LIST_ENTRY *)` {aka `long long unsigned int(const void *, long long unsigned int *, CONFIG_VAR_LIST_ENTRY *)`}
            20 | ConvertVariableListToVariableEntry (
                | ^~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
            In file included from /__w/1/s/SetupDataPkg/Library/ConfigVariableListLib/ConfigVariableListLib.c:16:
            /__w/1/s/SetupDataPkg/Include/Library/ConfigVariableListLib.h:123:1: note: previous declaration of `ConvertVariableListToVariableEntry` with type `EFI_STATUS(void *, UINTN *, CONFIG_VAR_LIST_ENTRY *)` {aka `long long unsigned int(void *, long long unsigned int *, CONFIG_VAR_LIST_ENTRY *)`}
            123 | ConvertVariableListToVariableEntry (
                | ^~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
            "/usr/bin/aarch64-linux-gnu-gcc"   -g -Os -fshort-wchar -fno-builtin -fno-strict-aliasing -Wall -Werror -Wno-array-bounds -include AutoGen.h -fno-common -ffunction-sections -fdata-sections -DSTRING_ARRAY_NAME=BaseLibStrings -g -Os -fshort-wchar -fno-builtin -fno-strict-aliasing -Wall -Werror -Wno-array-bounds -include AutoGen.h -fno-common -mlittle-endian -fno-short-enums -fverbose-asm -funsigned-char -ffunction-sections -fdata-sections -Wno-address -fno-asynchronous-unwind-tables -fno-unwind-tables -fno-pic -fno-pie -ffixed-x18 -mcmodel=small -flto -Wno-unused-but-set-variable -Wno-unused-const-variable -D DISABLE_NEW_DEPRECATED_INTERFACES -mstrict-align -mgeneral-regs-only -c -o /__w/1/s/Build/SetupDataPkg/DEBUG_GCC5/AARCH64/MdePkg/Library/BaseLib/BaseLib/OUTPUT/./GetPowerOfTwo64.obj -I/__w/1/s/MU_BASECORE/MdePkg/Library/BaseLib/AArch64 -I/__w/1/s/MU_BASECORE/MdePkg/Library/BaseLib/Arm -I/__w/1/s/MU_BASECORE/MdePkg/Library/BaseLib -I/__w/1/s/Build/SetupDataPkg/DEBUG_GCC5/AARCH64/MdePkg/Library/BaseLib/BaseLib/DEBUG -I/__w/1/s/MU_BASECORE/MdePkg -I/__w/1/s/MU_BASECORE/MdePkg/Include -I/__w/1/s/MU_BASECORE/MdePkg/Test/UnitTest/Include -I/__w/1/s/MU_BASECORE/MdePkg/Include/AArch64 /__w/1/s/MU_BASECORE/MdePkg/Library/BaseLib/GetPowerOfTwo64.c
            make: *** [GNUmakefile:297: /__w/1/s/Build/SetupDataPkg/DEBUG_GCC5/AARCH64/SetupDataPkg/Library/ConfigVariableListLib/ConfigVariableListLib/OUTPUT/ConfigVariableListLib.obj] Error 1


            build.py...
            : error 7000: Failed to execute command
                make tbuild [/__w/1/s/Build/SetupDataPkg/DEBUG_GCC5/AARCH64/SetupDataPkg/Library/ConfigVariableListLib/ConfigVariableListLib]


            build.py...
            : error F002: Failed to build module
                /__w/1/s/SetupDataPkg/Library/ConfigVariableListLib/ConfigVariableListLib.inf [AARCH64, GCC5, DEBUG]
        """)  # noqa: E501

        expected_output = [
            (
                logging.ERROR,
                "Compiler #error from /__w/1/s/SetupDataPkg/Library/ConfigVariableListLib/ConfigVariableListLib.c conflicting types for `ConvertVariableListToVariableEntry`; have `EFI_STATUS(const void *, UINTN *, CONFIG_VAR_LIST_ENTRY *)` {aka `long long unsigned int(const void *, long long unsigned int *, CONFIG_VAR_LIST_ENTRY *)`}",
            ),  # noqa: E501
            (logging.ERROR, "Compiler #7000 from : Failed to execute command"),
            (logging.ERROR, "EDK2 #002 from : Failed to build module"),
        ]
        self.assertEqual(edk2_logging.scan_compiler_output(output_stream), expected_output)


def test_NO_secret_filter(caplog):
    end_list = [" ", ",", ";", ":", " "]
    start_list = [" ", " ", " ", " ", ":"]

    edk2_logging.setup_console_logging(logging.DEBUG)
    # Test secret github (valid) 1
    fake_secret = "ghp_aeiou1"
    for start, end in zip(start_list, end_list):
        logging.debug(f"This is a secret{start}{fake_secret}{end}to be caught")

    for record, start, end in zip(caplog.records, start_list, end_list):
        assert record.msg == f"This is a secret{start}{fake_secret}{end}to be caught"
    caplog.clear()


def test_CI_secret_filter(caplog):
    caplog.set_level(logging.DEBUG)
    end_list = [" ", ",", ";", ":", " "]
    start_list = [" ", " ", " ", " ", ":"]

    os.environ["CI"] = "TRUE"
    edk2_logging.setup_console_logging(logging.DEBUG)
    caplog.clear()

    # Test secret github (valid) 1
    fake_secret = "ghp_aeiou1"
    for start, end in zip(start_list, end_list):
        logging.debug(f"This is a secret{start}{fake_secret}{end}to be caught")

    for record, start, end in zip(caplog.records, start_list, end_list):
        assert record.msg == f"This is a secret{start}*******{end}to be caught"
    caplog.clear()


def test_TF_BUILD_secret_filter(caplog):
    caplog.set_level(logging.DEBUG)
    end_list = [" ", ",", ";", ":", " "]
    start_list = [" ", " ", " ", " ", ":"]

    os.environ["TF_BUILD"] = "TRUE"
    edk2_logging.setup_console_logging(logging.DEBUG)
    caplog.clear()

    # Test secret github (valid) 1
    fake_secret = "ghp_aeiou1"
    for start, end in zip(start_list, end_list):
        logging.debug(f"This is a secret{start}{fake_secret}{end}to be caught")

    for record, start, end in zip(caplog.records, start_list, end_list):
        assert record.msg == f"This is a secret{start}*******{end}to be caught"
    caplog.clear()


# caplog is a pytest fixture that captures log messages
def test_catch_secrets_filter(caplog):
    caplog.set_level(logging.DEBUG)
    os.environ["CI"] = "TRUE"
    edk2_logging.setup_console_logging(logging.DEBUG)
    caplog.clear()

    end_list = [" ", ",", ";", ":", " "]
    start_list = [" ", " ", " ", " ", ":"]

    # Test secret github (valid) 2
    fake_secret = "gho_aeiou1"
    for start, end in zip(start_list, end_list):
        logging.debug(f"This is a secret{start}{fake_secret}{end}to be caught")

    for record, start, end in zip(caplog.records, start_list, end_list):
        assert record.msg == f"This is a secret{start}*******{end}to be caught"
    caplog.clear()

    # Test secret github (invalid) 1
    fake_secret = "ghz_aeiou1"
    for start, end in zip(start_list, end_list):
        logging.debug(f"This is a secret{start}{fake_secret}{end}to be caught")

    for record, start, end in zip(caplog.records, start_list, end_list):
        assert record.msg == f"This is a secret{start}{fake_secret}{end}to be caught"
    caplog.clear()

    # Test secret nuget (valid) 1
    fake_secret = "345def553aef545fffff42dqa56890493223dfasdfasdf"
    for start, end in zip(start_list, end_list):
        logging.debug(f"This is a secret{start}{fake_secret}{end}to be caught")

    for record, start, end in zip(caplog.records, start_list, end_list):
        assert record.msg == f"This is a secret{start}*******{end}to be caught"
    caplog.clear()

    # Test secret nuget (invalid) 1
    fake_secret = "345def553aef545fffff42dqa56890493223dfasdfasd"
    for start, end in zip(start_list, end_list):
        logging.debug(f"This is a secret{start}{fake_secret}{end}to be caught")

    for record, start, end in zip(caplog.records, start_list, end_list):
        assert record.msg == f"This is a secret{start}{fake_secret}{end}to be caught"
    caplog.clear()


def test_scan_compiler_output_rust_scenarios():
    output_stream = io.StringIO(r"""
error: This should be caught
error[AA500]: This should not be caught
error[E0605]: This should be caught
error[E0605] This should not be caught
catch this error: This should not be caught
--> This should be caught
> This should not be caught
catch this error --> This should not be caught
    """)
    expected_output = [
        (logging.ERROR, "error: This should be caught"),
        (logging.ERROR, "error[E0605]: This should be caught"),
        (logging.ERROR, "--> This should be caught"),
    ]
    assert edk2_logging.scan_compiler_output(output_stream) == expected_output


def test_scan_compiler_output_rust_actual():
    output_stream = io.StringIO(r"""
[cargo-make] INFO - cargo make 0.37.1
[cargo-make] INFO - Calling cargo metadata to extract project info
[cargo-make] INFO - Cargo metadata done
[cargo-make] INFO - Build File: Makefile.toml
[cargo-make] INFO - Task: build
[cargo-make] INFO - Profile: development
[cargo-make] INFO - Running Task: legacy-migration
[cargo-make] INFO - Running Task: individual-package-targets
[cargo-make] INFO - Execute Command: "cargo" "build" "-p" "RustCrate" "--profile" "dev" "--target" "x86_64-unknown-uefi" "-Zbuild-std=core,compiler_builtins,alloc" "-Zbuild-std-features=compiler-builtins-mem" "-Zunstable-options" "--timings=html"
   Compiling RustCrate v0.1.0 (C:\\src\\RustCrate)
error[E0605]: non-primitive cast: `MemorySpaceDescriptor` as `*mut MemorySpaceDescriptor`
   --> RustCrate\\src/main.rs:248:66
    |
248 |         if get_memory_space_descriptor(desc.memory_base_address, descriptor as *mut MemorySpaceDescriptor)
    |                                                                  ^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^ invalid cast
    |
help: consider borrowing the value
    |
248 |         if get_memory_space_descriptor(desc.memory_base_address, &mut descriptor as *mut MemorySpaceDescriptor)
    |                                                                  ++++

For more information about this error, try `rustc --explain E0605`.
error: could not compile `RustCrate` (bin "RustCrate") due to previous error
      Timing report saved to C:\\src\\RustCrate\\target\\cargo-timings\\cargo-timing-20230927T151803Z.html
[cargo-make] ERROR - Error while executing command, exit code: 101
[cargo-make] WARN - Build Failed.
    """)
    expected_output = [
        (logging.ERROR, "error[E0605]: non-primitive cast: `MemorySpaceDescriptor` as `*mut MemorySpaceDescriptor`"),
        (logging.ERROR, r"--> RustCrate\\src/main.rs:248:66"),
        (logging.ERROR, 'error: could not compile `RustCrate` (bin "RustCrate") due to previous error'),
    ]
    assert edk2_logging.scan_compiler_output(output_stream) == expected_output
