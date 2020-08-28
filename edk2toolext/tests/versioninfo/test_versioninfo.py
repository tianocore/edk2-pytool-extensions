## @file versioninfo_tool_test.py
# This unittest module contains test cases for the versioninfo_tool module and CLI routines.
#
##
# Copyright (C) Microsoft Corporation
#
# SPDX-License-Identifier: BSD-2-Clause-Patent
##

# spell-checker:ignore nmake, UCRT

import os
import sys
import unittest
import tempfile
import json
import copy
import logging
import edk2toollib.windows.locate_tools as locate_tools
from edk2toollib.utility_functions import RunCmd

from io import StringIO
from edk2toolext.versioninfo import versioninfo_tool
from edk2toolext.environment import shell_environment

DUMMY_EXE_FILE_NAME = 'dummy_exe'
DUMMY_EXE_SRC_NAME = 'dummy_exe_src'
DUMMY_JSON_FILE_NAME = 'dummy_json_file'
DUMMY_EXE_MAKEFILE_NAME = 'Makefile'
VERSIONINFO_JSON_FILE_NAME = 'VERSIONINFO'
BAD_JSON_FILE_NAME = 'bad_json'
NO_RSRC_EXE_NAME = 'no_rsrc.exe'
NOT_PE_NAME = 'not_pe.elf'
NO_STRINGFILEINFO_EXE_NAME = 'no_stringfileinfo.exe'
PATH_TO_VERSIONINFO_FOLDER = os.path.join('tests', 'versioninfo')

DUMMY_VALID_JSON = {
    "Minimal": "False",
    "FileVersion": "1.2.3.4",
    "ProductVersion": "1.2.3.4",
    "FileFlagsMask": "0x3f",
    "FileFlags": "0x0",
    "FileOS": "VOS_NT",
    "FileType": "VFT_DRV",
    "FileSubtype": "VFT2_DRV_SYSTEM",
    "StringFileInfo": {
        "Comments": "Dummy Driver",
        "CompanyName": "Dummy compnay",
        "FileDescription": "Dummy Driver",
        "FileVersion": "1.2.3.4",
        "InternalName": "Internal Dummy Driver",
        "LegalCopyright": "(C) 2048 Dummy Driver",
        "OriginalFilename": "Dummy.sys",
        "ProductName": "Dummy Driver"
    },
    "VarFileInfo": {
        "Translation": "0x0409 0x04b0"
    }
}

DUMMY_MINIMAL_JSON = {
    "Fileversion": "1,0,0,0",
    "ProductName": "Test Product",
    "CompanyName": "Test Company"
}

DUMMY_MINIMAL_DECODED = {
    "FileVersion": "1.0.0.0",
    "ProductVersion": "0.0.0.0",
    "FileFlagsMask": "0x0",
    "FileFlags": "0x0",
    "FileOS": "VOS_UNKNOWN",
    "FileType": "VFT_UNKNOWN",
    "FileSubtype": "VFT2_UNKNOWN",
    "StringFileInfo": {
        "CompanyName": "Test Company",
        "ProductName": "Test Product"
    },
    "VarFileInfo": {
        "Translation": "0x0409 0x04b0"
    }
}

DUMMY_EXE_SOURCE = '#include <stdio.h>\nint main() { printf("TEST"); }'

DUMMY_EXE_MAKEFILE_LINUX = f"""
all: {DUMMY_EXE_SRC_NAME}.o res.o
\tx86_64-w64-mingw32-gcc -o {DUMMY_EXE_FILE_NAME} {DUMMY_EXE_SRC_NAME}.o res.o

{DUMMY_EXE_SRC_NAME}.o: {DUMMY_EXE_SRC_NAME}.c
\tx86_64-w64-mingw32-gcc -c {DUMMY_EXE_SRC_NAME}.c

res.o: VERSIONINFO.rc
\tx86_64-w64-mingw32-windres -I. -i {VERSIONINFO_JSON_FILE_NAME}.rc -o res.o
"""

DUMMY_EXE_MAKEFILE_WINDOWS = """
norsrc: %s.c
    CL /Fe".\\%s.exe" /Fo".\\%s.obj"  /EHsc %s.c

rsrc: %s.c
    CL /Fo"%s.obj"  /EHsc /c %s.c
    RC VERSIONINFO.rc
    LINK %s.obj VERSIONINFO.res
""" % (DUMMY_EXE_SRC_NAME, DUMMY_EXE_FILE_NAME, DUMMY_EXE_FILE_NAME, DUMMY_EXE_SRC_NAME,
       DUMMY_EXE_SRC_NAME, DUMMY_EXE_FILE_NAME, DUMMY_EXE_SRC_NAME, DUMMY_EXE_FILE_NAME)


VS2019_INTERESTING_KEYS = ["ExtensionSdkDir", "INCLUDE", "LIB", "LIBPATH", "UniversalCRTSdkDir",
                           "UCRTVersion", "WindowsLibPath", "WindowsSdkBinPath", "WindowsSdkDir",
                           "WindowsSdkVerBinPath", "WindowsSDKVersion", "VCToolsInstallDir", "Path"]


def check_for_err_helper(cls, temp_dir, json_input, err_msg, decode=False):
    if decode:
        cli_params = [json_input, temp_dir, '-d']
    else:
        cli_params = [json_input, temp_dir]
    parsed_args = versioninfo_tool.get_cli_options(cli_params)
    with StringIO() as log_stream:
        log_handler = logging.StreamHandler(log_stream)
        logging.getLogger().addHandler(log_handler)
        returned_error = False
        try:
            versioninfo_tool.service_request(parsed_args)
        except SystemExit as e:
            returned_error = e.code == 1

        logging.getLogger().removeHandler(log_handler)
        cls.assertFalse(os.path.isfile(os.path.join(temp_dir, 'VERSIONINFO.rc')))
        cls.assertEqual(log_stream.getvalue(), err_msg)
        cls.assertTrue(returned_error)


def setup_vs_build(cls):
    # Find VS build tools
    (rc, vc_install_path) = locate_tools.FindWithVsWhere(vs_version="vs2019")
    if rc != 0 or vc_install_path is None or not os.path.exists(vc_install_path):
        logging.fatal("Cannot locate VS build tools install path")
        cls.fail()

    vc_ver_path = os.path.join(vc_install_path, "VC", "Tools", "MSVC")
    if not os.path.isdir(vc_ver_path):
        logging.fatal("Cannot locate VS build tools directory")
        cls.fail()

    vc_ver = os.listdir(vc_ver_path)[-1].strip()
    if vc_ver is None:
        logging.fatal("Cannot locate VS build tools version")
        cls.fail()

    # Set VS env variables
    vs2019_prefix = os.path.join(vc_install_path, "VC", "Tools", "MSVC", vc_ver)
    vs2019_prefix += os.path.sep
    shell_environment.GetEnvironment().set_shell_var("VS2019_PREFIX", vs2019_prefix)
    shell_environment.GetEnvironment().set_shell_var("VS2019_HOST", "x64")
    shell_env = shell_environment.GetEnvironment()
    vs_vars = locate_tools.QueryVcVariables(VS2019_INTERESTING_KEYS, "x64", vs_version="vs2019")
    for (k, v) in vs_vars.items():
        shell_env.set_shell_var(k, v)


def encode_decode_helper(cls, dummy_json, temp_dir, is_windows, reference=DUMMY_VALID_JSON):
    cli_params = [dummy_json, os.path.join(temp_dir, "VERSIONINFO.rc")]
    parsed_args = versioninfo_tool.get_cli_options(cli_params)
    versioninfo_tool.service_request(parsed_args)
    if is_windows:
        ret = RunCmd('nmake', 'rsrc', workingdir=temp_dir)
        cls.assertEqual(ret, 0, f"nmake failed with return code {ret}.")
    else:
        ret = RunCmd('make', "", workingdir=temp_dir)
        cls.assertEqual(ret, 0, f"make failed with return code {ret}.")

    cli_params = [os.path.join(temp_dir, DUMMY_EXE_FILE_NAME) + '.exe', os.path.join(temp_dir, "VERSIONINFO.json"), '-d'] # noqa
    parsed_args = versioninfo_tool.get_cli_options(cli_params)
    versioninfo_tool.service_request(parsed_args)
    try:
        with open(os.path.join(temp_dir, VERSIONINFO_JSON_FILE_NAME + '.json')) as generated_json:
            try:
                generated_dict = json.load(generated_json)
            except ValueError:
                cls.fail()

            cls.assertTrue('Signature' in generated_dict)
            del generated_dict['Signature']
            cls.assertTrue('StrucVersion' in generated_dict)
            del generated_dict['StrucVersion']
            if 'FileDateMS' in generated_dict:
                del generated_dict['FileDateMS']
            if 'FileDateLS' in generated_dict:
                del generated_dict['FileDateLS']
            ref = copy.deepcopy(reference)
            if "Minimal" in ref:
                del ref["Minimal"]
            cls.assertEqual(generated_dict, ref)
    except IOError:
        cls.fail()


class TestVersioninfo(unittest.TestCase):
    @unittest.skipUnless(sys.platform.startswith("win"), "requires Windows")
    def test_encode_decode_windows(self):
        setup_vs_build(self)
        temp_dir = tempfile.mkdtemp()
        dummy_json = os.path.join(temp_dir, DUMMY_JSON_FILE_NAME + '.json.orig')
        dummy_exe_src = os.path.join(temp_dir, DUMMY_EXE_SRC_NAME + '.c')
        dummy_exe_makefile = os.path.join(temp_dir, DUMMY_EXE_MAKEFILE_NAME)

        with open(dummy_json, 'w') as dummy_file:
            json.dump(DUMMY_VALID_JSON, dummy_file)
        with open(dummy_exe_src, 'w') as dummy_src:
            dummy_src.write(DUMMY_EXE_SOURCE)
        with open(dummy_exe_makefile, 'w') as dummy_makefile:
            dummy_makefile.write(DUMMY_EXE_MAKEFILE_WINDOWS)

        encode_decode_helper(self, dummy_json, temp_dir, True)

    @unittest.skipUnless(sys.platform.startswith("win"), "requires Windows")
    def test_encode_decode_minimal_windows(self):
        setup_vs_build(self)
        temp_dir = tempfile.mkdtemp()
        dummy_json = os.path.join(temp_dir, DUMMY_JSON_FILE_NAME + '.json.orig')
        dummy_exe_src = os.path.join(temp_dir, DUMMY_EXE_SRC_NAME + '.c')
        dummy_exe_makefile = os.path.join(temp_dir, DUMMY_EXE_MAKEFILE_NAME)

        with open(dummy_json, 'w') as dummy_file:
            json.dump(DUMMY_MINIMAL_JSON, dummy_file)
        with open(dummy_exe_src, 'w') as dummy_src:
            dummy_src.write(DUMMY_EXE_SOURCE)
        with open(dummy_exe_makefile, 'w') as dummy_makefile:
            dummy_makefile.write(DUMMY_EXE_MAKEFILE_WINDOWS)

        encode_decode_helper(self, dummy_json, temp_dir, True, DUMMY_MINIMAL_DECODED)

    @unittest.skipUnless(sys.platform.startswith("linux"), "requires Linx")
    def test_encode_decode_linux(self):
        temp_dir = tempfile.mkdtemp()
        dummy_json = os.path.join(temp_dir, DUMMY_JSON_FILE_NAME + '.json.orig')
        dummy_exe_src = os.path.join(temp_dir, DUMMY_EXE_SRC_NAME + '.c')
        dummy_exe_makefile = os.path.join(temp_dir, DUMMY_EXE_MAKEFILE_NAME)

        with open(dummy_json, 'w') as dummy_file:
            json.dump(DUMMY_VALID_JSON, dummy_file)
        with open(dummy_exe_src, 'w') as dummy_src:
            dummy_src.write(DUMMY_EXE_SOURCE)
        with open(dummy_exe_makefile, 'w') as dummy_makefile:
            dummy_makefile.write(DUMMY_EXE_MAKEFILE_LINUX)

        encode_decode_helper(self, dummy_json, temp_dir, False)

    @unittest.skipUnless(sys.platform.startswith("linux"), "requires Linux")
    def test_encode_decode_minimal_linux(self):
        temp_dir = tempfile.mkdtemp()
        dummy_json = os.path.join(temp_dir, DUMMY_JSON_FILE_NAME + '.json.orig')
        dummy_exe_src = os.path.join(temp_dir, DUMMY_EXE_SRC_NAME + '.c')
        dummy_exe_makefile = os.path.join(temp_dir, DUMMY_EXE_MAKEFILE_NAME)

        with open(dummy_json, 'w') as dummy_file:
            json.dump(DUMMY_MINIMAL_JSON, dummy_file)
        with open(dummy_exe_src, 'w') as dummy_src:
            dummy_src.write(DUMMY_EXE_SOURCE)
        with open(dummy_exe_makefile, 'w') as dummy_makefile:
            dummy_makefile.write(DUMMY_EXE_MAKEFILE_LINUX)

        encode_decode_helper(self, dummy_json, temp_dir, False, DUMMY_MINIMAL_DECODED)

    def test_no_rsrc(self):
        temp_dir = tempfile.mkdtemp()
        cli_params = [os.path.join(os.getcwd(), PATH_TO_VERSIONINFO_FOLDER, NO_RSRC_EXE_NAME), temp_dir, '-d']
        parsed_args = versioninfo_tool.get_cli_options(cli_params)
        with StringIO() as log_stream:
            log_handler = logging.StreamHandler(log_stream)
            logging.getLogger().addHandler(log_handler)
            returned_error = False
            try:
                versioninfo_tool.service_request(parsed_args)
            except SystemExit as e:
                returned_error = e.code == 1

            logging.getLogger().removeHandler(log_handler)
            self.assertFalse(os.path.isfile(os.path.join(temp_dir, 'VERSIONINFO.json')))
            self.assertEqual(log_stream.getvalue(),
                             "Could not find VS_FIXEDFILEINFO.\nFile does not contain .rsrc section.\n")
            self.assertTrue(returned_error)

    def test_missing_varinfo(self):
        temp_dir = tempfile.mkdtemp()
        bad_json_file = os.path.join(temp_dir, BAD_JSON_FILE_NAME + '.json')
        bad_json = copy.deepcopy(DUMMY_VALID_JSON)
        del bad_json['VarFileInfo']
        with open(bad_json_file, 'w') as bad_file:
            json.dump(bad_json, bad_file)

        check_for_err_helper(self, temp_dir, bad_json_file,
                             'Missing required parameter: VARFILEINFO.\nInvalid input, aborted.\n')

    def test_missing_translation(self):
        temp_dir = tempfile.mkdtemp()
        bad_json_file = os.path.join(temp_dir, BAD_JSON_FILE_NAME + '.json')
        bad_json = copy.deepcopy(DUMMY_VALID_JSON)
        del bad_json['VarFileInfo']['Translation']
        with open(bad_json_file, 'w') as bad_file:
            json.dump(bad_json, bad_file)

        check_for_err_helper(self, temp_dir, bad_json_file,
                             'Missing required parameter in VarFileInfo: Translation.\nInvalid input, aborted.\n')

    def test_invalid_varfileinfo(self):
        temp_dir = tempfile.mkdtemp()
        bad_json_file = os.path.join(temp_dir, BAD_JSON_FILE_NAME + '.json')
        bad_json = copy.deepcopy(DUMMY_VALID_JSON)
        bad_json['VarFileInfo']['FileVersion'] = "1.2.1.2"
        with open(bad_json_file, 'w') as bad_file:
            json.dump(bad_json, bad_file)

        check_for_err_helper(self, temp_dir, bad_json_file,
                             'Invalid VarFileInfo parameter: FileVersion.\nInvalid input, aborted.\n')

    def test_missing_companyname(self):
        temp_dir = tempfile.mkdtemp()
        bad_json_file = os.path.join(temp_dir, BAD_JSON_FILE_NAME + '.json')
        bad_json = copy.deepcopy(DUMMY_VALID_JSON)
        del bad_json['StringFileInfo']['CompanyName']
        with open(bad_json_file, 'w') as bad_file:
            json.dump(bad_json, bad_file)

        check_for_err_helper(self, temp_dir, bad_json_file,
                             'Missing required StringFileInfo parameter: CompanyName.\nInvalid input, aborted.\n')

    def test_version_overflow(self):
        temp_dir = tempfile.mkdtemp()
        bad_json_file = os.path.join(temp_dir, BAD_JSON_FILE_NAME + '.json')
        bad_json = copy.deepcopy(DUMMY_VALID_JSON)
        bad_json['ProductVersion'] = '65536.0.0.0'
        with open(bad_json_file, 'w') as bad_file:
            json.dump(bad_json, bad_file)

        check_for_err_helper(self, temp_dir, bad_json_file,
                             'Integer overflow in version string: 65536.0.0.0.\nInvalid input, aborted.\n')

    def test_invalid_version(self):
        temp_dir = tempfile.mkdtemp()
        bad_json_file = os.path.join(temp_dir, BAD_JSON_FILE_NAME + '.json')
        bad_json = copy.deepcopy(DUMMY_VALID_JSON)
        bad_json['ProductVersion'] = 'Version 1.0.1.0'
        with open(bad_json_file, 'w') as bad_file:
            json.dump(bad_json, bad_file)

        check_for_err_helper(self, temp_dir, bad_json_file,
                             'Invalid version string: Version 1.0.1.0. Version must be in form " INTEGER.INTEGER.INTEGER.INTEGER".\nInvalid input, aborted.\n') # noqa

    def test_bad_version_format(self):
        temp_dir = tempfile.mkdtemp()
        bad_json_file = os.path.join(temp_dir, BAD_JSON_FILE_NAME + '.json')
        bad_json = copy.deepcopy(DUMMY_VALID_JSON)
        bad_json['ProductVersion'] = '1.234'
        with open(bad_json_file, 'w') as bad_file:
            json.dump(bad_json, bad_file)

        check_for_err_helper(self, temp_dir, bad_json_file,
                             'Invalid version string: 1.234. Version must be in form "INTEGER.INTEGER.INTEGER.INTEGER".\nInvalid input, aborted.\n') # noqa

    def test_invalid_language_code_value(self):
        temp_dir = tempfile.mkdtemp()
        bad_json_file = os.path.join(temp_dir, BAD_JSON_FILE_NAME + '.json')
        bad_json = copy.deepcopy(DUMMY_VALID_JSON)
        bad_json['VarFileInfo']['Translation'] = '"0x0009 0x04b0"'
        with open(bad_json_file, 'w') as bad_file:
            json.dump(bad_json, bad_file)

        check_for_err_helper(self, temp_dir, bad_json_file,
                             'Invalid language code: "0x0009 0x04b0".\nInvalid input, aborted.\n')

    def test_invalid_language_code_string(self):
        temp_dir = tempfile.mkdtemp()
        bad_json_file = os.path.join(temp_dir, BAD_JSON_FILE_NAME + '.json')
        bad_json = copy.deepcopy(DUMMY_VALID_JSON)
        bad_json['VarFileInfo']['Translation'] = '"utf-8 US"'
        with open(bad_json_file, 'w') as bad_file:
            json.dump(bad_json, bad_file)

        check_for_err_helper(self, temp_dir, bad_json_file,
                             'Invalid language code: "utf-8 US".\nInvalid input, aborted.\n')

    def test_invalid_language_code_format(self):
        temp_dir = tempfile.mkdtemp()
        bad_json_file = os.path.join(temp_dir, BAD_JSON_FILE_NAME + '.json')
        bad_json = copy.deepcopy(DUMMY_VALID_JSON)
        bad_json['VarFileInfo']['Translation'] = '"0x400904b0"'
        with open(bad_json_file, 'w') as bad_file:
            json.dump(bad_json, bad_file)

        check_for_err_helper(self, temp_dir, bad_json_file,
                             'Translation field must contain 2 space delimited hexidecimal bytes.\nInvalid input, aborted.\n') # noqa

    def test_invalid_language_code_no_hex(self):
        temp_dir = tempfile.mkdtemp()
        bad_json_file = os.path.join(temp_dir, BAD_JSON_FILE_NAME + '.json')
        bad_json = copy.deepcopy(DUMMY_VALID_JSON)
        bad_json['VarFileInfo']['Translation'] = '"4009 04b0"'
        with open(bad_json_file, 'w') as bad_file:
            json.dump(bad_json, bad_file)

        check_for_err_helper(self, temp_dir, bad_json_file,
                             'Invalid language code: "4009 04b0".\nInvalid input, aborted.\n')

    def test_invalid_fileos_hex(self):
        temp_dir = tempfile.mkdtemp()
        bad_json_file = os.path.join(temp_dir, BAD_JSON_FILE_NAME + '.json')
        bad_json = copy.deepcopy(DUMMY_VALID_JSON)
        bad_json['FileOS'] = '0x12391'
        with open(bad_json_file, 'w') as bad_file:
            json.dump(bad_json, bad_file)

        check_for_err_helper(self, temp_dir, bad_json_file,
                             'Invalid FILEOS value: 0x12391.\nInvalid input, aborted.\n')

    def test_invalid_fileos_string(self):
        temp_dir = tempfile.mkdtemp()
        bad_json_file = os.path.join(temp_dir, BAD_JSON_FILE_NAME + '.json')
        bad_json = copy.deepcopy(DUMMY_VALID_JSON)
        bad_json['FileOS'] = 'INVALID'
        with open(bad_json_file, 'w') as bad_file:
            json.dump(bad_json, bad_file)

        check_for_err_helper(self, temp_dir, bad_json_file,
                             'Invalid FILEOS value: INVALID.\nInvalid input, aborted.\n')

    def test_invalid_filetype_hex(self):
        temp_dir = tempfile.mkdtemp()
        bad_json_file = os.path.join(temp_dir, BAD_JSON_FILE_NAME + '.json')
        bad_json = copy.deepcopy(DUMMY_VALID_JSON)
        bad_json['FileType'] = '0x12391'
        with open(bad_json_file, 'w') as bad_file:
            json.dump(bad_json, bad_file)

        check_for_err_helper(self, temp_dir, bad_json_file,
                             'Invalid FILETYPE value: 0x12391.\nInvalid FILESUBTYPE value for FILETYPE 0x12391, value must be 0.\nInvalid input, aborted.\n') # noqa

    def test_invalid_filetype_string(self):
        temp_dir = tempfile.mkdtemp()
        bad_json_file = os.path.join(temp_dir, BAD_JSON_FILE_NAME + '.json')
        bad_json = copy.deepcopy(DUMMY_VALID_JSON)
        bad_json['FileType'] = 'INVALID'
        with open(bad_json_file, 'w') as bad_file:
            json.dump(bad_json, bad_file)

        check_for_err_helper(self, temp_dir, bad_json_file,
                             'Invalid FILETYPE value: INVALID.\nInvalid FILESUBTYPE value for FILETYPE INVALID, value must be 0.\nInvalid input, aborted.\n') # noqa

    def test_invalid_filesubtype_drv(self):
        temp_dir = tempfile.mkdtemp()
        bad_json_file = os.path.join(temp_dir, BAD_JSON_FILE_NAME + '.json')
        bad_json = copy.deepcopy(DUMMY_VALID_JSON)
        bad_json['FileType'] = 'VFT_DRV'
        bad_json['FileSubtype'] = 'VFT2_FONT_RASTER'
        with open(bad_json_file, 'w') as bad_file:
            json.dump(bad_json, bad_file)

        check_for_err_helper(self, temp_dir, bad_json_file,
                             'Invalid FILESUBTYPE value for FILETYPE VFT_DRV: VFT2_FONT_RASTER.\nInvalid input, aborted.\n') # noqa

    def test_invalid_filesubtype_font(self):
        temp_dir = tempfile.mkdtemp()
        bad_json_file = os.path.join(temp_dir, BAD_JSON_FILE_NAME + '.json')
        bad_json = copy.deepcopy(DUMMY_VALID_JSON)
        bad_json['FileType'] = 'VFT_FONT'
        bad_json['FileSubtype'] = 'VFT2_DRV_SOUND'
        with open(bad_json_file, 'w') as bad_file:
            json.dump(bad_json, bad_file)

        check_for_err_helper(self, temp_dir, bad_json_file,
                             'Invalid FILESUBTYPE value for FILETYPE VFT_FONT: VFT2_DRV_SOUND.\nInvalid input, aborted.\n') # noqa

    def test_missing_filetype(self):
        temp_dir = tempfile.mkdtemp()
        bad_json_file = os.path.join(temp_dir, BAD_JSON_FILE_NAME + '.json')
        bad_json = copy.deepcopy(DUMMY_VALID_JSON)
        del bad_json['FileType']
        with open(bad_json_file, 'w') as bad_file:
            json.dump(bad_json, bad_file)

        check_for_err_helper(self, temp_dir, bad_json_file,
                             'Missing parameter: must have FileType if FileSubtype defined.\nInvalid input, aborted.\n')

    def test_no_stringinfo_header(self):
        temp_dir = tempfile.mkdtemp()
        bad_json_file = os.path.join(temp_dir, BAD_JSON_FILE_NAME + '.json')
        bad_json = copy.deepcopy(DUMMY_VALID_JSON)
        err_str = ''
        for key in bad_json['StringFileInfo']:
            if key == 'FileVersion':
                continue

            bad_json[key] = bad_json['StringFileInfo'][key]
            err_str += 'Invalid parameter: ' + key.upper() + '.\n'

        del bad_json['StringFileInfo']
        err_str += 'Missing required parameter: STRINGFILEINFO.\nInvalid input, aborted.\n'
        with open(bad_json_file, 'w') as bad_file:
            json.dump(bad_json, bad_file)

        check_for_err_helper(self, temp_dir, bad_json_file, err_str)

    def test_bad_input_path(self):
        check_for_err_helper(self, ".", "bad/path/to/file.json", "Could not find bad/path/to/file.json\n")

    def test_non_pe_file(self):
        temp_dir = tempfile.mkdtemp()
        bad_pe = os.path.join(temp_dir, DUMMY_JSON_FILE_NAME + '.bad')

        with open(bad_pe, 'w') as bad_file:
            json.dump(DUMMY_VALID_JSON, bad_file)

        check_for_err_helper(self, temp_dir, bad_pe,
                             "Error loading PE: 'DOS Header magic not found.'\nCannot parse, PE not loaded.\n", True)

    def test_invalid_json_format1(self):
        temp_dir = tempfile.mkdtemp()
        bad_json_file = os.path.join(temp_dir, BAD_JSON_FILE_NAME + '.json')
        bad_json = """
            "FileVersion": "1.2.3.4",
            "ProductVersion": "1.2.3.4",
            "FileFlagsMask": "0x3f",
            "FileFlags": "0x0",
            "FileOS": "VOS_NT",
            "FileType": "VFT_DRV",
            "FileSubtype": "VFT2_DRV_SYSTEM",
            "StringFileInfo": {
                "Comments": "Dummy Driver",
                "CompanyName": "Dummy compnay",
                "FileDescription": "Dummy Driver",
                "FileVersion": "1.2.3.4",
                "InternalName": "Internal Dummy Driver",
                "LegalCopyright": "(C) 2048 Dummy Driver",
                "OriginalFilename": "Dummy.sys",
                "ProductName": "Dummy Driver"
            },
            "VarFileInfo": {
                "Translation": "0x0409 0x04b0"
            }
        """

        with open(bad_json_file, 'w') as bad_file:
            bad_file.write(bad_json)

        check_for_err_helper(self, temp_dir, bad_json_file,
                             "Invalid JSON format, Extra data: line 2 column 26 (char 26)\nInvalid input, aborted.\n")

    def test_invalid_json_format2(self):
        temp_dir = tempfile.mkdtemp()
        bad_json_file = os.path.join(temp_dir, BAD_JSON_FILE_NAME + '.json')
        bad_json = """ {
            FileVersion: 1.2.3.4,
            ProductVersion: 1.2.3.4,
            FileFlagsMask: 0x3f,
            FileFlags: 0x0,
            FileOS: VOS_NT,
            FileType: VFT_DRV,
            "FileSubtype": "VFT2_DRV_SYSTEM",
            "StringFileInfo": {
                "Comments": "Dummy Driver",
                "CompanyName": "Dummy compnay",
                "FileDescription": "Dummy Driver",
                "FileVersion": "1.2.3.4",
                "InternalName": "Internal Dummy Driver",
                "LegalCopyright": "(C) 2048 Dummy Driver",
                "OriginalFilename": "Dummy.sys",
                "ProductName": "Dummy Driver"
            },
            "VarFileInfo": {
                "Translation": "0x0409 0x04b0"
            }
        }
        """

        with open(bad_json_file, 'w') as bad_file:
            bad_file.write(bad_json)

        check_for_err_helper(self, temp_dir, bad_json_file,
                             "Invalid JSON format, Expecting property name enclosed in double quotes: line 2 column 13 (char 15)\nInvalid input, aborted.\n") # noqa

    def test_invalid_json_format3(self):
        temp_dir = tempfile.mkdtemp()
        bad_json_file = os.path.join(temp_dir, BAD_JSON_FILE_NAME + '.json')
        bad_json = """ {
            "FileVersion": "1.2.3.4",
            "ProductVersion": "1.2.3.4",
            "FileFlagsMask": "0x3f",
            "FileFlags": "0x0",
            "FileOS": "VOS_NT",
            "FileType": "VFT_DRV",
            "FileSubtype": "VFT2_DRV_SYSTEM",
            "StringFileInfo": [
                "Comments": "Dummy Driver",
                "CompanyName": "Dummy compnay",
                "FileDescription": "Dummy Driver",
                "FileVersion": "1.2.3.4",
                "InternalName": "Internal Dummy Driver",
                "LegalCopyright": "(C) 2048 Dummy Driver",
                "OriginalFilename": "Dummy.sys",
                "ProductName": "Dummy Driver"
            ],
            "VarFileInfo": [
                "Translation": "0x0409 0x04b0"
            ]
        }
        """

        with open(bad_json_file, 'w') as bad_file:
            bad_file.write(bad_json)

        check_for_err_helper(self, temp_dir, bad_json_file,
                             "Invalid JSON format, Expecting ',' delimiter: line 10 column 27 (char 322)\nInvalid input, aborted.\n") # noqa

    def test_invalid_minimal_fields(self):
        temp_dir = tempfile.mkdtemp()
        bad_json_file = os.path.join(temp_dir, BAD_JSON_FILE_NAME + '.json')
        bad_json = {
            "Minimal": "True",
            "FileVersion": "1.2.3.4",
            "CompanyName": "Test Company",
            "FileType": "VFT_DRV",
        }
        with open(bad_json_file, 'w') as bad_file:
            json.dump(bad_json, bad_file)

        check_for_err_helper(self, temp_dir, bad_json_file,
                             'Invalid minimal parameter: FILETYPE.\nInvalid input, aborted.\n')

    def test_invalid_minimal_value(self):
        temp_dir = tempfile.mkdtemp()
        bad_json_file = os.path.join(temp_dir, BAD_JSON_FILE_NAME + '.json')
        bad_json = {
            "Minimal": "Yes",
            "FileVersion": "1.2.3.4",
            "CompanyName": "Test Company",
            "FileType": "VFT_DRV",
        }
        with open(bad_json_file, 'w') as bad_file:
            json.dump(bad_json, bad_file)

        check_for_err_helper(self, temp_dir, bad_json_file,
                             "Invalid value for 'Minimal', must be boolean.\nInvalid input, aborted.\n")
