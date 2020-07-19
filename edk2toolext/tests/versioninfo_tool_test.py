## @file versioninfo_tool_test.py
# This unittest module contains test cases for the versioninfo_tool module and CLI routines.
#
##
# Copyright (C) Microsoft Corporation
#
# SPDX-License-Identifier: BSD-2-Clause-Patent
##


import os
import sys
import unittest
import tempfile
import json
import copy
import logging
import edk2toollib.windows.locate_tools as locate_tools

from io import StringIO
from edk2toolext.versioninfo import versioninfo_tool
from edk2toolext.environment import shell_environment

DUMMY_EXE_FILE_NAME = 'dummy_exe'
DUMMY_EXE_SRC_NAME = 'dummy_exe_src'
DUMMY_JSON_FILE_NAME = 'dummy_json_file'
DUMMY_EXE_MAKEFILE_NAME = 'Makefile'
VERSIONINFO_JSON_FILE_NAME = 'VERSIONINFO'
BAD_JSON_FILE_NAME = 'bad_json'

DUMMY_VALID_JSON = {
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
DUMMY_EXE_MAKEFILE = """
norsrc: %s.cpp
    CL /Fe".\\%s.exe" /Fo".\\%s.obj"  /EHsc %s.cpp

rsrc: %s.cpp
    CL /Fo"%s.obj"  /EHsc /c %s.cpp
    RC VERSIONINFO.rc
    LINK %s.obj VERSIONINFO.res
""" % (DUMMY_EXE_SRC_NAME, DUMMY_EXE_FILE_NAME, DUMMY_EXE_FILE_NAME, DUMMY_EXE_SRC_NAME,
       DUMMY_EXE_SRC_NAME, DUMMY_EXE_FILE_NAME, DUMMY_EXE_SRC_NAME, DUMMY_EXE_FILE_NAME)

DUMMY_EXE_SOURCE = '#include <iostream>\nint main() { std::cout<<"TEST"<<std::endl; }'

VS2019_INTERESTING_KEYS = ["ExtensionSdkDir", "INCLUDE", "LIB", "LIBPATH", "UniversalCRTSdkDir",
                           "UCRTVersion", "WindowsLibPath", "WindowsSdkBinPath", "WindowsSdkDir",
                           "WindowsSdkVerBinPath", "WindowsSDKVersion", "VCToolsInstallDir", "Path"]


def check_for_err_helper(cls, temp_dir, json_input, err_msg):
    cli_params = [json_input, temp_dir]
    parsed_args = versioninfo_tool.get_cli_options(cli_params)
    with StringIO() as log_stream:
        log_handler = logging.StreamHandler(log_stream)
        logging.getLogger().addHandler(log_handler)
        versioninfo_tool.service_request(parsed_args)
        logging.getLogger().removeHandler(log_handler)
        cls.assertFalse(os.path.isfile(os.path.join(temp_dir, 'VERSIONINFO.rc')))
        cls.assertEqual(log_stream.getvalue(), err_msg + "Invalid input, aborted.\n")
    os.remove(json_input)


class VersionInfoTest(unittest.TestCase):
    # @classmethod
    # def setUpClass(cls):
    #     cls.temp_dir = tempfile.mkdtemp()
    #     cls.dummy_json = os.path.join(cls.temp_dir, DUMMY_JSON_FILE_NAME + '.json.orig')
    #     cls.dummy_exe_src = os.path.join(cls.temp_dir, DUMMY_EXE_SRC_NAME + '.cpp')
    #     cls.dummy_exe_makefile = os.path.join(cls.temp_dir, DUMMY_EXE_MAKEFILE_NAME)

    #     with open(cls.dummy_json, 'w') as dummy_file:
    #         json.dump(DUMMY_VALID_JSON, dummy_file)
    #     with open(cls.dummy_exe_src, 'w') as dummy_src:
    #         dummy_src.write(DUMMY_EXE_SOURCE)
    #     with open(cls.dummy_exe_makefile, 'w') as dummy_makefile:
    #         dummy_makefile.write(DUMMY_EXE_MAKEFILE)

    @unittest.skipUnless(sys.platform.startswith("win"), "requires Windows")
    def test_encode_decode_windows(self):
        # Find VS build tools
        (rc, vc_install_path) = locate_tools.FindWithVsWhere(vs_version="vs2019")
        if rc != 0 or vc_install_path is None or not os.path.exists(vc_install_path):
            logging.fatal("Cannot locate VS build tools install path")
            self.fail()

        vc_ver_path = os.path.join(vc_install_path, "VC", "Tools", "MSVC")
        if not os.path.isdir(vc_ver_path):
            logging.fatal("Cannot locate VS build tools directory")
            self.fail()

        vc_ver = os.listdir(vc_ver_path)[-1].strip()
        if vc_ver is None:
            logging.fatal("Cannot locate VS build tools version")
            self.fail()

        # Set VS env variables
        vs2019_prefix = os.path.join(vc_install_path, "VC", "Tools", "MSVC", vc_ver)
        vs2019_prefix += os.path.sep
        shell_environment.GetEnvironment().set_shell_var("VS2019_PREFIX", vs2019_prefix)
        shell_environment.GetEnvironment().set_shell_var("VS2019_HOST", "x64")
        shell_env = shell_environment.GetEnvironment()
        vs_vars = locate_tools.QueryVcVariables(VS2019_INTERESTING_KEYS, "x64", vs_version="vs2019")
        for (k, v) in vs_vars.items():
            shell_env.set_shell_var(k, v)

        temp_dir = tempfile.mkdtemp()
        dummy_json = os.path.join(temp_dir, DUMMY_JSON_FILE_NAME + '.json.orig')
        dummy_exe_src = os.path.join(temp_dir, DUMMY_EXE_SRC_NAME + '.cpp')
        dummy_exe_makefile = os.path.join(temp_dir, DUMMY_EXE_MAKEFILE_NAME)

        with open(dummy_json, 'w') as dummy_file:
            json.dump(DUMMY_VALID_JSON, dummy_file)
        with open(dummy_exe_src, 'w') as dummy_src:
            dummy_src.write(DUMMY_EXE_SOURCE)
        with open(dummy_exe_makefile, 'w') as dummy_makefile:
            dummy_makefile.write(DUMMY_EXE_MAKEFILE)

        cli_params = [dummy_json, temp_dir]
        parsed_args = versioninfo_tool.get_cli_options(cli_params)
        versioninfo_tool.service_request(parsed_args)
        cd = os.getcwd()
        os.system('cd %s && nmake rsrc && cd %s' % (temp_dir, cd))

        cli_params = [os.path.join(temp_dir, DUMMY_EXE_FILE_NAME) + '.exe', temp_dir, '-d']
        parsed_args = versioninfo_tool.get_cli_options(cli_params)
        versioninfo_tool.service_request(parsed_args)
        try:
            with open(os.path.join(temp_dir, VERSIONINFO_JSON_FILE_NAME + '.json')) as generated_json:
                try:
                    generated_dict = json.load(generated_json)
                except ValueError:
                    self.fail()

                self.assertTrue('Signature' in generated_dict)
                del generated_dict['Signature']
                self.assertTrue('StrucVersion' in generated_dict)
                del generated_dict['StrucVersion']
                if 'FileDateMS' in generated_dict:
                    del generated_dict['FileDateMS']
                if 'FileDateLS' in generated_dict:
                    del generated_dict['FileDateLS']
                self.assertEqual(generated_dict, DUMMY_VALID_JSON)
        except IOError:
            self.fail()

    def test_missing_varinfo(self):
        temp_dir = tempfile.mkdtemp()
        bad_json_file = os.path.join(temp_dir, BAD_JSON_FILE_NAME + '.json')
        bad_json = copy.deepcopy(DUMMY_VALID_JSON)
        del bad_json['VarFileInfo']
        with open(bad_json_file, 'w') as bad_file:
            json.dump(bad_json, bad_file)

        check_for_err_helper(self, temp_dir, bad_json_file, 'Missing required parameter: VARFILEINFO.\n')

    def test_missing_companyname(self):
        temp_dir = tempfile.mkdtemp()
        bad_json_file = os.path.join(temp_dir, BAD_JSON_FILE_NAME + '.json')
        bad_json = copy.deepcopy(DUMMY_VALID_JSON)
        del bad_json['StringFileInfo']['CompanyName']
        with open(bad_json_file, 'w') as bad_file:
            json.dump(bad_json, bad_file)

        check_for_err_helper(self, temp_dir, bad_json_file, 'Missing required StringFileInfo parameter: CompanyName.\n')

    def test_bad_version_format(self):
        temp_dir = tempfile.mkdtemp()
        bad_json_file = os.path.join(temp_dir, BAD_JSON_FILE_NAME + '.json')
        bad_json = copy.deepcopy(DUMMY_VALID_JSON)
        bad_json['ProductVersion'] = '1.234'
        with open(bad_json_file, 'w') as bad_file:
            json.dump(bad_json, bad_file)

        check_for_err_helper(self, temp_dir, bad_json_file,
                             'Invalid version string: 1.234. Version must be in form "INTEGER.INTEGER.INTEGER.INTEGER".\n') # noqa

    def test_inconsistent_file_version(self):
        temp_dir = tempfile.mkdtemp()
        bad_json_file = os.path.join(temp_dir, BAD_JSON_FILE_NAME + '.json')
        bad_json = copy.deepcopy(DUMMY_VALID_JSON)
        bad_json['FileVersion'] = '4.3.2.1'
        with open(bad_json_file, 'w') as bad_file:
            json.dump(bad_json, bad_file)

        check_for_err_helper(self, temp_dir, bad_json_file,
                             'FILEVERSION in header does not match FileVersion in StringFileInfo.\n')

    def test_invalid_language_code(self):
        temp_dir = tempfile.mkdtemp()
        bad_json_file = os.path.join(temp_dir, BAD_JSON_FILE_NAME + '.json')
        bad_json = copy.deepcopy(DUMMY_VALID_JSON)
        bad_json['VarFileInfo']['Translation'] = '"0x4009 0x04b0"'
        with open(bad_json_file, 'w') as bad_file:
            json.dump(bad_json, bad_file)

        check_for_err_helper(self, temp_dir, bad_json_file, 'Invalid language code: "0x4009".\n')
