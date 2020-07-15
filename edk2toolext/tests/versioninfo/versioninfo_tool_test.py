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

from io import StringIO
from edk2toolext.versioninfo import versioninfo_tool

DUMMY_EXE_FILE_NAME = 'dummy_exe'
DUMMY_EXE_SRC_NAME = 'dummy_exe_src'
DUMMY_JSON_FILE_NAME = 'dummy_json_file'
DUMMY_EXE_MAKEFILE_NAME = 'Makefile'

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

clean:
    del *.obj *.exe *.res *.rc *.json
""" % (DUMMY_EXE_SRC_NAME, DUMMY_EXE_FILE_NAME, DUMMY_EXE_FILE_NAME, DUMMY_EXE_SRC_NAME,
       DUMMY_EXE_SRC_NAME, DUMMY_EXE_FILE_NAME, DUMMY_EXE_SRC_NAME, DUMMY_EXE_FILE_NAME)

DUMMY_EXE_SOURCE = '#include <iostream>\nint main() { std::cout<<"TEST"<<std::endl; }'


class VersionInfoTest(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.temp_dir = tempfile.mkdtemp()
        cls.dummy_json = os.path.join(cls.temp_dir, DUMMY_JSON_FILE_NAME + '.json.orig')
        cls.dummy_exe_src = os.path.join(cls.temp_dir, DUMMY_EXE_SRC_NAME + '.cpp')
        cls.dummy_exe_makefile = os.path.join(cls.temp_dir, DUMMY_EXE_MAKEFILE_NAME)

        with open(cls.dummy_json, 'w') as dummy_file:
            json.dump(DUMMY_VALID_JSON, dummy_file)
        with open(cls.dummy_exe_src, 'w') as dummy_src:
            dummy_src.write(DUMMY_EXE_SOURCE)
        with open(cls.dummy_exe_makefile, 'w') as dummy_makefile:
            dummy_makefile.write(DUMMY_EXE_MAKEFILE)

    @unittest.skipUnless(sys.platform.startswith("win"), "requires Windows")
    def test_encode_decode(self):
        cli_params = [self.dummy_json, self.temp_dir]
        parsed_args = versioninfo_tool.get_cli_options(cli_params)
        versioninfo_tool.serviceRequest(parsed_args)
        cd = os.getcwd()
        os.system('cd %s && nmake rsrc && cd %s' % (self.temp_dir, cd))
        cli_params = [os.path.join(self.temp_dir, DUMMY_EXE_FILE_NAME) + '.exe', self.temp_dir, '-d']
        parsed_args = versioninfo_tool.get_cli_options(cli_params)
        versioninfo_tool.serviceRequest(parsed_args)
        with open(os.path.join(self.temp_dir, 'VERSIONINFO.json')) as generated_json:
            generatedDict = json.load(generated_json)
            self.assertTrue('Signature' in generatedDict)
            del generatedDict['Signature']
            self.assertTrue('StrucVersion' in generatedDict)
            del generatedDict['StrucVersion']
            if 'FileDateMS' in generatedDict:
                del generatedDict['FileDateMS']
            if 'FileDateLS' in generatedDict:
                del generatedDict['FileDateLS']
            self.assertEqual(generatedDict, DUMMY_VALID_JSON)
        cd = os.getcwd()
        os.system('cd %s && nmake clean && cd %s' % (self.temp_dir, cd))

    def test_missing_varinfo(self):
        bad_json_file = os.path.join(self.temp_dir, 'bad_json' + '.json')
        bad_json = copy.deepcopy(DUMMY_VALID_JSON)
        del bad_json['VarFileInfo']
        with open(bad_json_file, 'w') as bad_file:
            json.dump(bad_json, bad_file)

        cli_params = [bad_json_file, self.temp_dir]
        parsed_args = versioninfo_tool.get_cli_options(cli_params)
        with StringIO() as temp_err:
            sys.stderr = temp_err
            versioninfo_tool.serviceRequest(parsed_args)
            sys.stderr = sys.__stderr__
            self.assertFalse(os.path.isfile(os.path.join(self.temp_dir, 'VERSIONINFO.rc')))
            self.assertEqual(temp_err.getvalue(), 'ERROR: Missing required parameter: VARFILEINFO.\n')
        os.remove(bad_json_file)

    def test_missing_companyname(self):
        bad_json_file = os.path.join(self.temp_dir, 'bad_json' + '.json')
        bad_json = copy.deepcopy(DUMMY_VALID_JSON)
        del bad_json['StringFileInfo']['CompanyName']
        print(bad_json)
        with open(bad_json_file, 'w') as bad_file:
            json.dump(bad_json, bad_file)

        cli_params = [bad_json_file, self.temp_dir]
        parsed_args = versioninfo_tool.get_cli_options(cli_params)
        with StringIO() as temp_err:
            sys.stderr = temp_err
            versioninfo_tool.serviceRequest(parsed_args)
            sys.stderr = sys.__stderr__
            self.assertFalse(os.path.isfile(os.path.join(self.temp_dir, 'VERSIONINFO.rc')))
            self.assertEqual(temp_err.getvalue(), 'ERROR: Missing required StringFileInfo parameter: CompanyName.\n')
        os.remove(bad_json_file)

    def test_bad_version_format(self):
        bad_json_file = os.path.join(self.temp_dir, 'bad_json' + '.json')
        bad_json = copy.deepcopy(DUMMY_VALID_JSON)
        bad_json['ProductVersion'] = '1.234'
        print(bad_json)
        with open(bad_json_file, 'w') as bad_file:
            json.dump(bad_json, bad_file)

        cli_params = [bad_json_file, self.temp_dir]
        parsed_args = versioninfo_tool.get_cli_options(cli_params)
        with StringIO() as temp_err:
            sys.stderr = temp_err
            versioninfo_tool.serviceRequest(parsed_args)
            sys.stderr = sys.__stderr__
            self.assertFalse(os.path.isfile(os.path.join(self.temp_dir, 'VERSIONINFO.rc')))
            self.assertEqual(temp_err.getvalue(),
                             'ERROR: Invalid version string: 1.234. Version must be in form "INTEGER.INTEGER.INTEGER.INTEGER".\n') # noqa
        os.remove(bad_json_file)

    def test_inconsistent_file_version(self):
        bad_json_file = os.path.join(self.temp_dir, 'bad_json' + '.json')
        bad_json = copy.deepcopy(DUMMY_VALID_JSON)
        bad_json['FileVersion'] = '4.3.2.1'
        print(bad_json)
        with open(bad_json_file, 'w') as bad_file:
            json.dump(bad_json, bad_file)

        cli_params = [bad_json_file, self.temp_dir]
        parsed_args = versioninfo_tool.get_cli_options(cli_params)
        with StringIO() as temp_err:
            sys.stderr = temp_err
            versioninfo_tool.serviceRequest(parsed_args)
            sys.stderr = sys.__stderr__
            self.assertFalse(os.path.isfile(os.path.join(self.temp_dir, 'VERSIONINFO.rc')))
            self.assertEqual(temp_err.getvalue(),
                             'ERROR: FILEVERSION in header does not match FileVersion in StringFileInfo.\n')
        os.remove(bad_json_file)

    def test_invalid_language_code(self):
        bad_json_file = os.path.join(self.temp_dir, 'bad_json' + '.json')
        bad_json = copy.deepcopy(DUMMY_VALID_JSON)
        bad_json['VarFileInfo']['Translation'] = '"0x4009 0x04b0"'
        print(bad_json)
        with open(bad_json_file, 'w') as bad_file:
            json.dump(bad_json, bad_file)

        cli_params = [bad_json_file, self.temp_dir]
        parsed_args = versioninfo_tool.get_cli_options(cli_params)
        with StringIO() as temp_err:
            sys.stderr = temp_err
            versioninfo_tool.serviceRequest(parsed_args)
            sys.stderr = sys.__stderr__
            self.assertFalse(os.path.isfile(os.path.join(self.temp_dir, 'VERSIONINFO.rc')))
            self.assertEqual(temp_err.getvalue(), 'ERROR: Invalid language code: "0x4009".\n')
        os.remove(bad_json_file)
