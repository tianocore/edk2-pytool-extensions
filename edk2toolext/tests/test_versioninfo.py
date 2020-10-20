# @file test_versioninfo.py
# This unittest module contains test cases for the versioninfo_tool module and CLI routines.
#
##
# Copyright (C) Microsoft Corporation
#
# SPDX-License-Identifier: BSD-2-Clause-Patent
##

import os
import unittest
import tempfile
import json
import copy
import logging
import shutil
from io import StringIO
from edk2toolext.versioninfo import versioninfo_tool
from edk2toollib.utility_functions import RunCmd

DUMMY_EXE_FILE_NAME = 'dummy_exe'
DUMMY_JSON_FILE_NAME = 'dummy_json_file'
VERSIONINFO_JSON_FILE_NAME = 'VERSIONINFO'
BAD_JSON_FILE_NAME = 'bad_json'

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
        "CompanyName": "Dummy company",
        "FileDescription": "Dummy Driver",
        "FileVersion": "1.2.3.4",
        "InternalName": "Test Name",
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
    "OriginalFilename": "Test Name",
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
        "OriginalFilename": "Test Name"
    },
    "VarFileInfo": {
        "Translation": "0x0409 0x04b0"
    }
}


def check_for_err_helper(cls, temp_dir, json_input, err_msg, decode=False):
    with StringIO() as log_stream:
        log_handler = logging.StreamHandler(log_stream)
        log_handler.setLevel(logging.DEBUG)  # set the logger to get everything
        logging.getLogger().addHandler(log_handler)
        returned_error = False

        if decode:
            returned_error = not versioninfo_tool.decode_version_info_dump_json(json_input, temp_dir)
        else:
            returned_error = not versioninfo_tool.encode_version_info_dump_rc(json_input, temp_dir)

        logging.getLogger().removeHandler(log_handler)
        cls.assertFalse(os.path.isfile(os.path.join(temp_dir, 'VERSIONINFO.rc')))
        cls.assertTrue(err_msg in log_stream.getvalue())
        cls.assertTrue(returned_error)


def compared_decoded_version_info(self, json_file_path, reference):
    try:
        generated_json = open(json_file_path)
        generated_dict = json.load(generated_json)
        self.assertTrue('Signature' in generated_dict)
        del generated_dict['Signature']
        self.assertTrue('StrucVersion' in generated_dict)
        del generated_dict['StrucVersion']
        if 'FileDateMS' in generated_dict:
            del generated_dict['FileDateMS']
        if 'FileDateLS' in generated_dict:
            del generated_dict['FileDateLS']
        ref = copy.deepcopy(reference)
        if "Minimal" in ref:
            del ref["Minimal"]
        self.assertEqual(generated_dict, ref)
    except ValueError:
        self.fail()
    except IOError:
        self.fail()


class TestVersioninfo(unittest.TestCase):

    def test_encode_decode_full(self):
        temp_dir = tempfile.mkdtemp()
        # Create the EXE file
        versioned_exe_path = os.path.join(temp_dir, DUMMY_EXE_FILE_NAME) + '.exe'
        source_exe_path = os.path.join(os.path.dirname(__file__), "testdata", "versioninfo_full_exe.data")
        shutil.copyfile(source_exe_path, versioned_exe_path)
        # Create the parameters that will go to the service request function
        version_info_output_path = os.path.join(temp_dir, VERSIONINFO_JSON_FILE_NAME + '.json')
        versioninfo_tool.decode_version_info_dump_json(versioned_exe_path, version_info_output_path)

        # then we compare to make sure it matches what it should be
        compared_decoded_version_info(self, version_info_output_path, DUMMY_VALID_JSON)

    def test_encode_decode_minimal(self):
        temp_dir = tempfile.mkdtemp()
        # Create the EXE file
        versioned_exe_path = os.path.join(temp_dir, DUMMY_EXE_FILE_NAME) + '.exe'
        source_exe_path = os.path.join(os.path.dirname(__file__), "testdata", "versioninfo_minimal_exe.data")
        shutil.copyfile(source_exe_path, versioned_exe_path)
        # Create the parameters that will go to the service request function
        version_info_output_path = os.path.join(temp_dir, VERSIONINFO_JSON_FILE_NAME + '.json')
        versioninfo_tool.decode_version_info_dump_json(versioned_exe_path, version_info_output_path)

        # then we compare to make sure it matches what it should be
        compared_decoded_version_info(self, version_info_output_path, DUMMY_MINIMAL_DECODED)

    def test_encode_minimal(self):
        temp_dir = tempfile.mkdtemp()
        # Create the parameters that will go to the service request function
        version_info_input_path = os.path.join(temp_dir, "in.json")
        with open(version_info_input_path, "w") as f:
            json.dump(DUMMY_MINIMAL_JSON, f)
        obj = versioninfo_tool.encode_version_info(version_info_input_path)
        self.assertTrue(obj.validate_minimal())

    def test_missing_varinfo(self):
        temp_dir = tempfile.mkdtemp()
        bad_json_file = os.path.join(temp_dir, BAD_JSON_FILE_NAME + '.json')
        bad_json = copy.deepcopy(DUMMY_VALID_JSON)
        del bad_json['VarFileInfo']
        with open(bad_json_file, 'w') as bad_file:
            json.dump(bad_json, bad_file)

        check_for_err_helper(self, temp_dir, bad_json_file, 'Missing required parameter: VARFILEINFO')

    def test_missing_translation(self):
        temp_dir = tempfile.mkdtemp()
        bad_json_file = os.path.join(temp_dir, BAD_JSON_FILE_NAME + '.json')
        bad_json = copy.deepcopy(DUMMY_VALID_JSON)
        del bad_json['VarFileInfo']['Translation']
        with open(bad_json_file, 'w') as bad_file:
            json.dump(bad_json, bad_file)

        check_for_err_helper(self, temp_dir, bad_json_file, 'Missing required parameter in VarFileInfo: Translation')

    def test_invalid_varfileinfo(self):
        temp_dir = tempfile.mkdtemp()
        bad_json_file = os.path.join(temp_dir, BAD_JSON_FILE_NAME + '.json')
        bad_json = copy.deepcopy(DUMMY_VALID_JSON)
        bad_json['VarFileInfo']['FileVersion'] = "1.2.1.2"
        with open(bad_json_file, 'w') as bad_file:
            json.dump(bad_json, bad_file)

        check_for_err_helper(self, temp_dir, bad_json_file, 'Invalid VarFileInfo parameter: FileVersion')

    def test_missing_companyname(self):
        temp_dir = tempfile.mkdtemp()
        bad_json_file = os.path.join(temp_dir, BAD_JSON_FILE_NAME + '.json')
        bad_json = copy.deepcopy(DUMMY_VALID_JSON)
        del bad_json['StringFileInfo']['CompanyName']
        with open(bad_json_file, 'w') as bad_file:
            json.dump(bad_json, bad_file)

        check_for_err_helper(self, temp_dir, bad_json_file, 'Missing required StringFileInfo parameter: CompanyName')

    def test_version_overflow(self):
        temp_dir = tempfile.mkdtemp()
        bad_json_file = os.path.join(temp_dir, BAD_JSON_FILE_NAME + '.json')
        bad_json = copy.deepcopy(DUMMY_VALID_JSON)
        bad_json['ProductVersion'] = '65536.0.0.0'
        with open(bad_json_file, 'w') as bad_file:
            json.dump(bad_json, bad_file)

        check_for_err_helper(self, temp_dir, bad_json_file, 'Integer overflow in version string')

    def test_invalid_version(self):
        temp_dir = tempfile.mkdtemp()
        bad_json_file = os.path.join(temp_dir, BAD_JSON_FILE_NAME + '.json')
        bad_json = copy.deepcopy(DUMMY_VALID_JSON)
        bad_json['ProductVersion'] = 'Version 1.0.1.0'
        with open(bad_json_file, 'w') as bad_file:
            json.dump(bad_json, bad_file)

        check_for_err_helper(self, temp_dir, bad_json_file, 'Version must be in form " INTEGER.INTEGER.INTEGER.INTEGER"')  # noqa

    def test_bad_version_format(self):
        temp_dir = tempfile.mkdtemp()
        bad_json_file = os.path.join(temp_dir, BAD_JSON_FILE_NAME + '.json')
        bad_json = copy.deepcopy(DUMMY_VALID_JSON)
        bad_json['ProductVersion'] = '1.234'
        with open(bad_json_file, 'w') as bad_file:
            json.dump(bad_json, bad_file)

        check_for_err_helper(self, temp_dir, bad_json_file, 'Version must be in form "INTEGER.INTEGER.INTEGER.INTEGER"')  # noqa

    def test_invalid_language_code_value(self):
        temp_dir = tempfile.mkdtemp()
        bad_json_file = os.path.join(temp_dir, BAD_JSON_FILE_NAME + '.json')
        bad_json = copy.deepcopy(DUMMY_VALID_JSON)
        bad_json['VarFileInfo']['Translation'] = '"0x0009 0x04b0"'
        with open(bad_json_file, 'w') as bad_file:
            json.dump(bad_json, bad_file)

        check_for_err_helper(self, temp_dir, bad_json_file,
                             f"Invalid language code: {bad_json['VarFileInfo']['Translation']}")

    def test_invalid_language_code_string(self):
        temp_dir = tempfile.mkdtemp()
        bad_json_file = os.path.join(temp_dir, BAD_JSON_FILE_NAME + '.json')
        bad_json = copy.deepcopy(DUMMY_VALID_JSON)
        bad_json['VarFileInfo']['Translation'] = '"utf-8 US"'
        with open(bad_json_file, 'w') as bad_file:
            json.dump(bad_json, bad_file)

        check_for_err_helper(self, temp_dir, bad_json_file,
                             f"Invalid language code: {bad_json['VarFileInfo']['Translation']}")

    def test_invalid_language_code_format(self):
        temp_dir = tempfile.mkdtemp()
        bad_json_file = os.path.join(temp_dir, BAD_JSON_FILE_NAME + '.json')
        bad_json = copy.deepcopy(DUMMY_VALID_JSON)
        bad_json['VarFileInfo']['Translation'] = '"0x400904b0"'
        with open(bad_json_file, 'w') as bad_file:
            json.dump(bad_json, bad_file)

        check_for_err_helper(self, temp_dir, bad_json_file, 'Translation field must contain 2 space delimited hexidecimal bytes')  # noqa

    def test_invalid_language_code_no_hex(self):
        temp_dir = tempfile.mkdtemp()
        bad_json_file = os.path.join(temp_dir, BAD_JSON_FILE_NAME + '.json')
        bad_json = copy.deepcopy(DUMMY_VALID_JSON)
        bad_json['VarFileInfo']['Translation'] = '"4009 04b0"'
        with open(bad_json_file, 'w') as bad_file:
            json.dump(bad_json, bad_file)

        check_for_err_helper(self, temp_dir, bad_json_file, 'Invalid language code: '
                             + bad_json['VarFileInfo']['Translation'])

    def test_invalid_fileos_hex(self):
        temp_dir = tempfile.mkdtemp()
        bad_json_file = os.path.join(temp_dir, BAD_JSON_FILE_NAME + '.json')
        bad_json = copy.deepcopy(DUMMY_VALID_JSON)
        bad_json['FileOS'] = '0x12391'
        with open(bad_json_file, 'w') as bad_file:
            json.dump(bad_json, bad_file)

        check_for_err_helper(self, temp_dir, bad_json_file, 'Invalid FILEOS value: ' + bad_json['FileOS'])

    def test_invalid_fileos_string(self):
        temp_dir = tempfile.mkdtemp()
        bad_json_file = os.path.join(temp_dir, BAD_JSON_FILE_NAME + '.json')
        bad_json = copy.deepcopy(DUMMY_VALID_JSON)
        bad_json['FileOS'] = 'INVALID'
        with open(bad_json_file, 'w') as bad_file:
            json.dump(bad_json, bad_file)

        check_for_err_helper(self, temp_dir, bad_json_file, 'Invalid FILEOS value: ' + bad_json['FileOS'])

    def test_invalid_filetype_hex(self):
        temp_dir = tempfile.mkdtemp()
        bad_json_file = os.path.join(temp_dir, BAD_JSON_FILE_NAME + '.json')
        bad_json = copy.deepcopy(DUMMY_VALID_JSON)
        bad_json['FileType'] = '0x12391'
        with open(bad_json_file, 'w') as bad_file:
            json.dump(bad_json, bad_file)

        check_for_err_helper(self, temp_dir, bad_json_file, 'Invalid FILESUBTYPE value for FILETYPE ' + bad_json['FileType'])  # noqa

    def test_invalid_filetype_string(self):
        temp_dir = tempfile.mkdtemp()
        bad_json_file = os.path.join(temp_dir, BAD_JSON_FILE_NAME + '.json')
        bad_json = copy.deepcopy(DUMMY_VALID_JSON)
        bad_json['FileType'] = 'INVALID'
        with open(bad_json_file, 'w') as bad_file:
            json.dump(bad_json, bad_file)

        check_for_err_helper(self, temp_dir, bad_json_file, 'Invalid FILESUBTYPE value for FILETYPE ' + bad_json['FileType'])  # noqa

    def test_invalid_filesubtype_drv(self):
        temp_dir = tempfile.mkdtemp()
        bad_json_file = os.path.join(temp_dir, BAD_JSON_FILE_NAME + '.json')
        bad_json = copy.deepcopy(DUMMY_VALID_JSON)
        bad_json['FileType'] = 'VFT_DRV'
        bad_json['FileSubtype'] = 'VFT2_FONT_RASTER'
        with open(bad_json_file, 'w') as bad_file:
            json.dump(bad_json, bad_file)

        check_for_err_helper(self, temp_dir, bad_json_file, 'Invalid FILESUBTYPE value for FILETYPE VFT_DRV: VFT2_FONT_RASTER')  # noqa

    def test_invalid_filesubtype_font(self):
        temp_dir = tempfile.mkdtemp()
        bad_json_file = os.path.join(temp_dir, BAD_JSON_FILE_NAME + '.json')
        bad_json = copy.deepcopy(DUMMY_VALID_JSON)
        bad_json['FileType'] = 'VFT_FONT'
        bad_json['FileSubtype'] = 'VFT2_DRV_SOUND'
        with open(bad_json_file, 'w') as bad_file:
            json.dump(bad_json, bad_file)

        check_for_err_helper(self, temp_dir, bad_json_file, 'Invalid FILESUBTYPE value for FILETYPE VFT_FONT: VFT2_DRV_SOUND')  # noqa

    def test_missing_filetype(self):
        temp_dir = tempfile.mkdtemp()
        bad_json_file = os.path.join(temp_dir, BAD_JSON_FILE_NAME + '.json')
        bad_json = copy.deepcopy(DUMMY_VALID_JSON)
        del bad_json['FileType']
        with open(bad_json_file, 'w') as bad_file:
            json.dump(bad_json, bad_file)

        check_for_err_helper(self, temp_dir, bad_json_file,
                             'Missing parameter: must have FileType if FileSubtype defined')

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
        err_str += 'Missing required parameter: STRINGFILEINFO'
        with open(bad_json_file, 'w') as bad_file:
            json.dump(bad_json, bad_file)

        check_for_err_helper(self, temp_dir, bad_json_file, err_str)

    def test_bad_input_path(self):
        ''' check to make sure we throw an exception '''
        try:
            check_for_err_helper(self, ".", "bad/path/to/file.json", "Could not find bad/path/to/file.json\n")
            self.fail("We shouldn't have found the file")
        except FileNotFoundError:
            pass

    def test_command_line_interface(self):
        ''' makes sure the command line interface is working correctly '''
        ret = RunCmd('versioninfo_tool', '-h', logging_level=logging.ERROR)
        self.assertEqual(ret, 0)

    def test_non_pe_file(self):
        temp_dir = tempfile.mkdtemp()
        bad_pe = os.path.join(temp_dir, DUMMY_JSON_FILE_NAME + '.bad')

        with open(bad_pe, 'w') as bad_file:
            json.dump(DUMMY_VALID_JSON, bad_file)

        check_for_err_helper(self, temp_dir, bad_pe, "DOS Header magic not found", True)

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

        check_for_err_helper(self, temp_dir, bad_json_file, "Invalid JSON format, Extra data")

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

        check_for_err_helper(self, temp_dir, bad_json_file, "Invalid JSON format, Expecting property name enclosed in double quotes")  # noqa

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

        check_for_err_helper(self, temp_dir, bad_json_file, "Invalid JSON format, Expecting ',' delimiter")  # noqa

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

        check_for_err_helper(self, temp_dir, bad_json_file, 'Invalid minimal parameter: FILETYPE')

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

        check_for_err_helper(self, temp_dir, bad_json_file, "Invalid value for 'Minimal', must be boolean.")
