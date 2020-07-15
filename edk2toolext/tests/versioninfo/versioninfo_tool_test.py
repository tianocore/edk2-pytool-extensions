## @file versioninfo_tool_test.py
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

from edk2toolext.versioninfo import versioninfo_tool

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
DUMMY_JSON_FILE_NAME = 'dummy_json_file'


class VersionInfoTest(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.temp_dir = tempfile.mkdtemp()
        cls.dummy_json = os.path.join(cls.temp_dir, DUMMY_JSON_FILE_NAME + '.json')

        with open(cls.dummy_json, 'w') as dummy_file:
            json.dump(DUMMY_VALID_JSON, dummy_file)
    
    def test_dummy_file(self):
        with open (self.dummy_json, "r") as dummy_file:
            self.assertEqual(json.loads(dummy_file.read()), DUMMY_VALID_JSON)
