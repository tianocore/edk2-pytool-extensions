## @file versioninfo_helper.py
# This module contains helper functions for creating VERSIONINFO resources
# from json files, along with the functions to output version information from
# PE/PE+ files.
#
##
# Copyright (C) Microsoft Corporation
#
# SPDX-License-Identifier: BSD-2-Clause-Patent
##

import pefile
import sys
import json
import copy
import os
import logging

# String values for PE/PE+ header versioning metadata
FILE_OS_STRINGS = {
    0x00010000: "VOS_DOS",
    0x00040000: "VOS_NT",
    0x00000001: "VOS__WINDOWS16",
    0x00000004: "VOS__WINDOWS32",
    0x00020000: "VOS_OS216",
    0x00030000: "VOS_OS232",
    0x00000002: "VOS__PM16",
    0x00000003: "VOS__PM32",
    0x00000000: "VOS_UNKNOWN",
    0x00010001: "VOS_DOS_WINDOWS16",
    0x00010004: "VOS_DOS_WINDOWS32",
    0x00040004: "VOS_NT_WINDOWS32",
    0x00020002: "VOS_OS216_PM16",
    0x00030003: "VOS_OS232_PM32"
}

FILE_TYPE_STRINGS = {
    0x00000001: "VFT_APP",
    0x00000002: "VFT_DLL",
    0x00000003: "VFT_DRV",
    0x00000004: "VFT_FONT",
    0x00000007: "VFT_STATIC_LIB",
    0x00000000: "VFT_UNKNOWN",
    0x00000005: "VFT_VXD"
}

FILE_SUBTYPE_NOFONT_STRINGS = {
    0x0000000A: "VFT2_DRV_COMM",
    0x00000004: "VFT2_DRV_DISPLAY",
    0x00000008: "VFT2_DRV_INSTALLABLE",
    0x00000002: "VFT2_DRV_KEYBOARD",
    0x00000003: "VFT2_DRV_LANGUAGE",
    0x00000005: "VFT2_DRV_MOUSE",
    0x00000006: "VFT2_DRV_NETWORK",
    0x00000001: "VFT2_DRV_PRINTER",
    0x00000009: "VFT2_DRV_SOUND",
    0x00000007: "VFT2_DRV_SYSTEM",
    0x0000000C: "VFT2_DRV_VERSIONED_PRINTER",
    0x00000000: "VFT2_UNKNOWN"
}

FILE_SUBTYPE_FONT_STRINGS = {
    0x00000001: "VFT2_FONT_RASTER",
    0x00000003: "VFT2_FONT_TRUETYPE",
    0x00000002: "VFT2_FONT_VECTOR",
    0x00000000: "VFT2_UNKNOWN"
}

VALID_SIGNATURE = 0xfeef04bd

# PE/PE+ field names
SIGNATURE_STR = "Signature"
STRUC_VERSION_STR = "StrucVersion"
FILE_VERSION_MS_STR = "FileVersionMS"
FILE_VERSION_LS_STR = "FileVersionLS"
FILE_VERSION_STR = "FileVersion"
PRODUCT_VERSION_MS_STR = "ProductVersionMS"
PRODUCT_VERSION_LS_STR = "ProductVersionLS"
PRODUCT_VERSION_STR = "ProductVersion"
FILE_FLAG_MASK_STR = "FileFlagsMask"
FILE_FLAGS_STR = "FileFlags"
FILE_TYPE_STR = "FileType"
FILE_SUBTYPE_STR = "FileSubtype"
FILE_OS_STR = "FileOS"
FILE_DATE_MS_STR = "FileDateMS"
FILE_DATE_LS_STR = "FileDateLS"
FILE_DATE_STR = "FileDate"
VFT_FONT_STR = "VFT_FONT"
TRANSLATION_STR = "Translation"
RSRC_STR = ".rsrc"
STRING_FILE_INFO_STR = "StringFileInfo"
VAR_FILE_INFO_STR = "VarFileInfo"

# Key values for interacting with pefile objects
PE_ENCODING = "utf-8"
PE_STRUCT_STR = "Structure"
PE_VALUE_STR = "Value"
BEGIN_STR = "BEGIN"
END_STR = "END"
BLOCK_STR = "BLOCK"
VALUE_STR = "VALUE"

# Validation requirements
VERSIONFILE_REQUIRED_FIELDS = {
    FILE_VERSION_STR,
    PRODUCT_VERSION_STR,
    FILE_FLAG_MASK_STR,
    FILE_FLAGS_STR,
    FILE_OS_STR,
    FILE_TYPE_STR,
    FILE_SUBTYPE_STR,
    STRING_FILE_INFO_STR,
    VAR_FILE_INFO_STR
}

VERSIONFILE_ALLOWED_FIELDS = {
    FILE_VERSION_STR,
    PRODUCT_VERSION_STR,
    FILE_FLAG_MASK_STR,
    FILE_FLAGS_STR,
    FILE_OS_STR,
    FILE_TYPE_STR,
    FILE_SUBTYPE_STR,
    STRING_FILE_INFO_STR,
    VAR_FILE_INFO_STR,
    SIGNATURE_STR,
    STRUC_VERSION_STR,
    FILE_DATE_STR,
    FILE_DATE_MS_STR,
    FILE_DATE_LS_STR
}

COMPANY_NAME_STR = "CompanyName"
PRODUCT_NAME_STR = "ProductName"

STRING_FILE_INFO_REQUIRED_FIELDS = {
    COMPANY_NAME_STR,
    PRODUCT_NAME_STR,
    FILE_VERSION_STR
}

STRING_FILE_INFO_ALLOWED_FIELDS = {
    "Comments",
    "CompanyName",
    "FileDescription",
    "FileVersion",
    "InternalName",
    "LegalCopyright",
    "LegalTrademarks",
    "OriginalFilename",
    "PrivateBuild",
    "ProductName",
    "ProductVersion",
    "SpecialBuild"
}

VALID_FILE_OS_VALUES = {
    "VOS_UNKNOWN",
    "VOS_DOS",
    "VOS_NT",
    "VOS__WINDOWS16",
    "VOS__WINDOWS32",
    "VOS_DOS_WINDOWS16",
    "VOS_DOS_WINDOWS32",
    "VOS_NT_WINDOWS32"
}

VALID_FILE_TYPE_VALUES = {
    "VFT_APP",
    "VFT_DLL",
    "VFT_DRV",
    "VFT_FONT",
    "VFT_STATIC_LIB",
    "VFT_UNKNOWN",
    "VFT_VXD"
}

VALID_SUBTYPE_VFT_DRV = {
    "VFT2_UNKNOWN",
    "VFT2_DRV_COMM",
    "VFT2_DRV_PRINTER",
    "VFT2_DRV_KEYBOARD",
    "VFT2_DRV_LANGUAGE",
    "VFT2_DRV_DISPLAY",
    "VFT2_DRV_MOUSE",
    "VFT2_DRV_NETWORK",
    "VFT2_DRV_SYSTEM",
    "VFT2_DRV_INSTALLABLE",
    "VFT2_DRV_SOUND",
    "VFT2_DRV_VERSIONED_PRINTER"
}

VALID_SUBTYPE_VFT_FONT = {
    "VFT2_UNKNOWN",
    "VFT2_FONT_RASTER",
    "VFT2_FONT_VECTOR",
    "VFT2_FONT_TRUETYPE"
}

VALID_LANG_ID = {
    0x0401, 0x0402,
    0x0403, 0x0404,
    0x0405, 0x0406,
    0x0407, 0x0408,
    0x0409, 0x040A,
    0x040B, 0x040C,
    0x040D, 0x040E,
    0x040F, 0x0410,
    0x0411, 0x0412,
    0x0413, 0x0414,
    0x0415, 0x0416,
    0x0417, 0x0418,
    0x0419, 0x041A,
    0x041B, 0x041C,
    0x041D, 0x041E,
    0x041F, 0x0420,
    0x0421, 0x0804,
    0x0807, 0x0809,
    0x080A, 0x080C,
    0x0C0C, 0x100C,
    0x0816, 0x081A,
    0x0810, 0x0813,
    0x0814
}

VALID_CHARSET_ID = {
    0x0000, 0x03A4,
    0x03B5, 0x03B6,
    0x04B0, 0x04E2,
    0x04E3, 0x04E4,
    0x04E5, 0x04E6,
    0x04E7, 0x04E8
}


class PEObject(object):
    pe = None

    # Takes filepath to PE/PE+ file to parse
    def __init__(self, filepath):
        try:
            self.pe = pefile.PE(filepath)
        except FileNotFoundError:
            logging.error("Could not find " + filepath)

    # Private, given a 32 bit word, converts word into a string of 2 16 bit integers
    # seperated by '.' to conform to version string format.
    def _hex_to_version_str(self, val):
        return str(((val & ~0) >> 16) & 0xffff) + "." + str(val & 0xffff)

    # Private, converts hex version information to string according to Msft spec
    def _populate_entry(self, key, val, dict):
        if key == FILE_OS_STR:
            if val in FILE_OS_STRINGS:
                dict[key] = FILE_OS_STRINGS[val]
                return
        elif key == FILE_TYPE_STR:
            if val in FILE_TYPE_STRINGS:
                dict[key] = FILE_TYPE_STRINGS[val]
                return
        elif key == FILE_VERSION_MS_STR:
            dict[FILE_VERSION_STR] = self._hex_to_version_str(val)
            return
        elif key == FILE_VERSION_LS_STR:
            dict[FILE_VERSION_STR] += "." + self._hex_to_version_str(val)
            return
        elif key == PRODUCT_VERSION_MS_STR:
            dict[PRODUCT_VERSION_STR] = self._hex_to_version_str(val)
            return
        elif key == PRODUCT_VERSION_LS_STR:
            dict[PRODUCT_VERSION_STR] += "." + self._hex_to_version_str(val)
            return
        dict[key] = hex(val)

    # Returns true if PE object contains .rsrc section, false otherwise
    def contains_rsrc(self):
        if not self.pe:
            logging.fatal("Cannot parse, PE not loaded")
            return

        for section in self.pe.sections:
            if section.Name.decode(PE_ENCODING).replace("\x00", "") == RSRC_STR:
                return True
        return False

    # Parses PE/PE+ loaded into PEObject and returns dictionary contaning metadata from header and .rsrc section
    def get_version_dict(self):
        if not self.pe:
            logging.fatal("Cannot parse, PE not loaded")
            return

        result = {}
        try:
            vs_fixedfileinfo_dict = self.pe.VS_FIXEDFILEINFO[0].dump_dict()
            for key in vs_fixedfileinfo_dict.keys():
                # Skip sections that have dependencies
                if key == PE_STRUCT_STR or \
                   key == FILE_SUBTYPE_STR or \
                   key == FILE_VERSION_LS_STR or \
                   key == PRODUCT_VERSION_LS_STR or \
                   key == FILE_DATE_LS_STR:
                    continue

                self._populate_entry(key, vs_fixedfileinfo_dict[key][PE_VALUE_STR], result)

            # Resolve dependent fields
            if FILE_VERSION_MS_STR in vs_fixedfileinfo_dict.keys() and \
               FILE_VERSION_LS_STR in vs_fixedfileinfo_dict.keys():
                self._populate_entry(FILE_VERSION_LS_STR,
                                     vs_fixedfileinfo_dict[FILE_VERSION_LS_STR][PE_VALUE_STR], result)

            if PRODUCT_VERSION_MS_STR in vs_fixedfileinfo_dict.keys() and \
               PRODUCT_VERSION_LS_STR in vs_fixedfileinfo_dict.keys():
                self._populate_entry(PRODUCT_VERSION_LS_STR,
                                       vs_fixedfileinfo_dict[PRODUCT_VERSION_LS_STR][PE_VALUE_STR], result)

            if FILE_DATE_MS_STR in vs_fixedfileinfo_dict.keys() and \
               FILE_DATE_LS_STR in vs_fixedfileinfo_dict.keys():
                self._populate_entry(FILE_DATE_LS_STR,
                                       vs_fixedfileinfo_dict[FILE_DATE_LS_STR][PE_VALUE_STR], result)

            if FILE_SUBTYPE_STR in vs_fixedfileinfo_dict.keys():
                file_subtype = vs_fixedfileinfo_dict[FILE_SUBTYPE_STR][PE_VALUE_STR]
                if FILE_TYPE_STR in result and result[FILE_TYPE_STR] == VFT_FONT_STR:
                    if file_subtype in FILE_SUBTYPE_FONT_STRINGS:
                        result[FILE_SUBTYPE_STR] = FILE_SUBTYPE_FONT_STRINGS[file_subtype]
                    else:
                        result[FILE_SUBTYPE_STR] = file_subtype
                else:
                    if file_subtype in FILE_SUBTYPE_NOFONT_STRINGS.keys():
                        result[FILE_SUBTYPE_STR] = FILE_SUBTYPE_NOFONT_STRINGS[file_subtype]
                    else:
                        result[FILE_SUBTYPE_STR] = file_subtype

        except AttributeError:
            logging.warning("Could not find VS_FIXEDFILEINFO.")

        if self.contains_rsrc():
            try:
                for fileinfo in self.pe.FileInfo:
                    for entry in fileinfo:
                        if entry.Key.decode(PE_ENCODING).replace("\x00", "") == STRING_FILE_INFO_STR:
                            stringfileinfo_dict = {}
                            for strTable in entry.StringTable:
                                for item in strTable.entries.items():
                                    stringfileinfo_dict[item[0].decode(PE_ENCODING)] = item[1].decode(PE_ENCODING)
                            result[STRING_FILE_INFO_STR] = stringfileinfo_dict
                        elif entry.Key.decode(PE_ENCODING).replace("\x00", "") == VAR_FILE_INFO_STR:
                            varfileinfo_dict = {}
                            for var in entry.Var:
                                for item in var.entry.items():
                                    varfileinfo_dict[item[0].decode(PE_ENCODING)] = item[1]
                            result[VAR_FILE_INFO_STR] = varfileinfo_dict
            except AttributeError:
                logging.warning("Could not find FileInfoTable in .rsrc section.")
        else:
            logging.warning("Could not find .rsrc section.")

        return result


# Given a JSON file, object creates generator for VERSIONINFO rc file for the given JSON.
# Provides validaiton of some basic requirements and generates VERSIONINFO.rc source to be used with resource compiler.
# Here is an example of the minimum required JSON
# {
# 	"FileVersion": "1.0.0.0",
# 	"ProductVersion": "1.0.0.0",
# 	"FileFlagsMask": "VS_FFI_FILEFLAGSMASK",
# 	"FileFlags": "0",
# 	"FileOS": "VOS_NT",
# 	"FileType": "VFT_DRV",
# 	"FileSubtype": "VFT2_DRV_SYSTEM",
# 	"StringFileInfo": {
# 		"CompanyName": "Example Company",
# 		"ProductName": "Example Product",
# 		"FileVersion": "1.0.0.0",
# 	},
# 	"VarFileInfo": {
# 		"Translation": "0x0409 0x04b0"
# 	}
# }
#
# StringFileInfo and VarFileInfo can both have many more entries.
# More information available at https://docs.microsoft.com/en-us/windows/win32/menurc/versioninfo-resource.
class VERSIONINFOGenerator(object):
    _version_dict = None

    def __init__(self, filepath):
        try:
            with open(filepath, "r") as jsonFile:
                data = jsonFile.read()
                try:
                    self._version_dict = json.loads(data)
                except json.decoder.JSONDecodeError as e:
                    logging.error(e)

        except FileNotFoundError:
            logging.error("Could not find " + filepath)

    # Private, returns true if version_str is a valid version string, false otherwise.
    def _validate_version_number(self, version_str):
        if version_str.count('.') != 3:
            logging.error("Invalid version string: " + version_str + ". Version must be in form "
                          + "\"INTEGER.INTEGER.INTEGER.INTEGER\".")
            return False

        for substr in version_str.split("."):
            try:
                if int(substr) > 65535:
                    logging.warning("Integer overflow in version string: " + version_str + ".")
            except ValueError:
                logging.error("Invalid version string: " + version_str + ". Version must be in form \""
                              + " INTEGER.INTEGER.INTEGER.INTEGER\".")
                return False

        return True

    # Checks if loaded JSON file represents a valid VERSIONINFO resource. Returns true if JSON
    # is valid, print relevant error messages and returns false otherwise.
    def validate(self):
        if not self._version_dict:
            return False

        valid = True

        # First Pass: Check to see if all required fields are present
        required = {string.upper() for string in VERSIONFILE_REQUIRED_FIELDS}
        allowed = {string.upper() for string in VERSIONFILE_ALLOWED_FIELDS}
        for key in self._version_dict.keys():
            if key.upper() not in allowed:
                logging.error("Invalid parameter: " + key + ".")
                valid = False
            else:
                if key.upper() in required:
                    required.remove(key.upper())

        for remaining in required:
            logging.error("Missing required parameter: " + remaining + ".")
            valid = False

        if STRING_FILE_INFO_STR in self._version_dict:
            required_string_fields = copy.deepcopy(STRING_FILE_INFO_REQUIRED_FIELDS)
            for key in self._version_dict[STRING_FILE_INFO_STR]:
                if key in required_string_fields:
                    required_string_fields.remove(key)

            for remaining in required_string_fields:
                logging.error("Missing required StringFileInfo parameter: " + remaining + ".")
                valid = False

        if not valid:
            return False

        # Second pass: Check to see if fields are valid
        valid = self._validate_version_number(self._version_dict[FILE_VERSION_STR]) \
                and self._validate_version_number(self._version_dict[PRODUCT_VERSION_STR])

        if self._version_dict[FILE_OS_STR] not in VALID_FILE_OS_VALUES:
            logging.error("Invalid FILEOS value: " + self._version_dict[FILE_OS_STR] + ".")
            valid = False

        if self._version_dict[FILE_TYPE_STR] not in VALID_FILE_TYPE_VALUES:
            logging.error("Invalid FILETYPE value: " + self._version_dict[FILE_TYPE_STR] + ".")
            valid = False

        if self._version_dict[FILE_TYPE_STR] == "VFT_DRV":
            if self._version_dict[FILE_SUBTYPE_STR] not in VALID_SUBTYPE_VFT_DRV:
                logging.error("Invalid FILESUBTYPE value for FILETYPE VFT_DRV: " + self._version_dict[FILE_SUBTYPE_STR] + ".")
                valid = False
        elif self._version_dict[FILE_TYPE_STR] == "VFT_FONT":
            if self._version_dict[FILE_SUBTYPE_STR] not in VALID_SUBTYPE_VFT_FONT:
                logging.error("Invalid FILESUBTYPE value for FILETYPE VFT_FONT: " + self._version_dict[FILE_SUBTYPE_STR] + ".")
                valid = False
        elif self._version_dict[FILE_TYPE_STR] != "VFT_VXD" and self._version_dict[FILE_SUBTYPE_STR] != 0:
            logging.error("Invalid FILESUBTYPE value for FILETYPE " 
                          + self._version_dict[FILE_TYPE_STR] + ", value must be 0.")
            valid = False

        if self._validate_version_number(self._version_dict[STRING_FILE_INFO_STR][FILE_VERSION_STR]):
            if self._version_dict[STRING_FILE_INFO_STR][FILE_VERSION_STR] != self._version_dict[FILE_VERSION_STR]:
                logging.error("FILEVERSION in header does not match FileVersion in StringFileInfo.")
                valid = False
        else:
            valid = False

        if TRANSLATION_STR in self._version_dict[VAR_FILE_INFO_STR]:
            langid_set = self._version_dict[VAR_FILE_INFO_STR][TRANSLATION_STR].split(" ")
            try:
                if len(langid_set) != 2:
                    logging.error("Translation field must contain 2 space delimited hexidecimal 8 bit words.")
                    valid = False
                elif int(langid_set[0], 0) not in VALID_LANG_ID:
                    logging.error("Invalid language code: " + langid_set[0] + "\".")
                    valid = False
                elif int(langid_set[1], 0) not in VALID_CHARSET_ID:
                    logging.error("Invalid charset code: " + langid_set[1] + "\".")
                    valid = False
            except ValueError:
                logging.error("Invalid language code: " + langid_set[0] + "\".")
                valid = False
        else:
            logging.error("Missing required parameter: Translation in VarFileInfo")
            valid = False

        return valid

    def write(self, path):
        if not self.validate():
            logging.error("Invalid input, aborted.")
            return

        out_str = "/* Auto-generated VERSIONINFO resource file. */\n\n"
        out_str += "#include <ntdef.h>\n#include <winver.h>\n#ifdef RC_INVOKED\n"

        # Header fields
        out_str += "VS_VERSION_INFO\tVERSIONINFO\n"
        for param in self._version_dict.keys():
            if (param == STRING_FILE_INFO_STR
               or param == VAR_FILE_INFO_STR
               or param not in VERSIONFILE_REQUIRED_FIELDS):
                continue
            if param == PRODUCT_VERSION_STR or param == FILE_VERSION_STR:
                out_str += param + "\t"
                version = self._version_dict[param].split(".")
                out_str += version[0] + ',' + version[1] + ',' + version[2] + ',' + version[3] + "\n"
            else:
                out_str += param + "\t" + self._version_dict[param] + "\n"

        # StringFileInfo
        out_str += "\n" + BEGIN_STR + "\n\t" + BLOCK_STR + " \"" + STRING_FILE_INFO_STR + "\"\n\t" + BEGIN_STR + "\n"

        language_code = ""
        for code in self._version_dict[VAR_FILE_INFO_STR][TRANSLATION_STR].split(" "):
            language_code += code.split("0x", 1)[1]

        out_str += "\t\t" + BLOCK_STR + " \"" + language_code + "\"\n\t\t" + BEGIN_STR + "\n"
        for field in self._version_dict[STRING_FILE_INFO_STR].keys():
            out_str += "\t\t" + VALUE_STR + " \"" + field + "\",\t\"" \
                      + self._version_dict[STRING_FILE_INFO_STR][field] + "\"\n"

        out_str += "\t\t" + END_STR + "\n\t" + END_STR + "\n\n"

        # VarFileInfo
        out_str += "\t" + BLOCK_STR + " \"" + VAR_FILE_INFO_STR + "\"\n\t" + BEGIN_STR + "\n"
        language_tokens = self._version_dict[VAR_FILE_INFO_STR][TRANSLATION_STR].split(" ")
        for field in self._version_dict[VAR_FILE_INFO_STR].keys():
            if field == TRANSLATION_STR:
                out_str += "\t\t" + VALUE_STR + " \"" + field + "\",\t" + language_tokens[0] + "," \
                           + language_tokens[1] + "\n"
            else:
                out_str += "\t\t" + VALUE_STR + " \"" + field + "\",\t\"" \
                           + self._version_dict[VAR_FILE_INFO_STR][field] + "\"\n"

        out_str += "\t" + END_STR + "\n" + END_STR + "\n#endif"

        with open(os.path.join(path, "VERSIONINFO.rc"), "w") as out:
            out.write(out_str)
