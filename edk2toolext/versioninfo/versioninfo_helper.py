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

# spell-checker:ignore NOFONT, ntdef

import pefile
import json
import os
import logging
from datetime import datetime


class PEStrings(object):
    '''
    String literals for fields in PE/PE+ header and required fields for VERSIONINFO resource
    '''
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
    '''
    Class for parsing PE/PE+ files. Gives functionality for reading VS_VERSIONINFO metadata and .rsrc section.
    '''
    _pe: pefile.PE = None

    def __init__(self, filepath: str) -> None:
        '''
        Initializes PE parser

        filepath - filepath to PE/PE+ file to parse
        '''
        try:
            self._pe = pefile.PE(filepath)
        except pefile.PEFormatError as e:
            logging.error("Error loading PE: " + str(e))

    def _hex_to_version_str(self, val: int) -> str:
        '''Helper function to convert hex version number to string'''
        return str(((val & ~0) >> 16) & 0xffff) + "." + str(val & 0xffff)

    def _populate_entry(self, key: str, val: int, dict: dict) -> None:
        '''Helper function to format and insert VERSIONINFO fields into dictionary'''
        if key == PEStrings.FILE_OS_STR:
            if val in PEStrings.FILE_OS_STRINGS:
                dict[key] = PEStrings.FILE_OS_STRINGS[val]
                return
        elif key == PEStrings.FILE_TYPE_STR:
            if val in PEStrings.FILE_TYPE_STRINGS:
                dict[key] = PEStrings.FILE_TYPE_STRINGS[val]
                return
        elif key == PEStrings.FILE_VERSION_MS_STR:
            dict[PEStrings.FILE_VERSION_STR] = self._hex_to_version_str(val)
            return
        elif key == PEStrings.FILE_VERSION_LS_STR:
            dict[PEStrings.FILE_VERSION_STR] += "." + self._hex_to_version_str(val)
            return
        elif key == PEStrings.PRODUCT_VERSION_MS_STR:
            dict[PEStrings.PRODUCT_VERSION_STR] = self._hex_to_version_str(val)
            return
        elif key == PEStrings.PRODUCT_VERSION_LS_STR:
            dict[PEStrings.PRODUCT_VERSION_STR] += "." + self._hex_to_version_str(val)
            return
        dict[key] = hex(val)

    def contains_rsrc(self) -> bool:
        '''Returns true if PE object contains .rsrc section, false otherwise'''
        for section in self._pe.sections:
            if section.Name.decode(PEStrings.PE_ENCODING).replace("\x00", "") == PEStrings.RSRC_STR:
                return True
        return False

    def get_version_dict(self) -> dict:
        '''Parses PE/PE+ loaded into PEObject and returns dictionary contaning metadata from header and .rsrc section'''
        if not self._pe:
            logging.fatal("Cannot parse, PE not loaded.")
            return None

        result = {}
        try:
            vs_fixedfileinfo_dict = self._pe.VS_FIXEDFILEINFO[0].dump_dict()
            for key in vs_fixedfileinfo_dict.keys():
                # Skip sections that have dependencies
                if key == PEStrings.PE_STRUCT_STR or \
                   key == PEStrings.FILE_SUBTYPE_STR or \
                   key == PEStrings.FILE_VERSION_LS_STR or \
                   key == PEStrings.PRODUCT_VERSION_LS_STR or \
                   key == PEStrings.FILE_DATE_LS_STR:
                    continue

                self._populate_entry(key, vs_fixedfileinfo_dict[key][PEStrings.PE_VALUE_STR], result)

            # Resolve dependent fields
            if PEStrings.FILE_VERSION_MS_STR in vs_fixedfileinfo_dict.keys() and \
               PEStrings.FILE_VERSION_LS_STR in vs_fixedfileinfo_dict.keys():
                self._populate_entry(PEStrings.FILE_VERSION_LS_STR,
                                     vs_fixedfileinfo_dict[PEStrings.FILE_VERSION_LS_STR][PEStrings.PE_VALUE_STR], result) # noqa

            if PEStrings.PRODUCT_VERSION_MS_STR in vs_fixedfileinfo_dict.keys() and \
               PEStrings.PRODUCT_VERSION_LS_STR in vs_fixedfileinfo_dict.keys():
                self._populate_entry(PEStrings.PRODUCT_VERSION_LS_STR,
                                     vs_fixedfileinfo_dict[PEStrings.PRODUCT_VERSION_LS_STR][PEStrings.PE_VALUE_STR], result) # noqa

            if PEStrings.FILE_DATE_MS_STR in vs_fixedfileinfo_dict.keys() and \
               PEStrings.FILE_DATE_LS_STR in vs_fixedfileinfo_dict.keys():
                self._populate_entry(PEStrings.FILE_DATE_LS_STR,
                                     vs_fixedfileinfo_dict[PEStrings.FILE_DATE_LS_STR][PEStrings.PE_VALUE_STR], result)

            if PEStrings.FILE_SUBTYPE_STR in vs_fixedfileinfo_dict.keys():
                file_subtype = vs_fixedfileinfo_dict[PEStrings.FILE_SUBTYPE_STR][PEStrings.PE_VALUE_STR]
                if PEStrings.FILE_TYPE_STR in result and result[PEStrings.FILE_TYPE_STR] == PEStrings.VFT_FONT_STR:
                    if file_subtype in PEStrings.FILE_SUBTYPE_FONT_STRINGS:
                        result[PEStrings.FILE_SUBTYPE_STR] = PEStrings.FILE_SUBTYPE_FONT_STRINGS[PEStrings.file_subtype]
                    else:
                        result[PEStrings.FILE_SUBTYPE_STR] = file_subtype
                else:
                    if file_subtype in PEStrings.FILE_SUBTYPE_NOFONT_STRINGS.keys():
                        result[PEStrings.FILE_SUBTYPE_STR] = PEStrings.FILE_SUBTYPE_NOFONT_STRINGS[file_subtype]
                    else:
                        result[PEStrings.FILE_SUBTYPE_STR] = file_subtype

        except AttributeError:
            logging.warning("Could not find VS_FIXEDFILEINFO.")

        if self.contains_rsrc():
            for fileinfo in self._pe.FileInfo:
                for entry in fileinfo:
                    if entry.Key.decode(PEStrings.PE_ENCODING).replace("\x00", "") == PEStrings.STRING_FILE_INFO_STR:
                        stringfileinfo_dict = {}
                        for strTable in entry.StringTable:
                            for item in strTable.entries.items():
                                stringfileinfo_dict[item[0].decode(PEStrings.PE_ENCODING)] = item[1].decode(PEStrings.PE_ENCODING) # noqa
                        result[PEStrings.STRING_FILE_INFO_STR] = stringfileinfo_dict
                    elif entry.Key.decode(PEStrings.PE_ENCODING).replace("\x00", "") == PEStrings.VAR_FILE_INFO_STR:
                        varfileinfo_dict = {}
                        for var in entry.Var:
                            for item in var.entry.items():
                                varfileinfo_dict[item[0].decode(PEStrings.PE_ENCODING)] = item[1]
                        result[PEStrings.VAR_FILE_INFO_STR] = varfileinfo_dict
        else:
            logging.warning("File does not contain .rsrc section.")

        return result


class VERSIONINFOGenerator(object):
    '''
    Given a JSON file, object creates generator for VERSIONINFO rc file for the given JSON.
    Provides validation of some basic requirements and generates VERSIONINFO.rc source to be used with rc.exe.
    Here is an example of the minimum required JSON
    {
        "FileVersion": "1.0.0.0",
        "ProductVersion": "1.0.0.0",
        "FileFlagsMask": "VS_FFI_FILEFLAGSMASK",
        "FileFlags": "0",
        "FileOS": "VOS_NT",
        "FileType": "VFT_DRV",
        "FileSubtype": "VFT2_DRV_SYSTEM",
        "StringFileInfo": {
            "CompanyName": "Example Company",
            "ProductName": "Example Product",
            "FileVersion": "1.0.0.0",
        },
        "VarFileInfo": {
            "Translation": "0x0409 0x04b0"
        }
    }

    StringFileInfo and VarFileInfo can both have many more entries.
    More information available at https://docs.microsoft.com/en-us/windows/win32/menurc/versioninfo-resource.
    '''
    _version_dict = None

    def __init__(self, filepath: str) -> None:
        '''
        Initializes generator

        filepath - filepath to JSON file containing VERSIONINFO information in format shown above
        '''
        with open(filepath, "r") as jsonFile:
            data = jsonFile.read()
            try:
                self._version_dict = json.loads(data)
            except json.decoder.JSONDecodeError as e:
                logging.error("Invalid JSON format, " + str(e))

    def _validate_version_number(self, version_str: str) -> bool:
        '''Helper function to check if a version string format is valid or not'''
        if version_str.count('.') != 3:
            logging.error("Invalid version string: " + version_str + ". Version must be in form "
                          + "\"INTEGER.INTEGER.INTEGER.INTEGER\".")
            return False

        for substr in version_str.split("."):
            try:
                if int(substr) > 65535:
                    logging.error("Integer overflow in version string: " + version_str + ".")
                    return False
            except ValueError:
                logging.error("Invalid version string: " + version_str + ". Version must be in form \""
                              + " INTEGER.INTEGER.INTEGER.INTEGER\".")
                return False

        return True

    def validate(self) -> bool:
        '''
        Returns true if loaded JSON file represents a valid VERSIONINFO resource, false otherwise
        '''
        if not self._version_dict:
            return False

        valid = True

        # First Pass: Check to see if all required fields are present
        required = {string.upper() for string in PEStrings.VERSIONFILE_REQUIRED_FIELDS}
        allowed = {string.upper() for string in PEStrings.VERSIONFILE_ALLOWED_FIELDS}
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

        if PEStrings.STRING_FILE_INFO_STR in self._version_dict:
            required_string_fields = PEStrings.STRING_FILE_INFO_REQUIRED_FIELDS.copy()
            for key in self._version_dict[PEStrings.STRING_FILE_INFO_STR]:
                if key in required_string_fields:
                    required_string_fields.remove(key)

            for remaining in required_string_fields:
                logging.error("Missing required StringFileInfo parameter: " + remaining + ".")
                valid = False

        if not valid:
            return False

        # Second pass: Check to see if fields are valid
        valid = self._validate_version_number(self._version_dict[PEStrings.FILE_VERSION_STR])
        if PEStrings.PRODUCT_VERSION_STR in self._version_dict:
            valid = valid and self._validate_version_number(self._version_dict[PEStrings.PRODUCT_VERSION_STR])

        if PEStrings.FILE_OS_STR in self._version_dict:
            try:
                if int(self._version_dict[PEStrings.FILE_OS_STR], 0) not in PEStrings.FILE_OS_STRINGS.keys():
                    valid = False
                    logging.error("Invalid FILEOS value: " + self._version_dict[PEStrings.FILE_OS_STR] + ".")
            except ValueError:
                if self._version_dict[PEStrings.FILE_OS_STR] not in PEStrings.VALID_FILE_OS_VALUES:
                    valid = False
                    logging.error("Invalid FILEOS value: " + self._version_dict[PEStrings.FILE_OS_STR] + ".")

        if PEStrings.FILE_TYPE_STR in self._version_dict:
            try:
                if int(self._version_dict[PEStrings.FILE_TYPE_STR], 0) not in PEStrings.FILE_TYPE_STRINGS.keys():
                    valid = False
                    logging.error("Invalid FILETYPE value: " + self._version_dict[PEStrings.FILE_TYPE_STR] + ".")
            except ValueError:
                if self._version_dict[PEStrings.FILE_TYPE_STR] not in PEStrings.VALID_FILE_TYPE_VALUES:
                    valid = False
                    logging.error("Invalid FILETYPE value: " + self._version_dict[PEStrings.FILE_TYPE_STR] + ".")
            if PEStrings.FILE_SUBTYPE_STR in self._version_dict:
                if self._version_dict[PEStrings.FILE_TYPE_STR] == "VFT_DRV":
                    if self._version_dict[PEStrings.FILE_SUBTYPE_STR] not in PEStrings.VALID_SUBTYPE_VFT_DRV:
                        logging.error("Invalid FILESUBTYPE value for FILETYPE VFT_DRV: "
                                      + self._version_dict[PEStrings.FILE_SUBTYPE_STR] + ".")
                        valid = False
                elif self._version_dict[PEStrings.FILE_TYPE_STR] == "VFT_FONT":
                    if self._version_dict[PEStrings.FILE_SUBTYPE_STR] not in PEStrings.VALID_SUBTYPE_VFT_FONT:
                        logging.error("Invalid FILESUBTYPE value for FILETYPE VFT_FONT: "
                                      + self._version_dict[PEStrings.FILE_SUBTYPE_STR] + ".")
                        valid = False
                elif (self._version_dict[PEStrings.FILE_TYPE_STR] != "VFT_VXD"
                      and self._version_dict[PEStrings.FILE_SUBTYPE_STR] != 0):
                    logging.error("Invalid FILESUBTYPE value for FILETYPE "
                                  + self._version_dict[PEStrings.FILE_TYPE_STR] + ", value must be 0.")
                    valid = False
        elif PEStrings.FILE_SUBTYPE_STR in self._version_dict:
            logging.error("Missing parameter: must have FileType if FileSubtype defined.")
            valid = False

        if PEStrings.TRANSLATION_STR in self._version_dict[PEStrings.VAR_FILE_INFO_STR]:
            langid_set = self._version_dict[PEStrings.VAR_FILE_INFO_STR][PEStrings.TRANSLATION_STR].split(" ")
            try:
                if len(langid_set) != 2:
                    logging.error("Translation field must contain 2 space delimited hexidecimal bytes.")
                    valid = False
                elif (int(langid_set[0].replace('"', ''), 0) not in PEStrings.VALID_LANG_ID
                      or int(langid_set[1].replace('"', ''), 0) not in PEStrings.VALID_CHARSET_ID):
                    logging.error("Invalid language code: "
                                  + self._version_dict[PEStrings.VAR_FILE_INFO_STR][PEStrings.TRANSLATION_STR] + ".")
                    valid = False
            except ValueError:
                logging.error("Invalid language code: "
                              + self._version_dict[PEStrings.VAR_FILE_INFO_STR][PEStrings.TRANSLATION_STR] + ".")
                valid = False
        else:
            logging.error("Missing required parameter in VarFileInfo: Translation.")
            valid = False

        for field in self._version_dict[PEStrings.VAR_FILE_INFO_STR].keys():
            if field != PEStrings.TRANSLATION_STR:
                logging.error("Invalid VarFileInfo parameter: %s.", field)
                valid = False

        return valid

    def write(self, path: str) -> bool:
        '''
        Encodes the loaded JSON and writes it to VERSION.rc, a resource file comptaible with rc.exe.
        Returns true on success, false otherwise.

        path - path to directory that VERSIONINFO.rc will be written to
        '''
        if not self.validate():
            logging.error("Invalid input, aborted.")
            return False

        out_str = "/* Auto-generated VERSIONINFO resource file.\n" \
                  + "   Generated at %s */\n\n" % datetime.now().strftime("%d/%m/%Y %H:%M:%S") \
                  + "#include <ntdef.h>\n#include <winver.h>\n#ifdef RC_INVOKED\n"

        # Header fields
        out_str += "VS_VERSION_INFO\tVERSIONINFO\n"
        for param in self._version_dict.keys():
            if (param == PEStrings.STRING_FILE_INFO_STR
               or param == PEStrings.VAR_FILE_INFO_STR):
                continue
            if param == PEStrings.PRODUCT_VERSION_STR or param == PEStrings.FILE_VERSION_STR:
                out_str += param.upper() + "\t"
                version = self._version_dict[param].split(".")
                out_str += version[0] + ',' + version[1] + ',' + version[2] + ',' + version[3] + "\n"
            else:
                out_str += param.upper() + "\t" + str(self._version_dict[param]) + "\n"

        # StringFileInfo
        out_str += "\n" + PEStrings.BEGIN_STR + "\n\t"
        out_str += PEStrings.BLOCK_STR + " \"" + PEStrings.STRING_FILE_INFO_STR + "\"\n\t" + PEStrings.BEGIN_STR + "\n"

        language_code = ""
        for code in self._version_dict[PEStrings.VAR_FILE_INFO_STR][PEStrings.TRANSLATION_STR].split(" "):
            language_code += code.split("0x", 1)[1]

        out_str += "\t\t" + PEStrings.BLOCK_STR + " \"" + language_code + "\"\n\t\t" + PEStrings.BEGIN_STR + "\n"
        for field in self._version_dict[PEStrings.STRING_FILE_INFO_STR].keys():
            out_str += "\t\t" + PEStrings.VALUE_STR + " \"" + field + "\",\t\"" \
                       + self._version_dict[PEStrings.STRING_FILE_INFO_STR][field] + "\"\n"

        out_str += "\t\t" + PEStrings.END_STR + "\n\t" + PEStrings.END_STR + "\n\n"

        # VarFileInfo
        out_str += "\t" + PEStrings.BLOCK_STR
        out_str += " \"" + PEStrings.VAR_FILE_INFO_STR + "\"\n\t" + PEStrings.BEGIN_STR + "\n"
        language_tokens = self._version_dict[PEStrings.VAR_FILE_INFO_STR][PEStrings.TRANSLATION_STR].split(" ")
        for field in self._version_dict[PEStrings.VAR_FILE_INFO_STR].keys():
            out_str += "\t\t" + PEStrings.VALUE_STR + " \"" + field + "\",\t" + language_tokens[0] + "," \
                       + language_tokens[1] + "\n"

        out_str += "\t" + PEStrings.END_STR + "\n" + PEStrings.END_STR + "\n#endif"

        with open(os.path.join(path, "VERSIONINFO.rc"), "w") as out:
            out.write(out_str)

        return True
