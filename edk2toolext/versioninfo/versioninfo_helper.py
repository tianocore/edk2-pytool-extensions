import pefile
import sys
import json

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
            print("ERROR: Could not find " + filepath, file=sys.stderr)

    # Private, given a 32 bit word, converts word into a string of 2 16 bit integers
    # seperated by '.' to conform to version string format.
    def __versionStr__(self, val):
        return str(((val & ~0) >> 16) & 0xffff) + "." + str(val & 0xffff)

    # Private, converts hex version information to string according to Msft spec
    def __populateEntry__(self, key, val, dict):
        if key == FILE_OS_STR:
            if val in FILE_OS_STRINGS:
                dict[key] = FILE_OS_STRINGS[val]
                return
        elif key == FILE_TYPE_STR:
            if val in FILE_TYPE_STRINGS:
                dict[key] = FILE_TYPE_STRINGS[val]
                return
        elif key == FILE_VERSION_MS_STR:
            dict[FILE_VERSION_STR] = self.__versionStr__(val)
            return
        elif key == FILE_VERSION_LS_STR:
            dict[FILE_VERSION_STR] += "." + self.__versionStr__(val)
            return
        elif key == PRODUCT_VERSION_MS_STR:
            dict[PRODUCT_VERSION_STR] = self.__versionStr__(val)
            return
        elif key == PRODUCT_VERSION_LS_STR:
            dict[PRODUCT_VERSION_STR] += "." + self.__versionStr__(val)
            return
        dict[key] = hex(val)

    # Returns true if PE object contains .rsrc section, false otherwise
    def containsrsrc(self):
        if not self.pe:
            return

        for section in self.pe.sections:
            if section.Name.decode(PE_ENCODING).replace("\x00", "") == RSRC_STR:
                return True
        return False

    # Parses PE/PE+ loaded into PEObject and returns dictionary contaning metadata from header and .rsrc section
    def getVersionDict(self):
        if not self.pe:
            return

        result = {}
        try:
            vs_fixedfileinfoDict = self.pe.VS_FIXEDFILEINFO[0].dump_dict()
            for key in vs_fixedfileinfoDict.keys():
                # Skip sections that have dependencies
                if key == PE_STRUCT_STR or \
                   key == FILE_SUBTYPE_STR or \
                   key == FILE_VERSION_LS_STR or \
                   key == PRODUCT_VERSION_LS_STR or \
                   key == FILE_DATE_LS_STR:
                    continue

                self.__populateEntry__(key, vs_fixedfileinfoDict[key][PE_VALUE_STR], result)

            # Resolve dependent fields
            if FILE_VERSION_MS_STR in vs_fixedfileinfoDict.keys() and \
               FILE_VERSION_LS_STR in vs_fixedfileinfoDict.keys():
                self.__populateEntry__(FILE_VERSION_LS_STR,
                                       vs_fixedfileinfoDict[FILE_VERSION_LS_STR][PE_VALUE_STR], result)

            if PRODUCT_VERSION_MS_STR in vs_fixedfileinfoDict.keys() and \
               PRODUCT_VERSION_LS_STR in vs_fixedfileinfoDict.keys():
                self.__populateEntry__(PRODUCT_VERSION_LS_STR,
                                       vs_fixedfileinfoDict[PRODUCT_VERSION_LS_STR][PE_VALUE_STR], result)

            if FILE_DATE_MS_STR in vs_fixedfileinfoDict.keys() and \
               FILE_DATE_LS_STR in vs_fixedfileinfoDict.keys():
                self.__populateEntry__(FILE_DATE_LS_STR,
                                       vs_fixedfileinfoDict[FILE_DATE_LS_STR][PE_VALUE_STR], result)

            if FILE_SUBTYPE_STR in vs_fixedfileinfoDict.keys():
                fileSubType = vs_fixedfileinfoDict[FILE_SUBTYPE_STR][PE_VALUE_STR]
                if FILE_TYPE_STR in result and result[FILE_TYPE_STR] == VFT_FONT_STR:
                    if fileSubType in FILE_SUBTYPE_FONT_STRINGS:
                        result[FILE_SUBTYPE_STR] = FILE_SUBTYPE_FONT_STRINGS[fileSubType]
                    else:
                        result[FILE_SUBTYPE_STR] = fileSubType
                else:
                    if fileSubType in FILE_SUBTYPE_NOFONT_STRINGS.keys():
                        result[FILE_SUBTYPE_STR] = FILE_SUBTYPE_NOFONT_STRINGS[fileSubType]
                    else:
                        result[FILE_SUBTYPE_STR] = fileSubType

        except AttributeError:
            print("WARNING: Could not find VS_FIXEDFILEINFO.", file=sys.stderr)

        if self.containsrsrc():
            try:
                for fileinfo in self.pe.FileInfo:
                    for entry in fileinfo:
                        if entry.Key.decode(PE_ENCODING).replace("\x00", "") == STRING_FILE_INFO_STR:
                            stringFileInfoDict = {}
                            for strTable in entry.StringTable:
                                for item in strTable.entries.items():
                                    stringFileInfoDict[item[0].decode(PE_ENCODING)] = item[1].decode(PE_ENCODING)
                            result[STRING_FILE_INFO_STR] = stringFileInfoDict
                        elif entry.Key.decode(PE_ENCODING).replace("\x00", "") == VAR_FILE_INFO_STR:
                            varFileInfoDict = {}
                            for var in entry.Var:
                                for item in var.entry.items():
                                    varFileInfoDict[item[0].decode(PE_ENCODING)] = item[1]
                            result[VAR_FILE_INFO_STR] = varFileInfoDict
            except AttributeError:
                print("WARNING: Could not find FileInfoTable in .rsrc section.", file=sys.stderr)
        else:
            print("WARNING: Could not find .rsrc section.", file=sys.stderr)

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
    versionDict = None

    def __init__(self, filepath):
        try:
            with open(filepath, "r") as jsonFile:
                data = jsonFile.read()
                try:
                    self.versionDict = json.loads(data)
                except json.decoder.JSONDecodeError as e:
                    print(e, file=sys.stderr)

        except FileNotFoundError:
            print("ERROR: Could not find " + filepath, file=sys.stderr)

    # Private, returns true if verStr is a valid version string, false otherwise.
    def __validateVersionNumber__(self, verStr):
        if verStr.count('.') != 3:
            print("ERROR: Invalid version string: " + verStr + ". Version must be in form \" \
                   INTEGER.INTEGER.INTEGER.INTEGER\".", file=sys.stderr)
            return False

        for substr in verStr.split("."):
            try:
                if int(substr) > 65535:
                    print("WARNING: Integer overflow in version string: " + verStr + ".", file=sys.stderr)
            except ValueError:
                print("ERROR: Invalid version string: " + verStr + ". Version must be in form \" \
                       INTEGER.INTEGER.INTEGER.INTEGER\".", file=sys.stderr)
                return False

        return True

    # Checks if loaded JSON file represents a valid VERSIONINFO resource. Returns true if JSON
    # is valid, print relevant error messages and returns false otherwise.
    def validate(self):
        if not self.versionDict:
            return False

        valid = True

        # First Pass: Check to see if all required fields are present
        required = {string.upper() for string in VERSIONFILE_REQUIRED_FIELDS}
        allowed = {string.upper() for string in VERSIONFILE_ALLOWED_FIELDS}
        for key in self.versionDict.keys():
            if key.upper() not in allowed:
                print("ERROR: Invalid parameter: " + key + ".", file=sys.stderr)
                valid = False
            else:
                if key.upper() in required:
                    required.remove(key.upper())

        for remaining in required:
            print("ERROR: Missing required parameter: " + remaining + ".", file=sys.stderr)
            valid = False

        if STRING_FILE_INFO_STR in self.versionDict:
            requiredStringFileFields = STRING_FILE_INFO_REQUIRED_FIELDS
            for key in self.versionDict[STRING_FILE_INFO_STR]:
                if key in requiredStringFileFields:
                    requiredStringFileFields.remove(key)

            for remaining in requiredStringFileFields:
                print("ERROR: Missing required StringFileInfo parameter: " + remaining + ".", file=sys.stderr)
                valid = False

        if not valid:
            return False

        # Second pass: Check to see if fields are valid
        valid = self.__validateVersionNumber__(self.versionDict[FILE_VERSION_STR]) \
            and self.__validateVersionNumber__(self.versionDict[PRODUCT_VERSION_STR])

        if self.versionDict[FILE_OS_STR] not in VALID_FILE_OS_VALUES:
            print("ERROR: Invalid FILEOS value: " + self.versionDict[FILE_OS_STR] + ".", file=sys.stderr)
            valid = False

        if self.versionDict[FILE_TYPE_STR] not in VALID_FILE_TYPE_VALUES:
            print("ERROR: Invalid FILETYPE value: " + self.versionDict[FILE_TYPE_STR] + ".", file=sys.stderr)
            valid = False

        if self.versionDict[FILE_TYPE_STR] == "VFT_DRV":
            if self.versionDict[FILE_SUBTYPE_STR] not in VALID_SUBTYPE_VFT_DRV:
                print("ERROR: Invalid FILESUBTYPE value for FILETYPE VFT_DRV: "
                      + self.versionDict[FILE_SUBTYPE_STR] + ".", file=sys.stderr)
                valid = False
        elif self.versionDict[FILE_TYPE_STR] == "VFT_FONT":
            if self.versionDict[FILE_SUBTYPE_STR] not in VALID_SUBTYPE_VFT_FONT:
                print("ERROR: Invalid FILESUBTYPE value for FILETYPE VFT_FONT: "
                      + self.versionDict[FILE_SUBTYPE_STR] + ".", file=sys.stderr)
                valid = False
        elif self.versionDict[FILE_TYPE_STR] != "VFT_VXD" and self.versionDict[FILE_SUBTYPE_STR] != 0:
            print("ERROR: Invalid FILESUBTYPE value for FILETYPE "
                  + self.versionDict[FILE_TYPE_STR] + ", value must be 0.", file=sys.stderr)
            valid = False

        if self.__validateVersionNumber__(self.versionDict[STRING_FILE_INFO_STR][FILE_VERSION_STR]):
            if self.versionDict[STRING_FILE_INFO_STR][FILE_VERSION_STR] != self.versionDict[FILE_VERSION_STR]:
                print("ERROR: FILEVERSION in header does not match FileVersion in StringFileInfo.", file=sys.stderr)
                valid = False
        else:
            valid = False

        if TRANSLATION_STR in self.versionDict[VAR_FILE_INFO_STR]:
            langIDset = self.versionDict[VAR_FILE_INFO_STR][TRANSLATION_STR].split(" ")
            if len(langIDset) != 2:
                print("ERROR: Translation field must contain 2 space delimited hexidecimal 8 bit words.",
                      file=sys.stderr)
                valid = False
            elif int(langIDset[0], 0) not in VALID_LANG_ID:
                print("ERROR: Invalid language code: " + langIDset[0] + ".", file=sys.stderr)
                valid = False
            elif int(langIDset[1], 0) not in VALID_CHARSET_ID:
                print("ERROR: Invalid charset code: " + langIDset[1] + ".", file=sys.stderr)
                valid = False
        else:
            print("ERROR: Missing required parameter: Translation in VarFileInfo", file=sys.stderr)
            valid = False

        return valid

    def write(self, path):
        if not self.validate():
            return

        outStr = "/* Auto-generated VERSIONINFO resource file. */\n\n"
        outStr += "#include <ntdef.h>\n#include <winver.h>\n#ifdef RC_INVOKED\n"

        # Header fields
        outStr += "VS_VERSION_INFO\tVERSIONINFO\n"
        for param in self.versionDict.keys():
            if param == STRING_FILE_INFO_STR or param == VAR_FILE_INFO_STR or param not in VERSIONFILE_REQUIRED_FIELDS:
                continue
            outStr += param + "\t" + self.versionDict[param] + "\n"

        # StringFileInfo
        outStr += "\n" + BEGIN_STR + "\n\t" + BLOCK_STR + " \"" + STRING_FILE_INFO_STR + "\"\n\t" + BEGIN_STR + "\n"

        languageCode = ""
        for code in self.versionDict[VAR_FILE_INFO_STR][TRANSLATION_STR].split(" "):
            languageCode += code.split("0x", 1)[1]

        outStr += "\t\t" + BLOCK_STR + " \"" + languageCode + "\"\n\t\t" + BEGIN_STR + "\n"
        for field in self.versionDict[STRING_FILE_INFO_STR].keys():
            outStr += "\t\t" + VALUE_STR + " \"" + field + "\",\t\"" \
                      + self.versionDict[STRING_FILE_INFO_STR][field] + "\"\n"

        outStr += "\t\t" + END_STR + "\n\t" + END_STR + "\n\n"

        # VarFileInfo
        outStr += "\t" + BLOCK_STR + " \"" + VAR_FILE_INFO_STR + "\"\n\t" + BEGIN_STR + "\n"
        languageTokens = self.versionDict[VAR_FILE_INFO_STR][TRANSLATION_STR].split(" ")
        for field in self.versionDict[VAR_FILE_INFO_STR].keys():
            if field == TRANSLATION_STR:
                outStr += "\t\t" + VALUE_STR + " \"" + field + "\",\t" + languageTokens[0] + "," \
                          + languageTokens[1] + "\n"
            else:
                outStr += "\t\t" + VALUE_STR + " \"" + field + "\",\t\"" \
                          + self.versionDict[VAR_FILE_INFO_STR][field] + "\"\n"

        outStr += "\t" + END_STR + "\n" + END_STR + "\n#endif"

        with open(path + "VERSIONINFO.rc", "w") as out:
            out.write(outStr)
