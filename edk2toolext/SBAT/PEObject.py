import pefile
import peutils
import sys
import json

# String values for PE/PE+ header versioning metadata
FILE_OS_STRINGS = {
    0x00010000 : "VOS_DOS",
    0x00040000 : "VOS_NT",
    0x00000001 : "VOS__WINDOWS16",
    0x00000004 : "VOS__WINDOWS32",
    0x00020000 : "VOS_OS216",
    0x00030000 : "VOS_OS232",
    0x00000002 : "VOS__PM16",
    0x00000003 : "VOS__PM32",
    0x00000000 : "VOS_UNKNOWN",
    0x00010001 : "VOS_DOS_WINDOWS16",
    0x00010004 : "VOS_DOS_WINDOWS32",
    0x00040004 : "VOS_NT_WINDOWS32",
    0x00020002 : "VOS_OS216_PM16",
    0x00030003 : "VOS_OS232_PM32"
}

FILE_TYPE_STRINGS = {
    0x00000001 : "VFT_APP",
    0x00000002 : "VFT_DLL",
    0x00000003 : "VFT_DRV",
    0x00000004 : "VFT_FONT",
    0x00000007 : "VFT_STATIC_LIB",
    0x00000000 : "VFT_UNKNOWN",
    0x00000005 : "VFT_VXD"
}

FILE_SUBTYPE_NOFONT_STRINGS = {
    0x0000000A : "VFT2_DRV_COMM",
    0x00000004 : "VFT2_DRV_DISPLAY",
    0x00000008 : "VFT2_DRV_INSTALLABLE",
    0x00000002 : "VFT2_DRV_KEYBOARD",
    0x00000003 : "VFT2_DRV_LANGUAGE",
    0x00000005 : "VFT2_DRV_MOUSE",
    0x00000006 : "VFT2_DRV_NETWORK",
    0x00000001 : "VFT2_DRV_PRINTER",
    0x00000009 : "VFT2_DRV_SOUND",
    0x00000007 : "VFT2_DRV_SYSTEM",
    0x0000000C : "VFT2_DRV_VERSIONED_PRINTER",
    0x00000000 : "VFT2_UNKNOWN"
}

FILE_SUBTYPE_FONT_STRINGS = {
    0x00000001 : "VFT2_FONT_RASTER",
    0x00000003 : "VFT2_FONT_TRUETYPE",
    0x00000002 : "VFT2_FONT_VECTOR",
    0x00000000 : "VFT2_UNKNOWN"
}

VALID_SIGNATURE          = 0xfeef04bd

# PE/PE+ field names
SIGNATURE_STR            = "Signature"
STRUC_VERSION_STR        = "StrucVersion"
FILE_VERSION_MS_STR      = "FileVersionMS"
FILE_VERSION_LS_STR      = "FileVersionLS"
FILE_VERSION_STR         = "FileVersion"
PRODUCT_VERSION_MS_STR   = "ProductVersionMS"
PRODUCT_VERSION_LS_STR   = "ProductVersionLS"
PRODUCT_VERSION_STR      = "ProductVersion"
FILE_FLAG_MASK_STR       = "FileFlagsMask"
FILE_FLAGS_STR           = "FileFlags"
FILE_TYPE_STR            = "FileType"
FILE_SUBTYPE_STR         = "FileSubtype"
FILE_OS_STR              = "FileOS"
FILE_DATE_MS_STR         = "FileDateMS"
FILE_DATE_LS_STR         = "FileDateLS"
FILE_DATE_STR            = "FileDate"
VFT_FONT_STR             = "VFT_FONT"
RSRC_STR                 = ".rsrc"
STRING_FILE_INFO_STR     = "StringFileInfo"
VAR_FILE_INFO_STR        = "VarFileInfo"

# Key values for interacting with pefile objects
PE_ENCODING              = "utf-8"
PE_STRUCT_STR            = "Structure"
PE_VALUE_STR             = "Value"

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

class PEObject(object):
    pe = None

    # Takes filepath to PE/PE+ file to parse
    def __init__(self, filepath):
        try:
            self.pe = pefile.PE(filepath)
        except FileNotFoundError:
            print("ERROR: Could not find " + filepath, file=sys.stderr)

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
                # Skip sections that have a dependencies
                if (key == PE_STRUCT_STR 
                  or key == FILE_SUBTYPE_STR 
                  or key == FILE_VERSION_LS_STR 
                  or key == PRODUCT_VERSION_LS_STR 
                  or key == FILE_DATE_LS_STR):
                    continue

                self.__populateEntry__(key, vs_fixedfileinfoDict[key][PE_VALUE_STR], result)
            
            # Resolve dependent fields
            if FILE_VERSION_MS_STR in vs_fixedfileinfoDict.keys() and FILE_VERSION_LS_STR in vs_fixedfileinfoDict.keys():
                self.__populateEntry__(FILE_VERSION_LS_STR, vs_fixedfileinfoDict[FILE_VERSION_LS_STR][PE_VALUE_STR], result)

            if PRODUCT_VERSION_MS_STR in vs_fixedfileinfoDict.keys() and PRODUCT_VERSION_LS_STR in vs_fixedfileinfoDict.keys():
                self.__populateEntry__(PRODUCT_VERSION_LS_STR, vs_fixedfileinfoDict[PRODUCT_VERSION_LS_STR][PE_VALUE_STR], result)

            if FILE_DATE_MS_STR in vs_fixedfileinfoDict.keys() and FILE_DATE_LS_STR in vs_fixedfileinfoDict.keys():
                self.__populateEntry__(FILE_DATE_LS_STR, vs_fixedfileinfoDict[FILE_DATE_LS_STR][PE_VALUE_STR], result)

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

    # Parses PE/PE+ loaded into PEObject and returns JSON contaning metadata from header and .rsrc section
    # def getVersionJSON(self):
    #     if not self.pe:
    #         return

    #     return json.dumps(self.getVersionDict())

    # Validates header and .rsrc section of PE/PE+ loaded into PEObject. Returns true if all required
    # fields are valid and present, false otherwise.
    # def validate(self):
    #     versionDict = self.getVersionDict()
    #     if versionDict[SIGNATURE_STR] != VALID_SIGNATURE:
    #         return False

class VERSIONINFOGenerator(object):
    versionDict = None

    def __init__(self, filepath):
        try:
            with open(filepath, "r") as jsonFile:
                data = jsonFile.read()
                print(data)
                self.versionDict = json.loads(data)
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
                print("ERROR: Invalid FILESUBTYPE value for FILETYPE VFT_DRV: " + self.versionDict[FILE_SUBTYPE_STR] + ".", file=sys.stderr)
                valid = False
        elif self.versionDict[FILE_TYPE_STR] == "VFT_FONT":
            if self.versionDict[FILE_SUBTYPE_STR] not in VALID_SUBTYPE_VFT_FONT:
                print("ERROR: Invalid FILESUBTYPE value for FILETYPE VFT_FONT: " + self.versionDict[FILE_SUBTYPE_STR] + ".", file=sys.stderr)
                valid = False
        elif self.versionDict[FILE_TYPE_STR] != "VFT_VXD" and self.versionDict[FILE_SUBTYPE_STR] != 0:
            print("ERROR: Invalid FILESUBTYPE value for FILETYPE " + self.versionDict[FILE_TYPE_STR] + ", value must be 0.", file=sys.stderr)
            valid = False

        if self.__validateVersionNumber__(self.versionDict[STRING_FILE_INFO_STR][FILE_VERSION_STR]):
            if self.versionDict[STRING_FILE_INFO_STR][FILE_VERSION_STR] != self.versionDict[FILE_VERSION_STR]:
                print("ERROR: FILEVERSION in header does not match FileVersion in StringFileInfo." , file=sys.stderr)
                valid = False
        else:
            valid = False

        return valid



# obj = PEObject(".\\tests\\test1\\test1rsrc.exe")
# f = open("test1.json", "w")
# json.dump(obj.getVersionDict(), f)
# f.close()
generator = VERSIONINFOGenerator(".\\test1.json")
print(generator.validate())