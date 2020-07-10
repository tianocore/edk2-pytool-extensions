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
FILE_TYPE_STR            = "FileType"
FILE_SUBTYPE_STR         = "FileSubtype"
FILE_OS_STR              = "FileOS"
VFT_FONT_STR             = "VFT_FONT"
RSRC_STR                 = ".rsrc"
STRING_FILE_INFO_STR     = "StringFileInfo"
VAR_FILE_INFO_STR        = "VarFileInfo"

# Key values for interacting with pefile objects
PE_ENCODING              = "utf-8"
PE_STRUCT_STR            = "Structure"
PE_VALUE_STR             = "Value"

class PEObject(object):
    pe = None

    # Takes filepath to PE/PE+ file to parse
    def __init__(self, filepath):
        self.pe = pefile.PE(filepath)

    # Private, converts hex version information to string according to Msft spec
    def __hexToStrVS_FixedFileInfo__(self, key, val):
        if key == FILE_OS_STR:
            if val in FILE_OS_STRINGS:
                return FILE_OS_STRINGS[val]
        elif key == FILE_TYPE_STR:
            if val in FILE_TYPE_STRINGS:
                return FILE_TYPE_STRINGS[val]

        return hex(val)

    # Returns true if PE object contains .rsrc section, false otherwise
    def containsrsrc(self):
        for section in self.pe.sections:
            if section.Name.decode(PE_ENCODING).replace("\x00", "") == RSRC_STR:
                return True
        return False
    
    # Parses PE/PE+ loaded into PEObject and returns dictionary contaning metadata from header and .rsrc section
    def getVersionDict(self):
        result = {}
        try:
            vs_fixedfileinfoDict = self.pe.VS_FIXEDFILEINFO[0].dump_dict()
            for key in vs_fixedfileinfoDict.keys():
                if key == PE_STRUCT_STR or key == FILE_SUBTYPE_STR:
                    continue
                result[key] = self.__hexToStrVS_FixedFileInfo__(key, vs_fixedfileinfoDict[key][PE_VALUE_STR])
            
            # Ensure FileSubtype populated after FileType
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
                            for st in entry.StringTable:
                                for item in st.entries.items():
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
    def getVersionJSON(self):
        return json.dumps(self.getVersionDict())

    # Validates header and .rsrc section of PE/PE+ loaded into PEObject. Returns true if all required
    # fields are valid and present, false otherwise.
    def validate(self):
        versionDict = self.getVersionDict()
        if versionDict[SIGNATURE_STR] != VALID_SIGNATURE:
            return False

obj = PEObject("C:\\TEMP\\bootmgr.efi")
print(obj.getVersionJSON())