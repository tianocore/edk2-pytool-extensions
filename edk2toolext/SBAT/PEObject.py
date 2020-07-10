import pefile
import peutils
import sys
import json

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

class PEObject(object):

    pe = None

    def __init__(self, filepath):
        self.pe = pefile.PE(filepath)

    def __hexToStrVS_FixedFileInfo__(self, key, val):
        if key == "FileOS":
            if val in FILE_OS_STRINGS:
                return FILE_OS_STRINGS[val]
        elif key == "FileType":
            if val in FILE_TYPE_STRINGS:
                return FILE_TYPE_STRINGS[val]

        return hex(val)
    
    def getVersionDict(self):
        result = {}

        try:
            vs_fixedfileinfoDict = self.pe.VS_FIXEDFILEINFO[0].dump_dict()
            for key in vs_fixedfileinfoDict.keys():
                if key == "Structure" or key == "FileSubtype":
                    continue
                result[key] = self.__hexToStrVS_FixedFileInfo__(key, vs_fixedfileinfoDict[key]["Value"])
            
            # Ensure FileSubtype populated after FileType
            if "FileSubtype" in vs_fixedfileinfoDict.keys():
                fileSubType = vs_fixedfileinfoDict["FileSubtype"]["Value"]
                if "FileType" in result and result["FileType"] == "VFT_FONT":
                    if fileSubType in FILE_SUBTYPE_FONT_STRINGS:
                        result["FileSubtype"] = FILE_SUBTYPE_FONT_STRINGS[fileSubType]
                    else:
                        result["FileSubtype"] = fileSubType
                else:
                    if fileSubType in FILE_SUBTYPE_NOFONT_STRINGS.keys():
                        result["FileSubtype"] = FILE_SUBTYPE_NOFONT_STRINGS[fileSubType]
                    else:
                        result["FileSubtype"] = fileSubType
        except AttributeError:
            print("Could not find VS_FIXEDFILEINFO", file=sys.stderr)

        for fileinfo in self.pe.FileInfo:
            for entry in fileinfo:
                if entry.Key == b'StringFileInfo':
                    stringFileInfoDict = {}
                    for st in entry.StringTable:
                        for item in st.entries.items():
                            stringFileInfoDict[item[0].decode("utf-8")] = item[1].decode("utf-8")
                    result["StringFileInfo"] = stringFileInfoDict
                elif entry.Key == b'VarFileInfo':
                    varFileInfoDict = {}
                    for var in entry.Var:
                        for item in var.entry.items():
                            varFileInfoDict[item[0].decode("utf-8")] = item[1]
                    result["VarFileInfo"] = varFileInfoDict
        return result

    def getVersionJSON(self):
        return json.dumps(self.getVersionDict())

    def validate(self):
        versionDict = self.getVersionDict()
        if versionDict["Signature"] != hex(0xFEEF04BD):
            return False

obj = PEObject("C:\\TEMP\\PciBusDxe.efi")
print(obj.getVersionJSON())