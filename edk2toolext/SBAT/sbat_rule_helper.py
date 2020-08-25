import struct
import json
import logging
import mmap
from edk2toolext.versioninfo.versioninfo_helper import validate_version_number, version_str_to_int, hex_to_version_str

class VersionRecordCert(object):
    '''
    Version record cert object.
    '''
    NO_FILEVERSION = 0
    EQUAL = 0b00000001
    NOT_EQUAL = 0b00000010
    LESS_THAN = 0b00000100
    GREATER_THAN = 0b00001000
    LEQ = 0b00010000
    GEQ = 0b00100000

    OPERATOR_CODES = {
        "==": EQUAL,
        "!=": NOT_EQUAL,
        "<": LESS_THAN,
        ">": GREATER_THAN,
        "<=": LEQ,
        ">=": GEQ,
        EQUAL: "==",
        NOT_EQUAL: "!=",
        LESS_THAN: "<",
        GREATER_THAN: ">",
        LEQ: "<=",
        GEQ: ">="
    }

    compare_rule: int = None
    company_name: str = None
    product_name: str = None
    file_version: int = None

    def __init__(self, compare_rule: int, file_version: int, company_name: str, product_name: str = None):
        self.compare_rule = compare_rule
        self.company_name = company_name
        self.product_name = product_name
        self.file_version = file_version

class _VersionRecordCertEntryStruct(object):
    '''
    Wrapper class around struct module to create proper structs for individual version record entries. 
    '''
    _STRUCT_HEADER = '<3H2BQ'
    _STRUCT_TEMPLATE = _STRUCT_HEADER + '{company}{product}{padding}'
    _STRING_ENCODING = "UTF-16LE"
    _VERSION_RECORD_STRUC_VERSION = 1

    _cert_struct: str = None
    _company_name: str = None
    _product_name: str = None
    _compare_rule: int = 0
    _file_version: int = 0

    def __init__(self, compare_rule: int, file_version: int, company_name: str, product_name: str) -> None:
        '''
        Creates rule entry struct given a compare rule, file version, and unicode strings company_name and product_name. 
        '''
        self._compare_rule = compare_rule
        self._file_version = file_version
        self._company_name = company_name
        self._product_name = product_name
        company_name_len = 2 * (len(company_name) + 1)
        company_struct_entry = str(company_name_len) + 's'
        product_name_len = 0
        product_struct_entry = ""
        if product_name:
            product_name_len = 2 * (len(product_name) + 1)
            product_struct_entry = str(product_name_len) + 's'

        padding = ""
        print (self._compare_rule)
        print (self._file_version)
        print (self._company_name)
        print (self._product_name)
        if (company_name_len + product_name_len) % 8 != 0:
            padding = str(8 - ((company_name_len + product_name_len) % 8)) + 'x'
        
        print ("Padding str: ", padding)
        self._cert_struct = self._STRUCT_TEMPLATE.format(company = company_struct_entry, product = product_struct_entry, padding = padding)
        print ("Struct str: ", self._cert_struct)
        print ("Struc size here: ", struct.calcsize(self._cert_struct))

    def pack(self) -> bytes:
        '''
        Returns bytestring of C style struct of version record.
        '''
        rule_size = struct.calcsize(self._cert_struct)
        print ("Pack rule_size: ", rule_size)
        company_name_raw = self._company_name.encode(self._STRING_ENCODING)
        company_name_len = (len(self._company_name) + 1) * 2
        if self._product_name:
            product_name_raw = self._product_name.encode(self._STRING_ENCODING)
            product_name_len = (len(self._product_name) + 1) * 2
            print (self._cert_struct)
            return struct.pack(self._cert_struct, rule_size, self._VERSION_RECORD_STRUC_VERSION, self._compare_rule, company_name_len, product_name_len, self._file_version, company_name_raw, product_name_raw)
        else:
            return struct.pack(self._cert_struct, rule_size, self._VERSION_RECORD_STRUC_VERSION, self._compare_rule, company_name_len, 0, self._file_version, company_name_raw)

    def unpack(self, data: bytes) -> VersionRecordCert:
        '''
        Returns VersionRecordCert given raw bytes of C style struct from data.
        '''
        print ("Data len: " + str(len(data)))
        py_struct = struct.unpack(self._cert_struct, data)
        print(py_struct)
        if py_struct[4] == 0:
            return VersionRecordCert(py_struct[2], py_struct[5], py_struct[6].decode(self._STRING_ENCODING))
        else:
            return VersionRecordCert(py_struct[2], py_struct[5], py_struct[6].decode(self._STRING_ENCODING), py_struct[7].decode(self._STRING_ENCODING))

    def unpack_from(self, buffer: bytes, offset: int) -> VersionRecordCert:
        '''
        Returns VersionRecordCert of C style struct at a given offset in buffer.
        '''
        print ("Struct size: " + str(struct.calcsize(self._cert_struct)))
        print ("Offset: ", offset)
        print ("Buf Len: " + str(len (buffer[offset:offset + struct.calcsize(self._cert_struct)])))
        return self.unpack(buffer[offset:offset + struct.calcsize(self._cert_struct)])


class VersionRecordCertGenerator(object):
    '''
    Tool used to generate Version Record certs for secure boot. Given a JSON file, class
    generates raw binary encoding of rules that can be added to db/dbx. Assumes little-endianess.
    Example rule JSON:
    [
        # Any EFI image with comapny name "Microsoft" fufills rule
        ["Microsoft"], 

        # EFI image with comapny name "Microsoft" and product name "bootmgr" fufills rule
        ["Microsoft", "bootmgr"],
    
        # EFI image with comapny name "Microsoft", product name "bootmgr", and file version less than 1.2.3.4 fufills rule
        ["Microsoft", "bootmgr", "<", "1.2.3.4"],
    ]
    '''
    _record_list: list = None

    def __init__(self, filepath):
        with open(filepath) as json_dict:
            try:
                self._record_list = json.load(json_dict)
            except json.decoder.JSONDecodeError as e:
                logging.error("Invalid JSON format, " + str(e))

    def validate(self) -> bool:
        '''
        Returns true if currently loaded JSON is a valid rule representation, false otherwise.
        '''
        if not self._record_list:
            return False
        
        if type(self._record_list) != list:
            logging.error("Invalid format, rules must be in JSON array.")
            return False
        
        valid = True
        for rule in self._record_list:
            if type(rule) != list:
                logging.error("Invalid rule: %s. Rule must be JSON array object.", str(rule))
                valid = False
                continue

            if len(rule) == 0:
                logging.error("Invalid rule: rule is empty.")
                valid = False
                continue

            for member in rule:
                if type(member) != str:
                    logging.error("Invalid value %s in rule: %s. Value must be string.", str(member), str(rule))
                    valid = False
                    continue
                if member == "":
                    logging.error("Invalid value '' in rule: %s. Value cannot be empty string.", str(rule))
                    valid = False
            
            if not valid or len(rule) < 3:
                continue

            if rule[2] not in VersionRecordCert.OPERATOR_CODES:
                logging.error("Invalid value %s in rule: %s. Value must be comparison operator.", rule[2], str(rule))
                valid = False

            if not validate_version_number(rule[3]):
                logging.error("Invalid value %s in rule: %s.", rule[3], str(rule))
                valid = False
                continue

            if len(rule) > 4:
                logging.error("Invalid rule: %s. Rule must not have more than 4 members.", str(rule))
                valid = False

        return valid

    def write(self, filepath: str) -> bool:
        '''
        Checks if loaded JSON representation of VersionRecordCert is valid, then writes binary of rules in the form of EFI_SIGNATURE_DATA array to filepath.
        '''
        if not self.validate():
            logging.error("Invalid input, aborted.")
            return False
        raw_bytes = bytearray()
        for rule in self._record_list:
            compare_rule = VersionRecordCert.NO_FILEVERSION
            company_name = rule[0]
            product_name = None
            file_version = 0
            if len(rule) > 1:
                product_name = rule[1]

            if len(rule) == 4:
                dwords = version_str_to_int(rule[3])
                file_version = (dwords[0] << 32) + dwords[1]
                compare_rule = VersionRecordCert.OPERATOR_CODES[rule[2]]

            rule_struct = _VersionRecordCertEntryStruct(compare_rule, file_version, company_name, product_name)
            raw_bytes.extend(rule_struct.pack())

        with open(filepath, "wb+") as out_file:
            out_file.write(raw_bytes)

        return True

class VersionRecordCertDecoder(object):

    _byte_map: mmap = None

    def __init__(self, filepath: str):
        with open(filepath, "r+b") as raw_file:
            self._byte_map = mmap.mmap(raw_file.fileno(), 0)

    def get_record_list(self) -> list:
        rule_list = []
        bytes_read = 0
        print ("mmap length: ", len(self._byte_map))
        while bytes_read < self._byte_map.size():
            header = struct.unpack_from(_VersionRecordCertEntryStruct._STRUCT_HEADER, self._byte_map, bytes_read)
            company_off = bytes_read + struct.calcsize(_VersionRecordCertEntryStruct._STRUCT_HEADER)
            company_name_raw = self._byte_map[company_off:company_off + header[3] - 2]
            company_name = company_name_raw.decode(_VersionRecordCertEntryStruct._STRING_ENCODING)
            print ("Decoded company name: " + company_name)
            product_name = None
            if header[4] != 0:
                product_off = company_off + header[3]
                product_name_raw = self._byte_map[product_off:product_off + header[4] - 2]
                product_name = product_name_raw.decode(_VersionRecordCertEntryStruct._STRING_ENCODING)
                print ("Decoded product name: " + product_name)
                print ("Decoded product name len: ", len(product_name))

            formatted_rule = _VersionRecordCertEntryStruct(header[2], header[5], company_name, product_name).unpack_from(self._byte_map, bytes_read)
            cur_list = [formatted_rule.company_name]
            if formatted_rule.product_name:
                cur_list.append(formatted_rule.product_name)
            if formatted_rule.compare_rule != VersionRecordCert.NO_FILEVERSION:
                cur_list.append(VersionRecordCert.OPERATOR_CODES[formatted_rule.compare_rule])
                cur_list.append(formatted_rule.file_version)

            rule_list.append(cur_list)
            bytes_read += header[0]
    
        return rule_list

rule_gen = VersionRecordCertGenerator("test.json").write("out")
decode = VersionRecordCertDecoder("out")
print(decode.get_record_list())