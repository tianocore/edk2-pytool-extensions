"""FPDT Parser Tool.

Copyright (c) Microsoft Corporation
SPDX-License-Identifier: BSD-2-Clause-Patent

This module provides functionality to parse the Firmware Performance Data Table (FPDT) and Firmware Basic
Performance Table (FBPT) from Windows systems. It supports extracting and storing the parsed data in
various formats such as text and XML.

Classes:
    AcpiTableHeader:
        Represents the header of an ACPI table and provides methods to parse, display, and convert it to XML.
    FwBasicBootPerformanceRecord:
        Represents a Firmware Basic Boot Performance Record and provides methods to parse, display, and convert
        it to XML.
    FwBasicBootPerformanceTableHeader:
        Represents the Firmware Basic Boot Performance Table Header and provides methods to parse, display, and
        convert it to XML.
    FbptRecordHeader:
        Represents the header of a Firmware Boot Performance Table (FBPT) record and provides methods to parse,
        display, and convert it to XML.
    FwBasicBootPerformanceDataRecord:
        Represents a firmware basic boot performance data record and provides methods to parse, display, and
        convert it to XML.
    GuidEventRecord:
        Represents a GUID Event Record and provides methods to parse, display, and convert it to XML.
    DynamicStringEventRecord:
        Represents a dynamic string event record and provides methods to parse, display, and convert it to XML.
    DualGuidStringEventRecord:
        Represents a Dual GUID String Event Record and provides methods to parse, display, and convert it to XML.
    GuidQwordEventRecord:
        Represents a GUID Qword Event Record and provides methods to parse, display, and convert it to XML.
    GuidQwordStringEventRecord:
        Represents a GUID Qword String Event Record and provides methods to parse, display, and convert it to XML.
    SystemFirmwareTable:
        Provides services to interact with system firmware tables using Windows APIs.

Functions:
    fbpt_parsing_factory(fbpt_contents_file: BinaryIO, fbpt_records_list: list) -> int:
        Parses Firmware Boot Performance Table (FBPT) records from a binary file and appends them to a list.
    get_uefi_version() -> str:
        Retrieves the UEFI version from the system's BIOS information.
    get_model() -> str:
        Retrieves the model name of the computer system using WMI (Windows Management Instrumentation).

Usage:
    This script can be executed as a standalone tool to parse FPDT and FBPT data. It supports command-line
    arguments for specifying input binary files, output text files, and output XML files.

Command-line Arguments:
    -t, --output_text: Name of the output text file to store FPDT information.
    -x, --output_xml: Name of the output XML file to store FPDT information.
    -b, --input_bin: Name of the input binary file containing the FBPT.

Example:
    python fpdt_parser.py -x fpdt_output.xml
"""

import argparse
import ctypes
import datetime
import logging
import os
import re
import struct
import sys
import xml.etree.ElementTree as ET
from ctypes import (
    POINTER,
    WinError,
    c_int,
    c_ulong,
    c_void_p,
    create_string_buffer,
    pointer,
    windll,
)
from io import TextIOWrapper
from typing import BinaryIO
from xml.dom import minidom

FPDT_PARSER_VER = "3.00"

FIRMWARE_BASIC_BOOT_PERFORMANCE_DATA_EVENT_TYPE = 0x0002
GUID_EVENT_TYPE = 0x1010
FPDT_DYNAMIC_STRING_EVENT_TYPE = 0x1011
FPDT_DUAL_GUID_STRING_EVENT_TYPE = 0x1012
FPDT_GUID_QWORD_EVENT_TYPE = 0x1013
FPDT_GUID_QWORD_STRING_EVENT_TYPE = 0x1014
DYNAMIC_STRING_EVENT_TYPE = 0x2001
DUAL_GUID_STRING_EVENT_TYPE = 0x2002
GUID_QWORD_EVENT_TYPE = 0x2003
GUID_QWORD_STRING_EVENT_TYPE = 0x2004

KNOWN_FBPT_RECORD_TYPES = [
    FIRMWARE_BASIC_BOOT_PERFORMANCE_DATA_EVENT_TYPE,
    GUID_EVENT_TYPE,
    DYNAMIC_STRING_EVENT_TYPE,
    DUAL_GUID_STRING_EVENT_TYPE,
    GUID_QWORD_EVENT_TYPE,
    GUID_QWORD_STRING_EVENT_TYPE,
    FPDT_DYNAMIC_STRING_EVENT_TYPE,
    FPDT_DUAL_GUID_STRING_EVENT_TYPE,
    FPDT_GUID_QWORD_EVENT_TYPE,
    FPDT_GUID_QWORD_STRING_EVENT_TYPE,
]


class AcpiTableHeader(object):
    """Represents the header of an ACPI table header.

    Provides methods to parse, display, and convert the header data into different formats.

    Attributes:
        struct_format (str): The struct format string used for unpacking the header.
        size (int): The size of the ACPI table header in bytes.
        signature (str): The signature of the ACPI table (decoded from bytes).
        length (int): The length of the ACPI table in bytes.
        revision (int): The revision of the ACPI table.
        checksum (int): The checksum of the ACPI table.
        oem_id (bytes): The OEM ID associated with the ACPI table.
        oem_table_id (bytes): The OEM table ID associated with the ACPI table.
        oem_revision (int): The OEM revision of the ACPI table.
        creator_id (bytes): The ID of the creator of the ACPI table.
        creator_revision (int): The revision of the creator of the ACPI table.

    Methods:
        to_xml():
            Converts the ACPI table header to an XML representation.
    """

    struct_format = "=4sIBB6s8sI4sI"
    size = struct.calcsize(struct_format)

    def __init__(self, header_byte_array: bytes) -> None:
        """Initialize an AcpiTableHeader instance by unpacking data from a byte array.

        Args:
            header_byte_array (bytes): A byte array containing the ACPI table header data.
        """
        (
            self.signature,
            self.length,
            self.revision,
            self.checksum,
            self.oem_id,
            self.oem_table_id,
            self.oem_revision,
            self.creator_id,
            self.creator_revision,
        ) = struct.unpack_from(AcpiTableHeader.struct_format, header_byte_array)
        self.signature = self.signature.decode("ascii")

    def __str__(self) -> str:
        """Generate a string representation of the object.

        Returns:
            str: A formatted string representation of the object's data.
        """
        return f"""
  ACPI Table Header
------------------------------------------------------------------
  Signature        : {self.signature}
  Length           : 0x{self.length:08X}
  Revision         : 0x{self.revision:02X}
  Checksum         : 0x{self.checksum:02X}
  OEM ID           : {self.oem_id}
  OEM Table ID     : {self.oem_table_id}
  OEM Revision     : 0x{self.oem_revision:08X}
  Creator ID       : {self.creator_id}
  Creator Revision : 0x{self.creator_revision:08X}
"""

    def to_xml(self) -> ET.Element:
        """Converts the object's data into an XML representation.

        Returns:
            ET.Element: An XML element containing the serialized data of the object.
        """
        xml_repr = ET.Element("AcpiTableHeader")
        xml_repr.set("Signature", f"{self.signature}")
        xml_repr.set("Length", f"0x{self.length:X}")
        xml_repr.set("Revision", f"0x{self.revision:X}")
        xml_repr.set("Checksum", f"0x{self.checksum:X}")
        xml_repr.set("OEMID", f"{self.oem_id}")
        xml_repr.set("OEMTableID", f"{self.oem_table_id}")
        xml_repr.set("OEMRevision", f"0x{self.oem_revision:X}")
        xml_repr.set("CreatorID", f"{self.creator_id}")
        xml_repr.set("CreatorRevision", f"0x{self.creator_revision:X}")
        return xml_repr


class FwBasicBootPerformanceRecord(object):
    """Represents a Firmware Basic Boot Performance Record.

    Attributes:
        struct_format (str): The struct format string used for unpacking the binary data.
        size (int): The size of the structure in bytes, calculated using the struct format.
        performance_record_type (int): The type of the performance record.
        record_length (int): The length of the record.
        revision (int): The revision of the record.
        reserved (int): Reserved field for future use.
        fbpt_pointer (int): Pointer to the Firmware Boot Performance Table (FBPT).

    Methods:
        to_xml(): Converts the record's data into an XML representation.
    """

    struct_format = "=HBBIQ"
    size = struct.calcsize(struct_format)

    def __init__(self, record_byte_array: bytes) -> None:
        """Initializes an instance of the FwBasicBootPerformanceRecord class.

        Args:
            record_byte_array (bytes): A byte array containing the performance record
                                       data to be unpacked.
        """
        (
            self.performance_record_type,
            self.record_length,
            self.revision,
            self.reserved,
            self.fbpt_pointer,
        ) = struct.unpack_from(FwBasicBootPerformanceRecord.struct_format, record_byte_array)

    def __str__(self) -> str:
        """Generate a string representation of the object.

        Returns:
            str: A formatted string representation of the object's data.
        """
        return f"""
  Firmware Basic Boot Performance Record
------------------------------------------------------------------
  Performance Record Type : 0x{self.performance_record_type:04X}
  Record Length           : 0x{self.record_length:02X}
  Revision                : 0x{self.revision:02X}
  Reserved                : 0x{self.reserved:08X}
  FBPT Pointer            : 0x{self.fbpt_pointer:016X}
"""

    def to_xml(self) -> ET.Element:
        """Converts the object's data into an XML representation.

        Returns:
            ET.Element: An XML element containing the serialized data of the object.
        """
        xml_repr = ET.Element("FwBasicBootPerformanceRecord")
        xml_repr.set("PerformanceRecordType", f"0x{self.performance_record_type:X}")
        xml_repr.set("RecordLength", f"0x{self.record_length:X}")
        xml_repr.set("Revision", f"0x{self.revision:X}")
        xml_repr.set("Reserved", f"0x{self.reserved:X}")
        xml_repr.set("FBPTPointer", f"0x{self.fbpt_pointer:X}")
        return xml_repr


class FwBasicBootPerformanceTableHeader(object):
    """Represents the Firmware Basic Boot Performance Table Header.

    This class is used to parse and represent the header of a firmware basic boot
    performance table. It provides methods to interpret the header data, convert
    it to a string representation, and serialize it into an XML format.

    Attributes:
        struct_format (str): The format string used for unpacking the binary data.
        size (int): The size of the header structure in bytes.
        signature (str): The ASCII signature of the header.
        length (int): The length of the header in bytes.

    Methods:
        to_xml(): Converts the record's data into an XML representation.
    """

    struct_format = "=4sI"
    size = struct.calcsize(struct_format)

    def __init__(self, header_byte_array: bytes) -> None:
        """Initializes an instance of the FwBasicBootPerformanceTableHeader class.

        Args:
            header_byte_array (bytes): A byte array containing the header data.
                                       It is unpacked to extract the signature and length.
        """
        (self.signature, self.length) = struct.unpack_from(
            FwBasicBootPerformanceTableHeader.struct_format, header_byte_array
        )
        self.signature = self.signature.decode("ascii")

    def __str__(self) -> str:
        """Generate a string representation of the object.

        Returns:
            str: A formatted string representation of the object's data.
        """
        return f"""
  Firmware Basic Boot Performance Table Header
------------------------------------------------------------------
  Signature : {self.signature}
  Length    : 0x{self.length:08X}
"""

    def to_xml(self) -> ET.Element:
        """Converts the object's data into an XML representation.

        Returns:
            ET.Element: An XML element containing the serialized data of the object.
        """
        xml_repr = ET.Element("Fbpt")
        xml_repr.set("Signature", f"{self.signature}")
        xml_repr.set("Length", f"0x{self.length:X}")
        return xml_repr


class FbptRecordHeader(object):
    """Represents the header of a Firmware Boot Performance Table (FBPT) record.

    Attributes:
        struct_format (str): The format string used for unpacking the header data.
        size (int): The size of the header structure in bytes.
        performance_record_type (int): The type of the performance record.
        record_length (int): The length of the record.
        revision (int): The revision of the record.

    Methods:
        to_xml(): Converts the record's data into an XML representation.
    """

    struct_format = "=HBB"
    size = struct.calcsize(struct_format)

    def __init__(self, header_byte_array: bytes) -> None:
        """Initializes an instance of the class by parsing a header byte array.

        Args:
            header_byte_array (bytes): A byte array containing the header data to be parsed.
        """
        (self.performance_record_type, self.record_length, self.revision) = struct.unpack_from(
            FbptRecordHeader.struct_format, header_byte_array
        )

    def __str__(self) -> str:
        """Generate a string representation of the object.

        Returns:
            str: A formatted string representation of the object's data.
        """
        return f"""
  FBPT Record Header
------------------------------------------------------------------
  Performance Record Type : 0x{self.performance_record_type:04X}
  Record Length           : 0x{self.record_length:02X}
  Revision                : 0x{self.revision:02X}
"""

    def to_xml(self) -> ET.Element:
        """Converts the object's data into an XML representation.

        Returns:
            ET.Element: An XML element containing the serialized data of the object.
        """
        if self.performance_record_type == FIRMWARE_BASIC_BOOT_PERFORMANCE_DATA_EVENT_TYPE:
            xml_repr = ET.Element("FirmwareBasicBootPerformanceEvent")
        elif self.performance_record_type == GUID_EVENT_TYPE:
            xml_repr = ET.Element("GuidEvent")
        elif (
            self.performance_record_type == DYNAMIC_STRING_EVENT_TYPE
            or self.performance_record_type == FPDT_DYNAMIC_STRING_EVENT_TYPE
        ):
            xml_repr = ET.Element("DynamicStringEvent")
        elif (
            self.performance_record_type == DUAL_GUID_STRING_EVENT_TYPE
            or self.performance_record_type == FPDT_DUAL_GUID_STRING_EVENT_TYPE
        ):
            xml_repr = ET.Element("DualGuidStringEvent")
        elif (
            self.performance_record_type == GUID_QWORD_EVENT_TYPE
            or self.performance_record_type == FPDT_GUID_QWORD_EVENT_TYPE
        ):
            xml_repr = ET.Element("GuidQwordEvent")
        elif (
            self.performance_record_type == GUID_QWORD_STRING_EVENT_TYPE
            or self.performance_record_type == FPDT_GUID_QWORD_STRING_EVENT_TYPE
        ):
            xml_repr = ET.Element("GuidQwordStringEvent")
        else:
            logging.critical("Creating XML out of an unknown type record!")
            xml_repr = ET.Element("UnknownEvent")

        xml_repr.set("PerformanceRecordType", f"0x{self.performance_record_type:X}")
        xml_repr.set("RecordLength", f"0x{self.record_length:X}")
        xml_repr.set("Revision", f"0x{self.revision:X}")

        return xml_repr


class FwBasicBootPerformanceDataRecord(object):
    """Represents a firmware basic boot performance data record.

    Attributes:
        struct_format (str): The format string used for unpacking the binary data.
        size (int): The size of the binary data structure in bytes.
        header: The record header containing metadata about the performance data.
        reserved (int): Reserved field in the performance data record.
        reset_end (int): Timestamp indicating the end of the reset phase.
        os_loader_load_image_start (int): Timestamp indicating the start of loading the OS loader image.
        os_loader_start_image_start (int): Timestamp indicating the start of the OS loader image execution.
        exit_boot_services_entry (int): Timestamp indicating the entry point of the ExitBootServices call.
        exit_boot_services_exit (int): Timestamp indicating the exit point of the ExitBootServices call.

    Methods:
        to_xml(): Converts the performance data record to an XML representation.
    """

    struct_format = "=IQQQQQ"
    size = struct.calcsize(struct_format)

    def __init__(self, record_header: FbptRecordHeader, contents_byte_array: bytes) -> None:
        """Initializes an instance of the FwBasicBootPerformanceDataRecord class.

        Args:
            record_header (FbptRecordHeader): The header information for the firmware boot performance record.
            contents_byte_array (bytes): A byte array containing the performance data record contents.
        """
        self.header = record_header
        (
            self.reserved,
            self.reset_end,
            self.os_loader_load_image_start,
            self.os_loader_start_image_start,
            self.exit_boot_services_entry,
            self.exit_boot_services_exit,
        ) = struct.unpack_from(FwBasicBootPerformanceDataRecord.struct_format, contents_byte_array)

    def __str__(self) -> str:
        """Generate a string representation of the object.

        Returns:
            str: A formatted string representation of the object's data.
        """
        return (
            f"{self.header}\n"
            f"""  FW Basic Boot Performance Data Record Contents
------------------------------------------------------------------
  Reserved                   : 0x{self.reserved:08X}
  Reset End                  : 0x{self.reset_end:016X}
  OS Loader LoadImage Start  : 0x{self.os_loader_load_image_start:016X}
  OS Loader StartImage Start : 0x{self.os_loader_start_image_start:016X}
  ExitBootServices Entry     : 0x{self.exit_boot_services_entry:016X}
  ExitBootServices Exit      : 0x{self.exit_boot_services_exit:016X}
"""
        )

    def to_xml(self) -> ET.Element:
        """Converts the object's data into an XML representation.

        Returns:
            ET.Element: An XML element containing the serialized data of the object.
        """
        xml_repr = self.header.to_xml()

        reset_end_xml = ET.SubElement(xml_repr, "ResetEnd")
        reset_end_xml.set("RawValue", f"0x{self.reset_end:X}")
        reset_end_xml.set("ValueInMilliseconds", f"{self.reset_end / 1000000.0:.6f}")

        os_loader_load_image_start_xml = ET.SubElement(xml_repr, "OSLoaderLoadImageStart")
        os_loader_load_image_start_xml.set("RawValue", f"0x{self.os_loader_load_image_start:X}")
        os_loader_load_image_start_xml.set("ValueInMilliseconds", f"{self.os_loader_load_image_start / 1000000.0:.6f}")

        os_loader_start_image_start_xml = ET.SubElement(xml_repr, "OSLoaderStartImageStart")
        os_loader_start_image_start_xml.set("RawValue", f"0x{self.os_loader_start_image_start:X}")
        os_loader_start_image_start_xml.set(
            "ValueInMilliseconds", f"{self.os_loader_start_image_start / 1000000.0:.6f}"
        )

        exit_boot_services_entry_xml = ET.SubElement(xml_repr, "ExitBootServicesEntry")
        exit_boot_services_entry_xml.set("RawValue", f"0x{self.exit_boot_services_entry:X}")
        exit_boot_services_entry_xml.set("ValueInMilliseconds", f"{self.exit_boot_services_entry / 1000000.0:.6f}")

        exit_boot_services_exit_xml = ET.SubElement(xml_repr, "ExitBootServicesExit")
        exit_boot_services_exit_xml.set("RawValue", f"0x{self.exit_boot_services_exit:X}")
        exit_boot_services_exit_xml.set("ValueInMilliseconds", f"{self.exit_boot_services_exit / 1000000.0:.6f}")

        return xml_repr


class GuidEventRecord(object):
    """Represents a GUID Event Record parsed from a binary data structure.

    Attributes:
        struct_format (str): The format string used for unpacking the binary data.
        size (int): The size of the binary structure as calculated by `struct.calcsize`.

    Methods:
        to_xml(): Converts the event record to an XML representation.
    """

    struct_format = "=HIQIHHBBBBBBBB"
    size = struct.calcsize(struct_format)

    def __init__(self, record_header: FbptRecordHeader, contents_byte_array: bytes) -> None:
        """Initializes a GuidEventRecord instance.

        Args:
            record_header (FbptRecordHeader): The header of the record containing metadata.
            contents_byte_array (bytes): A byte array containing the data for the GUID event record.
        """
        self.header = record_header
        (
            self.progress_id,
            self.apic_id,
            self.timestamp,
            self.guid_uint32,
            self.guid_uint16_0,
            self.guid_uint16_1,
            self.guid_uint8_0,
            self.guid_uint8_1,
            self.guid_uint8_2,
            self.guid_uint8_3,
            self.guid_uint8_4,
            self.guid_uint8_5,
            self.guid_uint8_6,
            self.guid_uint8_7,
        ) = struct.unpack_from(GuidEventRecord.struct_format, contents_byte_array)

    def __str__(self) -> str:
        """Generate a string representation of the object.

        Returns:
            str: A formatted string representation of the object's data.
        """
        return (
            f"{self.header}\n"
            f"""  GUID Event Record Contents
------------------------------------------------------------------
  Progress ID : 0x%04X
  Apic ID     : 0x%08X
  Timestamp   : 0x%016X
  GUID        : %08X-%04X-%04X-%02X%02X-%02X%02X%02X%02X%02X%02X
"""
            % (
                self.progress_id,
                self.apic_id,
                self.timestamp,
                self.guid_uint32,
                self.guid_uint16_0,
                self.guid_uint16_1,
                self.guid_uint8_0,
                self.guid_uint8_1,
                self.guid_uint8_2,
                self.guid_uint8_3,
                self.guid_uint8_4,
                self.guid_uint8_5,
                self.guid_uint8_6,
                self.guid_uint8_7,
            )
        )

    def to_xml(self) -> ET.Element:
        """Converts the object's data into an XML representation.

        Returns:
            ET.Element: An XML element containing the serialized data of the object.
        """
        xml_repr = self.header.to_xml()

        progress_id_xml = ET.SubElement(xml_repr, "ProgressID")
        progress_id_xml.set("Value", f"0x{self.progress_id:X}")

        apic_id_xml = ET.SubElement(xml_repr, "ApicID")
        apic_id_xml.set("Value", f"0x{self.apic_id:X}")

        timestamp_xml = ET.SubElement(xml_repr, "Timestamp")
        timestamp_xml.set("RawValue", f"0x{self.timestamp:X}")
        timestamp_xml.set("ValueInMilliseconds", f"{self.timestamp / 1000000.0:.6f}")

        guid_xml = ET.SubElement(xml_repr, "GUID")
        guid_xml.set(
            "Value",
            "%08X-%04X-%04X-%02X%02X-%02X%02X%02X%02X%02X%02X"
            % (
                self.guid_uint32,
                self.guid_uint16_0,
                self.guid_uint16_1,
                self.guid_uint8_0,
                self.guid_uint8_1,
                self.guid_uint8_2,
                self.guid_uint8_3,
                self.guid_uint8_4,
                self.guid_uint8_5,
                self.guid_uint8_6,
                self.guid_uint8_7,
            ),
        )

        return xml_repr


class DynamicStringEventRecord(object):
    """Represents a dynamic string event record.

    Provides methods to parse the binary data, represent the record as a string, and convert it to
    an XML representation.

    Attributes:
        struct_format (str): The format string used to unpack the binary data.
        size (int): The size of the binary data structure.
        header: The record header containing metadata.
        string (str): The extracted and sanitized string from the binary data.
        progress_id (int): The progress ID of the event.
        apic_id (int): The APIC ID associated with the event.
        timestamp (int): The timestamp of the event in raw format.
        guid_uint32 (int): The first 32 bits of the GUID.
        guid_uint16_0 (int): The first 16-bit segment of the GUID.
        guid_uint16_1 (int): The second 16-bit segment of the GUID.
        guid_uint8_0 to guid_uint8_7 (int): The 8 individual bytes of the GUID.

    Methods:
        to_xml(): Converts the event record to an XML representation.
    """

    struct_format = "=HIQIHHBBBBBBBB"
    size = struct.calcsize(struct_format)

    def __init__(
        self,
        record_header: FbptRecordHeader,
        contents_byte_array: bytes,
        string_byte_array: bytes,
        string_size: int,
    ) -> None:
        """Initializes a DynamicStringEventRecord instance.

        Args:
            record_header (FbptRecordHeader): The header of the FBPT record.
            contents_byte_array (bytes): Byte array containing the contents of the record.
            string_byte_array (bytes): Byte array containing the string data.
            string_size (int): The size of the string in bytes.
        """
        self.header = record_header
        string_format = f"={string_size}s"
        self.string = struct.unpack_from(string_format, string_byte_array)[0]
        (
            self.progress_id,
            self.apic_id,
            self.timestamp,
            self.guid_uint32,
            self.guid_uint16_0,
            self.guid_uint16_1,
            self.guid_uint8_0,
            self.guid_uint8_1,
            self.guid_uint8_2,
            self.guid_uint8_3,
            self.guid_uint8_4,
            self.guid_uint8_5,
            self.guid_uint8_6,
            self.guid_uint8_7,
        ) = struct.unpack_from(DynamicStringEventRecord.struct_format, contents_byte_array)
        try:
            self.string = self.string[: self.string.index(b"\x00")]
        except ValueError:
            logging.critical("String in a Dynamic String Record does not contain a null terminator")
        self.string = "".join(
            [i if ((ord(i) == 0) or ((ord(i) > 31) and (ord(i) < 127))) else "?" for i in self.string.decode("ascii")]
        )

    def __str__(self) -> str:
        """Generate a string representation of the object.

        Returns:
            str: A formatted string representation of the object's data.
        """
        string = self.string.split("\x00")
        return (
            f"{self.header}\n"
            f"""  Dynamic String Event Record Contents
    ------------------------------------------------------------------
      Progress ID : 0x{self.progress_id:04X}
      Apic ID     : 0x{self.apic_id:08X}
      Timestamp   : 0x{self.timestamp:016X}
      GUID        : {self.guid_uint32:08X}-{self.guid_uint16_0:04X}-{self.guid_uint16_1:04X}-"""
            f"""{self.guid_uint8_0:02X}{self.guid_uint8_1:02X}-{self.guid_uint8_2:02X}{self.guid_uint8_3:02X}"""
            f"""{self.guid_uint8_4:02X}{self.guid_uint8_5:02X}{self.guid_uint8_6:02X}{self.guid_uint8_7:02X}
      String      : {string}
    """
        )

    def to_xml(self) -> ET.Element:
        """Converts the object's data into an XML representation.

        Returns:
            ET.Element: An XML element containing the serialized data of the object.
        """
        xml_repr = self.header.to_xml()

        progress_id_xml = ET.SubElement(xml_repr, "ProgressID")
        progress_id_xml.set("Value", f"0x{self.progress_id:X}")

        apic_id_xml = ET.SubElement(xml_repr, "ApicID")
        apic_id_xml.set("Value", f"0x{self.apic_id:X}")

        timestamp_xml = ET.SubElement(xml_repr, "Timestamp")
        timestamp_xml.set("RawValue", f"0x{self.timestamp:X}")
        timestamp_xml.set("ValueInMilliseconds", f"{self.timestamp / 1000000.0:.6f}")

        guid_xml = ET.SubElement(xml_repr, "GUID")
        guid_xml.set(
            "Value",
            "%08X-%04X-%04X-%02X%02X-%02X%02X%02X%02X%02X%02X"
            % (
                self.guid_uint32,
                self.guid_uint16_0,
                self.guid_uint16_1,
                self.guid_uint8_0,
                self.guid_uint8_1,
                self.guid_uint8_2,
                self.guid_uint8_3,
                self.guid_uint8_4,
                self.guid_uint8_5,
                self.guid_uint8_6,
                self.guid_uint8_7,
            ),
        )

        string_xml = ET.SubElement(xml_repr, "String")
        sanitized_string = self.string.split("\x00")[0]
        string_xml.set("Value", sanitized_string)

        return xml_repr


class DualGuidStringEventRecord(object):
    """Represents a Dual GUID String Event Record.

    Provides methods to parse the binary data, represent it as a string, and convert it to an XML representation.

    Attributes:
        struct_format (str): The format string used for unpacking the binary data.
        size (int): The size of the binary structure based on the format string.
        header: The record header associated with this event record.
        string (str): The parsed string from the binary data.
        progress_id (int): The progress ID of the event.
        apic_id (int): The APIC ID of the event.
        timestamp (int): The timestamp of the event in raw format.
        guid1_*: Components of the first GUID (GUID1).
        guid2_*: Components of the second GUID (GUID2).

    Methods:
        to_xml(): Converts the event record to an XML representation.
    """

    struct_format = "=HIQIHHBBBBBBBBIHHBBBBBBBB"
    size = struct.calcsize(struct_format)

    def __init__(
        self,
        record_header: FbptRecordHeader,
        contents_byte_array: bytes,
        string_byte_array: bytes,
        string_size: int,
    ) -> None:
        """Initializes a DualGuidStringEventRecord instance.

        Args:
            record_header (FbptRecordHeader): The header of the record.
            contents_byte_array (bytes): Byte array containing the record's content data.
            string_byte_array (bytes): Byte array containing the string data.
            string_size (int): The size of the string in bytes.
        """
        self.header = record_header
        string_format = f"={string_size}s"
        self.string = struct.unpack_from(string_format, string_byte_array)[0]
        (
            self.progress_id,
            self.apic_id,
            self.timestamp,
            self.guid1_uint32,
            self.guid1_uint16_0,
            self.guid1_uint16_1,
            self.guid1_uint8_0,
            self.guid1_uint8_1,
            self.guid1_uint8_2,
            self.guid1_uint8_3,
            self.guid1_uint8_4,
            self.guid1_uint8_5,
            self.guid1_uint8_6,
            self.guid1_uint8_7,
            self.guid2_uint32,
            self.guid2_uint16_0,
            self.guid2_uint16_1,
            self.guid2_uint8_0,
            self.guid2_uint8_1,
            self.guid2_uint8_2,
            self.guid2_uint8_3,
            self.guid2_uint8_4,
            self.guid2_uint8_5,
            self.guid2_uint8_6,
            self.guid2_uint8_7,
        ) = struct.unpack_from(DualGuidStringEventRecord.struct_format, contents_byte_array)
        try:
            self.string = self.string[: self.string.index(b"\x00")]
        except ValueError:
            logging.critical("String in a Dual GUID String Record does not contain a null terminator")
        self.string = "".join(
            [i if ((ord(i) == 0) or ((ord(i) > 31) and (ord(i) < 127))) else "?" for i in self.string.decode("ascii")]
        )

    def __str__(self) -> str:
        """Generate a string representation of the object.

        Returns:
            str: A formatted string representation of the object's data.
        """
        return (
            f"{self.header}\n"
            f"""  Dual GUID String Event Record Contents
------------------------------------------------------------------
  Progress ID : 0x%04X
  Apic ID     : 0x%08X
  Timestamp   : 0x%016X
  GUID1       : %08X-%04X-%04X-%02X%02X-%02X%02X%02X%02X%02X%02X
  GUID2       : %08X-%04X-%04X-%02X%02X-%02X%02X%02X%02X%02X%02X
  String      : %s
"""
            % (
                self.progress_id,
                self.apic_id,
                self.timestamp,
                self.guid1_uint32,
                self.guid1_uint16_0,
                self.guid1_uint16_1,
                self.guid1_uint8_0,
                self.guid1_uint8_1,
                self.guid1_uint8_2,
                self.guid1_uint8_3,
                self.guid1_uint8_4,
                self.guid1_uint8_5,
                self.guid1_uint8_6,
                self.guid1_uint8_7,
                self.guid2_uint32,
                self.guid2_uint16_0,
                self.guid2_uint16_1,
                self.guid2_uint8_0,
                self.guid2_uint8_1,
                self.guid2_uint8_2,
                self.guid2_uint8_3,
                self.guid2_uint8_4,
                self.guid2_uint8_5,
                self.guid2_uint8_6,
                self.guid2_uint8_7,
                self.string.split("\x00")[0],
            )
        )

    def to_xml(self) -> ET.Element:
        """Converts the object's data into an XML representation.

        Returns:
            ET.Element: An XML element containing the serialized data of the object.
        """
        xml_repr = self.header.to_xml()

        progress_id_xml = ET.SubElement(xml_repr, "ProgressID")
        progress_id_xml.set("Value", f"0x{self.progress_id:X}")

        apic_id_xml = ET.SubElement(xml_repr, "ApicID")
        apic_id_xml.set("Value", f"0x{self.apic_id:X}")

        timestamp_xml = ET.SubElement(xml_repr, "Timestamp")
        timestamp_xml.set("RawValue", f"0x{self.timestamp:X}")
        timestamp_xml.set("ValueInMilliseconds", f"{self.timestamp / 1000000.0:.6f}")

        guid1_xml = ET.SubElement(xml_repr, "GUID1")
        guid1_xml.set(
            "Value",
            f"{self.guid1_uint32:08X}-{self.guid1_uint16_0:04X}-{self.guid1_uint16_1:04X}-"
            f"{self.guid1_uint8_0:02X}{self.guid1_uint8_1:02X}-{self.guid1_uint8_2:02X}{self.guid1_uint8_3:02X}"
            f"{self.guid1_uint8_4:02X}{self.guid1_uint8_5:02X}{self.guid1_uint8_6:02X}{self.guid1_uint8_7:02X}",
        )

        guid2_xml = ET.SubElement(xml_repr, "GUID2")
        guid2_xml.set(
            "Value",
            f"{self.guid2_uint32:08X}-{self.guid2_uint16_0:04X}-{self.guid2_uint16_1:04X}-"
            f"{self.guid2_uint8_0:02X}{self.guid2_uint8_1:02X}-{self.guid2_uint8_2:02X}{self.guid2_uint8_3:02X}"
            f"{self.guid2_uint8_4:02X}{self.guid2_uint8_5:02X}{self.guid2_uint8_6:02X}{self.guid2_uint8_7:02X}",
        )

        string_xml = ET.SubElement(xml_repr, "String")
        string = self.string.split("\x00")[0]
        string_xml.set("Value", f"{string}")

        return xml_repr


class GuidQwordEventRecord(object):
    """Represents a GUID Qword Event Record.

    Provides methods to convert the parsed data into human-readable string and XML representations.

    Attributes:
        struct_format (str): The format string used for unpacking the binary data.
        size (int): The size of the binary structure, calculated using the struct format.
        header: The record header associated with the event.
        progress_id (int): The progress ID of the event.
        apic_id (int): The APIC ID of the event.
        timestamp (int): The timestamp of the event in raw format.
        guid_uint32 (int): The first 32 bits of the GUID.
        guid_uint16_0 (int): The first 16-bit segment of the GUID.
        guid_uint16_1 (int): The second 16-bit segment of the GUID.
        guid_uint8_0 to guid_uint8_7 (int): The 8 individual bytes of the GUID.
        qword (int): A 64-bit value associated with the event.

    Methods:
        to_xml(): Converts the event record to an XML representation.
    """

    struct_format = "=HIQIHHBBBBBBBBQ"
    size = struct.calcsize(struct_format)

    def __init__(self, record_header: FbptRecordHeader, contents_byte_array: bytes) -> None:
        """Initializes a GuidQwordEventRecord instance.

        Args:
            record_header (FbptRecordHeader): The header of the FBPT record.
            contents_byte_array (bytes): The byte array containing the record data.
        """
        self.header = record_header
        (
            self.progress_id,
            self.apic_id,
            self.timestamp,
            self.guid_uint32,
            self.guid_uint16_0,
            self.guid_uint16_1,
            self.guid_uint8_0,
            self.guid_uint8_1,
            self.guid_uint8_2,
            self.guid_uint8_3,
            self.guid_uint8_4,
            self.guid_uint8_5,
            self.guid_uint8_6,
            self.guid_uint8_7,
            self.qword,
        ) = struct.unpack_from(GuidQwordEventRecord.struct_format, contents_byte_array)

    def __str__(self) -> str:
        """Generate a string representation of the object.

        Returns:
            str: A formatted string representation of the object's data.
        """
        return (
            f"{self.header}\n"
            f"""  GUID Qword Event Record Contents
------------------------------------------------------------------
  Progress ID : 0x{self.progress_id:04X}
  Apic ID     : 0x{self.apic_id:08X}
  Timestamp   : 0x{self.timestamp:016X}
  GUID        : {self.guid_uint32:08X}-{self.guid_uint16_0:04X}-{self.guid_uint16_1:04X}-"""
            f"""{self.guid_uint8_0:02X}{self.guid_uint8_1:02X}{self.guid_uint8_2:02X}{self.guid_uint8_3:02X}"""
            f"""{self.guid_uint8_4:02X}{self.guid_uint8_5:02X}{self.guid_uint8_6:02X}{self.guid_uint8_7:02X}
  Qword       : 0x{self.qword:016X}
"""
        )

    def to_xml(self) -> ET.Element:
        """Converts the object's data into an XML representation.

        Returns:
            ET.Element: An XML element containing the serialized data of the object.
        """
        xml_repr = self.header.to_xml()

        progress_id_xml = ET.SubElement(xml_repr, "ProgressID")
        progress_id_xml.set("Value", f"0x{self.progress_id:X}")

        apic_id_xml = ET.SubElement(xml_repr, "ApicID")
        apic_id_xml.set("Value", f"0x{self.apic_id:X}")

        timestamp_xml = ET.SubElement(xml_repr, "Timestamp")
        timestamp_xml.set("RawValue", f"0x{self.timestamp:X}")
        timestamp_xml.set("ValueInMilliseconds", f"{self.timestamp / 1000000.0:.6f}")

        guid_xml = ET.SubElement(xml_repr, "GUID")
        guid_xml.set(
            "Value",
            f"{self.guid_uint32:08X}-{self.guid_uint16_0:04X}-{self.guid_uint16_1:04X}-"
            f"{self.guid_uint8_0:02X}{self.guid_uint8_1:02X}{self.guid_uint8_2:02X}{self.guid_uint8_3:02X}"
            f"{self.guid_uint8_4:02X}{self.guid_uint8_5:02X}{self.guid_uint8_6:02X}{self.guid_uint8_7:02X}",
        )

        qword_xml = ET.SubElement(xml_repr, "Qword")
        qword_xml.set("Value", f"0x{self.qword:X}")

        return xml_repr


class GuidQwordStringEventRecord(object):
    """Represents a GUID Qword String Event Record."""

    class GuidQwordStringEventRecord:
        """Represents a GUID Qword String Event Record, which parses and stores data from a binary record format.

        Attributes:
            struct_format (str): The format string used for unpacking the binary data.
            size (int): The size of the binary structure as calculated by the struct format.
            header: The header of the record.
            string (str): The parsed string from the binary data, with non-printable characters replaced by '?'.
            progress_id (int): The progress ID extracted from the binary data.
            apic_id (int): The APIC ID extracted from the binary data.
            timestamp (int): The timestamp extracted from the binary data.
            guid_uint32 (int): The first 32 bits of the GUID.
            guid_uint16_0 (int): The first 16 bits of the GUID.
            guid_uint16_1 (int): The second 16 bits of the GUID.
            guid_uint8_0 to guid_uint8_7 (int): The remaining 8 bytes of the GUID.
            qword (int): A 64-bit value extracted from the binary data.

        Methods:
            to_xml(): Converts the event record to an XML representation.
        """

    struct_format = "=HIQIHHBBBBBBBBQ"
    size = struct.calcsize(struct_format)

    def __init__(
        self,
        record_header: FbptRecordHeader,
        contents_byte_array: bytes,
        string_byte_array: bytes,
        string_size: int,
    ) -> None:
        """Initializes a GuidQwordStringEventRecord instance.

        Args:
            record_header (FbptRecordHeader): The header of the FBPT record.
            contents_byte_array (bytes): Byte array containing the contents of the record.
            string_byte_array (bytes): Byte array containing the string data.
            string_size (int): The size of the string in bytes.
        """
        self.header = record_header
        string_format = f"={string_size}s"
        self.string = struct.unpack_from(string_format, string_byte_array)[0]
        (
            self.progress_id,
            self.apic_id,
            self.timestamp,
            self.guid_uint32,
            self.guid_uint16_0,
            self.guid_uint16_1,
            self.guid_uint8_0,
            self.guid_uint8_1,
            self.guid_uint8_2,
            self.guid_uint8_3,
            self.guid_uint8_4,
            self.guid_uint8_5,
            self.guid_uint8_6,
            self.guid_uint8_7,
            self.qword,
        ) = struct.unpack_from(GuidQwordStringEventRecord.struct_format, contents_byte_array)
        # in case string has non-printable chars, let's replace those with '?'
        # first cut off garbage behind the null terminator

        if b"\x00" in self.string:
            self.string = self.string[: self.string.index(b"\x00")]

        self.string = "".join(
            [i if ((ord(i) == 0) or ((ord(i) > 31) and (ord(i) < 127))) else "?" for i in self.string.decode("ascii")]
        )

    def __str__(self) -> str:
        """Generate a string representation of the object.

        Returns:
            str: A formatted string representation of the object's data.
        """
        string = self.string.split("\x00")[0]
        return (
            f"{self.header}\n"
            f"""  GUID Qword String Event Record Contents
------------------------------------------------------------------
  Progress ID : 0x{self.progress_id:04X}
  Apic ID     : 0x{self.apic_id:08X}
  Timestamp   : 0x{self.timestamp:016X}
  GUID        : {self.guid_uint32:08X}-{self.guid_uint16_0:04X}-{self.guid_uint16_1:04X}-"""
            f"""{self.guid_uint8_0:02X}{self.guid_uint8_1:02X}{self.guid_uint8_2:02X}{self.guid_uint8_3:02X}"""
            f"""{self.guid_uint8_4:02X}{self.guid_uint8_5:02X}{self.guid_uint8_6:02X}{self.guid_uint8_7:02X}
  Qword       : 0x{self.qword:016X}
  String      : {string}
"""
        )

    def to_xml(self) -> ET.Element:
        """Converts the object's data into an XML representation.

        Returns:
            xml.etree.ElementTree.Element: The root XML element representing the object.
        """
        xml_repr = self.header.to_xml()

        progress_id_xml = ET.SubElement(xml_repr, "ProgressID")
        progress_id_xml.set("Value", f"0x{self.progress_id:X}")

        apic_id_xml = ET.SubElement(xml_repr, "ApicID")
        apic_id_xml.set("Value", f"0x{self.apic_id:X}")

        timestamp_xml = ET.SubElement(xml_repr, "Timestamp")
        timestamp_xml.set("RawValue", f"0x{self.timestamp:X}")
        timestamp_xml.set("ValueInMilliseconds", f"{self.timestamp / 1000000.0:.6f}")

        guid_xml = ET.SubElement(xml_repr, "GUID")
        guid_xml.set(
            "Value",
            f"{self.guid_uint32:08X}-{self.guid_uint16_0:04X}-{self.guid_uint16_1:04X}-"
            f"{self.guid_uint8_0:02X}{self.guid_uint8_1:02X}{self.guid_uint8_2:02X}{self.guid_uint8_3:02X}"
            f"{self.guid_uint8_4:02X}{self.guid_uint8_5:02X}{self.guid_uint8_6:02X}{self.guid_uint8_7:02X}",
        )

        qword_xml = ET.SubElement(xml_repr, "Qword")
        qword_xml.set("Value", f"0x{self.qword:X}")

        string_xml = ET.SubElement(xml_repr, "String")
        string = self.string.split("\x00")[0]
        string_xml.set("Value", f"{string}")

        return xml_repr


class SystemFirmwareTable:
    """Provides services to get system firmware tables.

    Interacts with Windows APIs like `GetSystemFirmwareTable` and `NtQuerySystemInformation` to perform these
    operations.

    Methods:
        get_acpi_table(table_id: bytes) -> tuple:
            Retrieves an ACPI table from the system firmware.
        get_fbpt() -> tuple:
            Retrieves the Firmware Boot Performance Table (FBPT) using the NtQuerySystemInformation API.
    """

    def __init__(self) -> None:
        """Initializes the class and sets up the necessary privileges and system firmware APIs.

        This constructor:
            1. Enables the `SeSystemEnvironmentPrivilege` privilege for the current process.
            2. Imports and configures the `GetSystemFirmwareTable` and `NtQuerySystemInformation`
               functions from the Windows API for interacting with system firmware and querying
               system information.

        Raises:
            AttributeError: If the required firmware table functions are not available in the
                            Windows API.
        """
        import win32api
        import win32process
        import win32security

        # Enable required SeSystemEnvironmentPrivilege privilege
        privilege = win32security.LookupPrivilegeValue(None, "SeSystemEnvironmentPrivilege")
        token = win32security.OpenProcessToken(
            win32process.GetCurrentProcess(),
            win32security.TOKEN_READ | win32security.TOKEN_ADJUST_PRIVILEGES,
        )
        win32security.AdjustTokenPrivileges(token, False, [(privilege, win32security.SE_PRIVILEGE_ENABLED)])
        win32api.CloseHandle(token)

        kernel32 = windll.kernel32
        ntdll = windll.ntdll

        # Import firmware variable APIs
        try:
            self._get_system_firmware_table = kernel32.GetSystemFirmwareTable
            self._get_system_firmware_table.restype = c_int
            self._get_system_firmware_table.argtypes = [c_int, c_int, c_void_p, c_int]

            self._nt_query_system_information = ntdll.NtQuerySystemInformation

            # NTSTATUS WINAPI NtQuerySystemInformation(
            #     _In_      SYSTEM_INFORMATION_CLASS SystemInformationClass,
            #     _Inout_   PVOID                    SystemInformation,
            #     _In_      ULONG                    SystemInformationLength,
            #     _Out_opt_ PULONG                   ReturnLength
            # );
            self._nt_query_system_information.restype = c_ulong
            self._nt_query_system_information.argtypes = [
                c_int,
                c_void_p,
                c_ulong,
                POINTER(c_ulong),
            ]

        except AttributeError:
            logging.error("GetSystemFirmwareTable function doesn't seem to exist")

    def get_acpi_table(self, table_id: bytes) -> tuple:
        """Retrieves an ACPI table from the system firmware.

        This function uses the `GetSystemFirmwareTable` Windows API to retrieve an ACPI table
        identified by the provided `table_id`. The function handles cases where the table size
        exceeds the initial buffer length by dynamically resizing the buffer.

        Args:
            table_id (bytes): A 4-byte identifier for the ACPI table in little-endian format.

        Returns:
            tuple: A tuple containing:
                - int: Error code (0 for success, or a non-zero error code on failure).
                - bytes or None: The retrieved ACPI table as a byte array, or None if an error occurred.
                - str or None: An error message or additional information, or None if no error occurred.

        Notes:
            - The function logs detailed information and errors using the `logging` module.
            - If the `_get_system_firmware_table` attribute is not set, the function returns an error code of -20.
            - If the table retrieval fails, the function logs the error and returns the corresponding Windows
              error code.
        """
        err = 0  # Success
        table_type = struct.unpack(">i", b"ACPI")[0]  # Big endian
        table_id_as_int = struct.unpack("<i", table_id)[0]  # TableId is little endian or native
        table_length = 1000
        table = create_string_buffer(table_length)
        if self._get_system_firmware_table is not None:  # mock
            kernel32 = windll.kernel32
            logging.info(
                f"Calling GetSystemFirmwareTable( fw_table_provider=0x{table_type:x},"
                f" fw_table_id=0x{table_id_as_int:X} )"
            )
            length = self._get_system_firmware_table(table_type, table_id_as_int, table, table_length)  # mock
            if length > table_length:
                logging.info(f"Table length is: 0x{length:x}")
                table = create_string_buffer(length)
                length2 = self._get_system_firmware_table(table_type, table_id_as_int, table, length)

                if length2 != length:
                    err = kernel32.GetLastError()
                    logging.error(f"GetSystemFirmwareTable failed (GetLastError = 0x{err:x})")
                    logging.error(WinError())
                    return err, None, WinError(err)
            elif length != 0:
                return err, table[:length], None
            err = kernel32.GetLastError()
            logging.error(f"GetSystemFirmwareTable failed (GetLastError = 0x{err:x})")
            logging.error(WinError())
            return err, None, "Length = 0"
        return -20, None, "GetSystemFirmwareTable is None"

    def get_fbpt(self) -> tuple[int, ctypes.c_char_p | None]:
        """Retrieves the Firmware Boot Performance Table (FBPT) using the NtQuerySystemInformation API.

        Returns:
            tuple: A tuple containing:
                - status (int): The status code of the operation. A value of 0 indicates success.
                - param1 (ctypes.c_char_p or None): A buffer containing the FBPT data if the operation
                  is successful, or None if an error occurs.
        """
        param0 = c_int(198)  # 198 is SystemFirmwareBootPerformanceInformation
        param1 = c_void_p(0)
        param2 = c_ulong(0)
        param3c = c_ulong(0)
        param3 = pointer(param3c)

        # First call the function with NULL SystemInformation and 0 SystemInformationLength
        # This way we'll get the size of FBPT in ReturnLength
        status = self._nt_query_system_information(param0, param1, param2, param3)

        # 0xc0000004 is STATUS_INFO_LENGTH_MISMATCH
        if status != 0xC0000004 or param3c == 0:
            return 1, None

        param1 = create_string_buffer(param3c.value)
        param2 = param3c
        status = self._nt_query_system_information(param0, param1, param2, param3)

        if status != 0:
            return 1, None

        return status, param1


# Helper function for parsing FBPT contents
def fbpt_parsing_factory(fbpt_contents_file: BinaryIO, fbpt_records_list: list) -> int:
    """Parses Firmware Boot Performance Table (FBPT) records from a binary file and appends them to a list.

    Args:
        fbpt_contents_file (BinaryIO): A binary file object containing the FBPT data.
        fbpt_records_list (list): A list to store the parsed FBPT records.

    Returns:
        int: 0 upon successful parsing.

    Raises:
        ValueError: If an unknown record type is encountered.

    Notes:
        - The function assumes that the binary file contains complete records and does not stop in the middle
          of a record header.
        - If an unknown record type is encountered, a critical message is logged and the record is skipped.
    """
    # We need to read first record's header first (4 bytes), then using the length of this record, read the rest
    # of the record
    fbpt_contents_string: bytes = fbpt_contents_file.read(FbptRecordHeader.size)

    # If the size of returned string for the header is less than the size of the header that we
    # requested, it means we've reached EOF
    # The check below is more strict, it assumes the file stops after a record and not in the middle of a header
    while fbpt_contents_string != b"":
        fbpt_record_header: FbptRecordHeader = FbptRecordHeader(fbpt_contents_string)

        # If unknown record type print it and stop
        if fbpt_record_header.performance_record_type not in KNOWN_FBPT_RECORD_TYPES:
            logging.critical(f"Unknown record type 0x{fbpt_record_header.performance_record_type:04x}")
            fbpt_contents_file.read(fbpt_record_header.record_length - 4)  # subtracting 4, that's the header size

        # Using the record type from the record header we will fill out a struct with the info from the record
        # and will print it
        # FIRMWARE_BASIC_BOOT_PERFORMANCE_DATA_EVENT_TYPE
        # GUID_EVENT_TYPE
        # DYNAMIC_STRING_EVENT_TYPE
        # DUAL_GUID_STRING_EVENT_TYPE
        # GUID_QWORD_EVENT_TYPE
        # GUID_QWORD_STRING_EVENT_TYPE
        if fbpt_record_header.performance_record_type == FIRMWARE_BASIC_BOOT_PERFORMANCE_DATA_EVENT_TYPE:
            fw_basic_boot_performance_data_record_string: bytes = fbpt_contents_file.read(
                FwBasicBootPerformanceDataRecord.size
            )
            fw_basic_boot_performance_data_record: FwBasicBootPerformanceDataRecord = FwBasicBootPerformanceDataRecord(
                fbpt_record_header, fw_basic_boot_performance_data_record_string
            )
            fbpt_records_list.append(fw_basic_boot_performance_data_record)
        elif fbpt_record_header.performance_record_type == GUID_EVENT_TYPE:
            guid_event_record_contents_string: bytes = fbpt_contents_file.read(GuidEventRecord.size)
            guid_event_record: GuidEventRecord = GuidEventRecord(fbpt_record_header, guid_event_record_contents_string)
            fbpt_records_list.append(guid_event_record)
        elif (
            fbpt_record_header.performance_record_type == DYNAMIC_STRING_EVENT_TYPE
            or fbpt_record_header.performance_record_type == FPDT_DYNAMIC_STRING_EVENT_TYPE
        ):
            dynamic_string_event_record_contents_string: bytes = fbpt_contents_file.read(DynamicStringEventRecord.size)
            dynamic_string_string_size: int = (
                fbpt_record_header.record_length - FbptRecordHeader.size - DynamicStringEventRecord.size
            )
            dynamic_string_string_byte_array: bytes = fbpt_contents_file.read(dynamic_string_string_size)
            dynamic_string_event_record: DynamicStringEventRecord = DynamicStringEventRecord(
                fbpt_record_header,
                dynamic_string_event_record_contents_string,
                dynamic_string_string_byte_array,
                dynamic_string_string_size,
            )
            fbpt_records_list.append(dynamic_string_event_record)
        elif (
            fbpt_record_header.performance_record_type == DUAL_GUID_STRING_EVENT_TYPE
            or fbpt_record_header.performance_record_type == FPDT_DUAL_GUID_STRING_EVENT_TYPE
        ):
            dual_guid_string_event_record_contents_string: bytes = fbpt_contents_file.read(
                DualGuidStringEventRecord.size
            )
            dual_guid_string_string_size: int = (
                fbpt_record_header.record_length - FbptRecordHeader.size - DualGuidStringEventRecord.size
            )
            dual_guid_string_string_byte_array: bytes = fbpt_contents_file.read(dual_guid_string_string_size)
            dual_guid_string_event_record: DualGuidStringEventRecord = DualGuidStringEventRecord(
                fbpt_record_header,
                dual_guid_string_event_record_contents_string,
                dual_guid_string_string_byte_array,
                dual_guid_string_string_size,
            )
            fbpt_records_list.append(dual_guid_string_event_record)
        elif (
            fbpt_record_header.performance_record_type == GUID_QWORD_EVENT_TYPE
            or fbpt_record_header.performance_record_type == FPDT_GUID_QWORD_EVENT_TYPE
        ):
            guid_qword_event_record_contents_string: bytes = fbpt_contents_file.read(GuidQwordEventRecord.size)
            guid_qword_event_record: GuidQwordEventRecord = GuidQwordEventRecord(
                fbpt_record_header, guid_qword_event_record_contents_string
            )
            fbpt_records_list.append(guid_qword_event_record)
        elif (
            fbpt_record_header.performance_record_type == GUID_QWORD_STRING_EVENT_TYPE
            or fbpt_record_header.performance_record_type == FPDT_GUID_QWORD_STRING_EVENT_TYPE
        ):
            guid_qword_string_event_record_contents_string: bytes = fbpt_contents_file.read(
                GuidQwordStringEventRecord.size
            )
            guid_qword_string_string_size: int = (
                fbpt_record_header.record_length - FbptRecordHeader.size - GuidQwordStringEventRecord.size
            )
            guid_qword_string_byte_array: bytes = fbpt_contents_file.read(guid_qword_string_string_size)
            guid_qword_string_event_record: GuidQwordStringEventRecord = GuidQwordStringEventRecord(
                fbpt_record_header,
                guid_qword_string_event_record_contents_string,
                guid_qword_string_byte_array,
                guid_qword_string_string_size,
            )
            fbpt_records_list.append(guid_qword_string_event_record)

        # Read next record's header
        fbpt_contents_string = fbpt_contents_file.read(FbptRecordHeader.size)

    return 0


def get_uefi_version() -> str:
    """Retrieves the UEFI version from the system's BIOS information.

    This function uses the Windows Management Instrumentation (WMI) interface
    to query the system's BIOS and extract the SMBIOS BIOS version.

    Returns:
        str: The UEFI version as a string if successfully retrieved,
             otherwise returns "Unknown".

    Logs:
        Logs an error message if the UEFI version cannot be retrieved.
    """
    import wmi

    try:
        c = wmi.WMI()
        bios_info = c.Win32_BIOS()[0]
        return bios_info.SMBIOSBIOSVersion
    except Exception as e:
        logging.error(f"Failed to retrieve UEFI version: {e}")
        return "Unknown"


def get_model() -> str:
    """Retrieves the model name of the computer system using WMI (Windows Management Instrumentation).

    Returns:
        str: The model name of the computer system. If an error occurs during retrieval,
        "Unknown" is returned and the error is logged.
    """
    import wmi

    try:
        c = wmi.WMI()
        computer_system = c.Win32_ComputerSystem()[0]
        return computer_system.Model
    except Exception as e:
        logging.error(f"Failed to retrieve model: {e}")
        return "Unknown"


class ParserApp:
    """The main execution environment to parse FPDT."""

    def __init__(self) -> None:
        """Initializes the record parser."""
        parser = argparse.ArgumentParser(description="FPDT Parser Tool")
        parser.add_argument(
            "-t",
            "--output_text",
            dest="output_text_file",
            help="Name of the output text file which will contain the FPDT info",
            default=None,
        )
        parser.add_argument(
            "-x",
            "--output_xml",
            dest="output_xml_file",
            help="Name of the output XML file which will contain the FPDT info",
            default=None,
        )
        parser.add_argument(
            "-b",
            "--input_bin",
            dest="input_fbpt_bin",
            help="Name of the input binary file which contains the FBPT",
            default=None,
        )
        self.options = parser.parse_args()
        self.set_up_logging()
        self.text_log = self.handle_output_file()
        self.handle_input_file()
        self.uefi_version, self.model = self.get_uefi_version_model()
        self.fbpt_tree = None  # Initialize FBPT container element

        self.write_text_header()
        self.xml_tree = self.write_xml_header()

    def set_up_logging(self) -> None:
        """Sets up logging during parsing."""
        logger = logging.getLogger("")
        logger.setLevel(logging.INFO)
        formatter = logging.Formatter("%(levelname)s - %(message)s")
        console = logging.StreamHandler()
        console.setLevel(logging.CRITICAL)
        console.setFormatter(formatter)
        logger.addHandler(console)

    def handle_output_file(self) -> TextIOWrapper:
        """Parses and validates the output file arguments."""
        if self.options.output_xml_file:
            if len(self.options.output_xml_file) < 2:
                logging.critical("The output XML file parameter is invalid")
                raise ValueError("Output XML file name must be at least 2 characters long")

        if self.options.output_text_file:
            if len(self.options.output_text_file) < 2:
                logging.critical("The output text file parameter is invalid")
                raise ValueError("Output text file name must be at least 2 characters long")
            else:
                text_log = open(self.options.output_text_file, "w")
                return text_log

    def handle_input_file(self) -> None:
        """Parses and validates the input file argument."""
        if self.options.input_fbpt_bin:
            if len(self.options.input_fbpt_bin) < 2:
                logging.critical("The input binary file parameter is invalid")
                raise ValueError("Input file name must be at least 2 characters long")
            if not os.path.isfile(self.options.input_fbpt_bin):
                logging.critical("The input binary file is not found")
                raise ValueError("Invalid input file path")

    def get_uefi_version_model(self) -> (str, str):
        """Gets the uefi version and model from the file name."""
        if self.options.input_fbpt_bin is None:
            uefi_version = get_uefi_version()
            model = get_model()
        else:
            p = re.compile(r"FBPT_([\w ]*)_([\d\.]*)\.bin")
            m = p.match(os.path.split(self.options.input_fbpt_bin)[1])
            if m is not None:
                uefi_version = m.group(1)
                model = m.group(2)
            else:
                logging.critical("The binary file name doesn't contain model name and UEFI version")
                logging.critical("Tool expects binary name in format FBPT_<ModelName>_<UefiVer>.bin")
                logging.critical("Continuing with N/A for model name and UEFI version")
                uefi_version = "N/A"
                model = "N/A"
        return (uefi_version, model)

    def write_text_header(self) -> None:
        """Writes the header to the text file."""
        if self.options.output_text_file:
            self.text_log.write(
                f"  Platform Information\n------------------------------------------------------------------\n"
                f"UEFI Version : {self.uefi_version}\n  Model        : {self.model}\n"
            )

    def write_xml_header(self) -> ET.Element:
        """Writes the header to the XML file."""
        if self.options.output_xml_file:
            xml_tree = ET.Element("FpdtParserData")
            xml_repr = ET.Element("UEFIVersion")
            xml_repr.set("Value", self.uefi_version)
            xml_tree.append(xml_repr)

            xml_repr = ET.Element("Model")
            xml_repr.set("Value", self.model)
            xml_tree.append(xml_repr)

            now = datetime.datetime.now()
            date_collected = f"{now.month}/{now.day}/{now.year}"
            xml_repr = ET.Element("DateCollected")
            xml_repr.set("Value", date_collected)
            xml_tree.append(xml_repr)

            xml_repr = ET.Element("FpdtParserVersion")
            xml_repr.set("Value", FPDT_PARSER_VER)
            xml_tree.append(xml_repr)
            return xml_tree

    def write_fpdt_header(self, table: SystemFirmwareTable) -> None:
        """Writes the general FPDT header to the output file."""
        if self.options.input_fbpt_bin is None:
            (error_code, data, error_string) = table.get_acpi_table(b"FPDT")
            fpdt_header = AcpiTableHeader(data)

            # Store FPDT header in text and/or XML tree
            if self.options.output_text_file:
                self.text_log.write(str(fpdt_header))
            if self.options.output_xml_file:
                self.xml_tree.append(fpdt_header.to_xml())

            # This assumes we only have one perf record - Firmware Basic Boot Performance Record
            if (fpdt_header.length - AcpiTableHeader.size) > FwBasicBootPerformanceRecord.size:
                logging.critical("Extra records are present in FPDT but will be ignored")

            # Parse the basic boot perf record
            fbbpr = FwBasicBootPerformanceRecord(data[AcpiTableHeader.size :])

            # Store the basic boot perf record in text and/or XML tree
            if self.options.output_text_file:
                self.text_log.write(str(fbbpr))
            if self.options.output_xml_file:
                self.xml_tree.append(fbbpr.to_xml())

    def find_fbpt_file(self, table: SystemFirmwareTable) -> BinaryIO:
        """Looks for the FBPT file in a given path or a known system location."""
        if self.options.input_fbpt_bin is None:
            (return_code, fbpt_buffer) = table.get_fbpt()

            if return_code != 0:
                logging.critical(r"This version of Windows doesn't support access to FBPT - aborting")
                raise EnvironmentError("Unsupported platform: cannot access FBPT")
            else:
                # get_fbpt returned expected return_code, so let's use the buffer it returned
                fbpt_file_w = open("FBPT.BIN", "wb")
                fbpt_file_w.write(fbpt_buffer)
                fbpt_file_w.close()
                fbpt_file = open("FBPT.BIN", "rb")
        else:
            fbpt_file = open(self.options.input_fbpt_bin, "rb")
        return fbpt_file

    def write_fbpt(self, fbpt_file: BinaryIO) -> None:
        """Writes the header into the FBPT."""
        fbpt_header = FwBasicBootPerformanceTableHeader(fbpt_file.read(FwBasicBootPerformanceTableHeader.size))
        # Store header into text log and/or XML tree
        if self.options.output_text_file:
            self.text_log.write(str(fbpt_header))
        if self.options.output_xml_file:
            # Store FBPT header as a container element that will hold all records
            self.fbpt_tree = fbpt_header.to_xml()
            # Don't append to xml_tree yet - we'll do that after adding all records

    def gather_fbpt_records(self, fbpt_file: BinaryIO) -> list:
        """Collects FBPT records from an input file."""
        fbpt_records_list = list()

        # This helper function parses through the FBPT records and populates the list with records
        fbpt_parse_result = fbpt_parsing_factory(fbpt_file, fbpt_records_list)

        fbpt_file.close()
        if self.options.input_fbpt_bin is None:
            os.remove("FBPT.BIN")

        if fbpt_parse_result == 1:
            if self.options.output_text_file:
                self.text_log.close()
            logging.shutdown()
            raise ValueError("Failed to parse FBPT: binary data is malformed or unsupported")

        return fbpt_records_list

    def write_records(self, fbpt_records_list: list) -> int:
        """Writes FBPT records to an output file."""
        if self.options.output_xml_file:
            # Add all records to the FBPT container element
            for record in fbpt_records_list:
                self.fbpt_tree.append(record.to_xml())

            # Now append the complete FBPT container to the main XML tree
            self.xml_tree.append(self.fbpt_tree)

            # Format XML properly with indentation
            rough_string = ET.tostring(self.xml_tree, encoding='unicode')
            reparsed = minidom.parseString(rough_string)
            formatted_xml = reparsed.toprettyxml(indent="    ")

            with open(self.options.output_xml_file, "w", encoding='utf-8') as xml_file:
                xml_file.write(formatted_xml)

        if self.options.output_text_file:
            for record in fbpt_records_list:
                self.text_log.write(str(record))
            self.text_log.write(f"\nFBPT Record count: {len(fbpt_records_list)}\n")
            self.text_log.close()

        return len(fbpt_records_list)


def main() -> None:
    """Main function to execute the script."""
    parser_app = ParserApp()
    table = SystemFirmwareTable()
    parser_app.write_fpdt_header(table)
    fbpt_file = parser_app.find_fbpt_file(table)
    parser_app.write_fbpt(fbpt_file)
    fbpt_parse_result = parser_app.gather_fbpt_records(fbpt_file)
    records_parsed = parser_app.write_records(fbpt_parse_result)

    logging.critical(f"SUCCESS, {records_parsed} record(s) parsed")
    logging.shutdown()
    sys.exit(0)


if __name__ == "__main__":
    main()
