"""perf_report_generator.py.

Copyright (c) Microsoft Corporation
SPDX-License-Identifier: BSD-2-Clause-Patent

This module provides tools for parsing Firmware Performance Data Table (FPDT) XML data
and generating performance reports in text and HTML formats. It includes functionality
to extract GUIDs from UEFI source files, process FPDT records, and produce detailed
timing information for firmware boot processes.

Functions:
    add_guid(guid: str, name: str, guid_dict: dict) -> None:
        Add a GUID and its associated name to the GUID dictionary.
    parse_guids_in_directory(input_path: str, guid_dict: dict) -> None:
        Parse GUIDs within the specified directory and add them to the GUID dictionary.
    main() -> None:
        Main function to parse command-line arguments and generate performance reports.

Constants:
    REPORT_GENERATOR_VER: str
        Version of the report generator.
    EVENT_PROGRESS_ID: str
        Progress ID for event records.
    DYNAMIC_STRING_PROGRESS_IDS: list[str]
        List of progress IDs for dynamic string events.
    GUID_QWORD_PROGRESS_IDS: list[str]
        List of progress IDs for GUID QWORD events.
    GUID_PROGRESS_ID: str
        Progress ID for GUID events.
    DUAL_GUID_STRING_PROGRESS_IDS: list[str]
        List of progress IDs for dual GUID string events.
    PROGRESS_ID_LABEL_DICT: dict
        Dictionary mapping progress IDs to their labels.
    DEC_REGEX: str
        Regular expression for extracting GUIDs from DEC files.
    INF_FILE_REGEX: str
        Regular expression for extracting base names from INF files.
    INF_GUID_REGEX: str
        Regular expression for extracting GUIDs from INF files.
    FDF_GUID_REGEX: str
        Regular expression for extracting GUIDs from FDF files.
    FDF_FILE_REGEX: str
        Regular expression for extracting file names from FDF files.
"""

import argparse
import datetime
import hashlib
import logging
import os
import re
import sys
import xml.etree.ElementTree as ET
from operator import itemgetter
from typing import TextIO

REPORT_GENERATOR_VER = "2.00"

messages = []

# Code using these data structures assumes that progress IDs are hex numbers of 0xXXXX format:
# "0x" in front, then 4 characters, numbers and UPPERCASE characters

EVENT_PROGRESS_ID = "0x0000"

DYNAMIC_STRING_PROGRESS_IDS = ["0x0030", "0x0040", "0x0050"]

GUID_QWORD_PROGRESS_IDS = ["0x0003", "0x0005", "0x0007", "0x0009", "0x000A"]

GUID_PROGRESS_ID = "0x0001"

DUAL_GUID_STRING_PROGRESS_IDS = ["0x0010", "0x0020"]

# dict of all progress ID codes -> their labels
PROGRESS_ID_LABEL_DICT = {
    "0x0001": "Entrypoint",
    "0x0003": "LoadImage",
    "0x0005": "BindingStart",
    "0x0007": "BindingSupport",
    "0x0009": "BindingStop",
    "0x0010": "EventSignal",
    "0x0020": "Callback",
    "0x0030": "Function",
    "0x0040": "Inmodule",
    "0x0050": "Crossmodule",
}

##
# Regular Expressions for extracting Guids from UEFI file types
##

# DEC files
DEC_REGEX = (
    r"\s*([a-zA-Z]\w*)\s*\=\s*"
    + r"\{\s*0x([0-9a-fA-F]{1,8})\s*,\s*"
    + r"0x([0-9a-fA-F]{1,4})\s*,\s*"
    + r"0x([0-9a-fA-F]{1,4})\s*,\s*"
    + r"\s*\{\s*0x([0-9a-fA-F]{1,2})\s*,\s*"
    + r"0x([0-9a-fA-F]{1,2})\s*,\s*"
    + r"0x([0-9a-fA-F]{1,2})\s*,\s*"
    + r"0x([0-9a-fA-F]{1,2})\s*,\s*"
    + r"0x([0-9a-fA-F]{1,2})\s*,\s*"
    + r"0x([0-9a-fA-F]{1,2})\s*,\s*"
    + r"0x([0-9a-fA-F]{1,2})\s*,\s*"
    + r"0x([0-9a-fA-F]{1,2})\s*\}\s*\}"
)

# INF files
INF_FILE_REGEX = r"\s*BASE_NAME\s*\=\s*([a-zA-Z]\w*)\s*"
INF_GUID_REGEX = (
    r"\s*FILE_GUID\s*\=\s*([0-9a-fA-F]{8,8}-[0-9a-fA-F]{4,4}-[0-9a-fA-F]{4,4}-[0-9a-fA-F]{4,4}-[0-9a-fA-F]{12,12})\s*"
)

# FDF files
FDF_GUID_REGEX = (
    r"\s*FILE\s*DRIVER\s*\=\s*([0-9a-fA-F]{8,8}-[0-9a-fA-F]{4,4}-[0-9a-fA-F]{4,4}-[0-9a-fA-F]{4,4}-"
    r"[0-9a-fA-F]{12,12})\s*\{+\s*"
)
FDF_FILE_REGEX = r"\s*SECTION\s*UI\s*\=\s*\"([\w\s]+)\"\s*"


def add_guid(guid: str, name: str, guid_dict: dict) -> None:
    """Add a GUID and its associated name to the guid_dict.

    Args:
        guid (str): The GUID to add.
        name (str): The name associated with the GUID.
        guid_dict (dict): The dictionary to store the GUID and name.
    """
    guid_upper = guid.upper()
    if guid_upper in guid_dict:
        logging.warning(f"Duplicate GUID found: {guid}")
    else:
        guid_dict[guid_upper] = name
        logging.debug(f"Added GUID: '{name}' : '{guid}'")


def parse_guids_in_directory(input_path: str, guid_dict: dict) -> None:
    """Parse GUIDs within the specified directory and add them to the GUID dictionary.

    Args:
        input_path (str): The path to the directory to parse.
        guid_dict (dict): The dictionary to store parsed GUIDs.
    """
    logging.debug(f"Parsing path {input_path}:")
    for root, _, files in os.walk(input_path):
        for name in files:
            file_path = os.path.join(root, name)
            if name.lower().endswith(".dec"):
                _parse_file(file_path, (DEC_REGEX,), guid_dict, is_dec=True)
            elif name.lower().endswith(".inf"):
                _parse_file(file_path, (INF_FILE_REGEX, INF_GUID_REGEX), guid_dict, is_inf=True)
            elif name.lower().endswith(".fdf"):
                _parse_file(file_path, (FDF_FILE_REGEX, FDF_GUID_REGEX), guid_dict, is_fdf=True)


def _parse_file(
    file_path: str,
    regexes: tuple[str],
    guid_dict: dict[str, str],
    is_dec: bool = False,
    is_inf: bool = False,
    is_fdf: bool = False,
) -> None:
    """Helper function to parse a file for GUIDs based on its type.

    Args:
        file_path (str): Path to the file to parse.
        regexes (tuple[str]): Regex pattern(s) to use for parsing.
        guid_dict (dict[str, str]): Dictionary to store parsed GUIDs.
        is_dec (bool): Whether the file is a DEC file.
        is_inf (bool): Whether the file is an INF file.
        is_fdf (bool): Whether the file is an FDF file.
    """
    logging.debug(f"Parsing file {file_path}:")
    with open(file_path, "r") as file:
        for regex in regexes:
            if is_dec:
                pattern = re.compile(regex)
                for line in file:
                    match = pattern.match(line)
                    if match:
                        guid_key = _format_guid(match.groups())
                        add_guid(guid_key, match.group(1), guid_dict)
            elif is_inf or is_fdf:
                file_pattern = re.compile(INF_FILE_REGEX if is_inf else FDF_FILE_REGEX)
                guid_pattern = re.compile(INF_GUID_REGEX if is_inf else FDF_GUID_REGEX)
                guid_value: str | None = None
                guid_key: str | None = None
                for line in file:
                    if file_match := file_pattern.match(line):
                        guid_value = file_match.group(1)
                    elif guid_match := guid_pattern.match(line):
                        guid_key = guid_match.group(1).upper()
                    if guid_value and guid_key:
                        add_guid(guid_key, guid_value, guid_dict)
                        guid_value, guid_key = None, None


def _format_guid(groups: tuple) -> str:
    """Format GUID components into a standard GUID string.

    Args:
        groups (tuple): Regex match groups containing GUID components.

    Returns:
        str: Formatted GUID string.
    """
    return (
        f"{groups[1].upper().zfill(8)}-{groups[2].upper().zfill(4)}-{groups[3].upper().zfill(4)}-"
        f"{groups[4].upper().zfill(2)}{groups[5].upper().zfill(2)}-"
        f"{''.join(groups[6:]).upper().zfill(12)}"
    )


def main() -> int:
    """Main function to parse command-line arguments and generate performance reports."""
    guids = {}
    options = parse_arguments()

    html_report = None
    if options.output_html_file:
        if len(options.output_html_file) < 2:
            logging.critical("The output HTML file parameter is invalid")
            return -1
        else:
            html_report = open(options.output_html_file, "w")

    if options.output_debug_log:
        if len(options.output_debug_log) < 2:
            logging.critical("The output debug log file parameter is invalid")
            return -2
        else:
            # Setup file-based logging
            file_logger = logging.FileHandler(filename=options.output_debug_log, mode="w")
            if options.debug:
                file_logger.setLevel(logging.DEBUG)
            else:
                file_logger.setLevel(logging.INFO)

            file_logger.setFormatter(formatter)
            logging.getLogger("").addHandler(file_logger)

    logging.info(f"Log Started: {datetime.datetime.strftime(datetime.datetime.now(), '%A, %B %d, %Y %I:%M%p')}")

    text_log = None
    if options.output_text_file:
        if len(options.output_text_file) < 2:
            logging.critical("The output text file parameter is invalid")
            return -3
        else:
            # Create a new text log file
            text_log = open(options.output_text_file, "w")

    if not options.input_xml_file or not os.path.exists(options.input_xml_file):
        logging.critical("No Input XML File")
        return -4

    if options.src_tree_root:
        parse_source_tree(options.src_tree_root, guids)

        #
        # Print out the GUID list if debug is on
        #
        if options.debug:
            for k, v in guids.items():
                logging.debug(f"{k} = {v}")

    timing_list, messages, unrecognized_records = parse_fpdt_records(options.input_xml_file, text_log, guids)

    if html_report:
        write_html_report(options.input_xml_file, timing_list, messages, html_report)

    return unrecognized_records


def parse_arguments() -> argparse.Namespace:
    """Parse command-line arguments.

    Returns:
        argparse.Namespace: Parsed command-line arguments.

    Command-line arguments:
        -t, --output_text: Name of the output text file (default: None).
        -r, --output_html: Name of the output HTML file (default: None).
        -i, --input_xml_file: Path to the input XML file with raw FPDT data (default: None).
        -s, --src_tree_root: Root of UEFI Code tree to parse for GUIDs (default: None, accepts multiple values).
        -d, --debug: Enable debug output (default: False).
        -l, --output_debug_log: Log all debug and error output to a file (default: None).
    """
    parser = argparse.ArgumentParser(description="FPDT XML Parser Tool")
    parser.add_argument(
        "-t", "--output_text", dest="output_text_file", help="Name of the output text file", default=None
    )
    parser.add_argument(
        "-r", "--output_html", dest="output_html_file", help="Name of the output HTML file", default=None
    )
    parser.add_argument("-i", "--input_xml_file", help="Path to the input XML file with raw FPDT data", default=None)
    parser.add_argument(
        "-s", "--src_tree_root", help="Root of UEFI Code tree to parse for GUIDs", nargs="*", default=None
    )
    parser.add_argument("-d", "--debug", help="Enable debug output", action="store_true")
    parser.add_argument(
        "-l", "--output_debug_log", dest="output_debug_log", help="Log all debug and error output to file", default=None
    )
    return parser.parse_args()


def parse_source_tree(src_tree_root: list[str], guids: dict[str, str]) -> None:
    """Parse the source tree for GUIDs.

    Args:
        src_tree_root (list[str]): List of source tree root paths to parse.
        guids (dict[str, str]): Dictionary to store parsed GUIDs.
    """
    for src_tree in src_tree_root:
        logging.critical(f"Parsing Code Tree for GUIDs: {src_tree}")
        parse_guids_in_directory(src_tree, guids)


def parse_fpdt_records(input_xml_file: str, text_log: str, guids: dict) -> tuple:
    """Parses Firmware Performance Data Table (FPDT) records from an input XML file and generates a timing list.

    This function processes various types of performance records, including basic boot events, dynamic string events,
    GUID-based events, and others. It extracts relevant timing information, organizes it into a list of tuples,
    and optionally writes the output to a text log file.

    Args:
        input_xml_file (str): Path to the input XML file containing performance records.
        text_log (str): Path to the output text log file. If None, no text log is generated.
        guids (dict): A dictionary mapping GUIDs to their corresponding string representations.

    Returns:
        tuple: A tuple containing:
            - timing_list (list): A sorted list of tuples, where each tuple contains:
                (<ID#>, <Type>, <GUID>, <GuidValue>, <String>, <StartTime>, <Length>).
            - messages (list): A list of messages indicating errors or warnings encountered during parsing.
            - unrecognized_records (int): The count of unrecognized records found in the input XML file.

    Notes:
        - The function logs critical errors if no FBPT records are found or if unrecognized record types are
          encountered.
        - The timing list is sorted by start times before being returned.
        - Unmatched start records are checked and logged as warnings.
    """
    logging.critical("Parsing FPDT XML records")

    # List of tuples, where each tuple is (<ID#>, <Type>, <GUID>, <GuidValue>, <String>, <StartTime>, <Length>)
    # ID is a counter that starts at 1
    timing_list = []
    id_counter = 1

    # Dictionary label:start_time
    start_records_dict = {}

    # Dictionary for cross-module start GUIDs and guid_strings
    # label : (guid, guid_string)
    cross_module_start_guid_dict = {}
    # Loop through records and find all binding_start_end records which contain the string,
    # we'll create a dict of qword->string mappings
    # Dictionary qword:DevicePath
    controller_handle_dict = {}

    # Keep a count of unrecognized entries to use as a return code
    # 0 return means every record was successfully decoded
    unrecognized_records = 0

    messages = []

    fbpt = ET.parse(input_xml_file).find("Fbpt")

    if fbpt is None:
        logging.critical(f"Error! No FBPT records found in {input_xml_file}")
        messages.append(("Error", f"No FBPT records found in {input_xml_file}"))
        return [], messages, 1

    controller_handle_dict = _extract_controller_handles(fbpt)

    for record in fbpt:
        if record.tag == "FirmwareBasicBootPerformanceEvent":
            # Special case for basic record: create 3 events (ResetEnd, OSLoaderLoadImageStart,
            # OSLoaderStartImageStart), and one process (ExitBootServices)
            id_counter = _process_basic_boot_event(record, timing_list, id_counter)
        elif record.tag == "DynamicStringEvent":
            id_counter, unrecognized_records = _process_dynamic_string_event(
                record,
                guids,
                timing_list,
                start_records_dict,
                cross_module_start_guid_dict,
                messages,
                id_counter,
                unrecognized_records,
            )
        elif record.tag == "GuidQwordEvent":
            id_counter, unrecognized_records = _process_guid_qword_event(
                record,
                guids,
                timing_list,
                start_records_dict,
                controller_handle_dict,
                messages,
                id_counter,
                unrecognized_records,
            )
        elif record.tag == "GuidQwordStringEvent":
            id_counter, unrecognized_records = _process_guid_qword_string_event(
                record, guids, timing_list, start_records_dict, messages, id_counter, unrecognized_records
            )
        elif record.tag == "GuidEvent":
            id_counter, unrecognized_records = _process_guid_event(
                record, guids, timing_list, start_records_dict, messages, id_counter, unrecognized_records
            )
        elif record.tag == "DualGuidStringEvent":
            id_counter, unrecognized_records = _process_dual_guid_string_event(
                record, guids, timing_list, start_records_dict, messages, id_counter, unrecognized_records
            )
        else:
            logging.critical(f"Error! Unrecognized record found with tag {record.tag}")
            messages.append(("Error", f"Unrecognized record found with tag {record.tag}"))
            unrecognized_records += 1

    _check_unmatched_start_records(start_records_dict, messages)

    # sort timing_list by start times, i.e. 1th element produce requested output
    timing_list.sort(key=itemgetter(5))

    if text_log is not None:
        _write_text_output(timing_list, text_log)

    return timing_list, messages, unrecognized_records


def _extract_controller_handles(fbpt: ET.Element) -> dict[str, str]:
    """Extract controller handles from the FPDT records.

    Args:
        fbpt (ET.Element): The XML element containing FPDT records.

    Returns:
        dict[str, str]: A dictionary mapping Qword values to string representations.
    """
    controller_handle_dict: dict[str, str] = {}
    for record in fbpt:
        if record.tag == "GuidQwordStringEvent":
            # The type should be BindingStart
            qword = record.find("Qword").attrib["Value"]
            string_value = record.find("String").attrib["Value"]
            controller_handle_dict[qword] = string_value
    return controller_handle_dict


def _process_basic_boot_event(
    record: ET.Element, timing_list: list[tuple[int, str, str, str, str, float, float]], id_counter: int
) -> int:
    """Process a FirmwareBasicBootPerformanceEvent record and append timing data to the timing list.

    This function extracts specific performance event timings from the provided XML record
    and appends them to the timing_list in a structured format. It processes events such as
    ResetEnd, OSLoaderLoadImageStart, OSLoaderStartImageStart, and ExitBootServices.

    Args:
        record (ET.Element): An XML element containing performance event data.
        timing_list (list[tuple[int, str, str, str, str, float, float]]): A list to store timing data.
            Each entry in the list is a tuple containing:
            - An integer ID.
            - A string representing the type of event or process.
            - Placeholder strings ("N/A").
            - The name of the event or process.
            - A float representing the start time in milliseconds.
            - A float representing the duration in milliseconds (0.000001 for events).
        id_counter (int): A counter to assign unique IDs to each timing entry.

    Returns:
        int: The updated id_counter after processing the events.
    """
    timing_list.append(
        (
            id_counter,
            "Event",
            "N/A",
            "N/A",
            "ResetEnd",
            float(record.find("ResetEnd").attrib["ValueInMilliseconds"]),
            0.000001,
        )
    )
    timing_list.append(
        (
            id_counter + 1,
            "Event",
            "N/A",
            "N/A",
            "OSLoaderLoadImageStart",
            float(record.find("OSLoaderLoadImageStart").attrib["ValueInMilliseconds"]),
            0.000001,
        )
    )
    timing_list.append(
        (
            id_counter + 2,
            "Event",
            "N/A",
            "N/A",
            "OSLoaderStartImageStart",
            float(record.find("OSLoaderStartImageStart").attrib["ValueInMilliseconds"]),
            0.000001,
        )
    )
    timing_list.append(
        (
            id_counter + 3,
            "Process",
            "N/A",
            "N/A",
            "ExitBootServices",
            float(record.find("ExitBootServicesEntry").attrib["ValueInMilliseconds"]),
            float(record.find("ExitBootServicesExit").attrib["ValueInMilliseconds"])
            - float(record.find("ExitBootServicesEntry").attrib["ValueInMilliseconds"]),
        )
    )
    return id_counter + 4


def _process_dynamic_string_event(
    record: ET.Element,
    guids: dict[str, str],
    timing_list: list[tuple[int, str, str, str, str, float, float]],
    start_records_dict: dict[str, float],
    cross_module_start_guid_dict: dict[str, tuple[str, str]],
    messages: list[tuple[str, str]],
    id_counter: int,
    unrecognized_records: int,
) -> tuple[int, int]:
    """Processes a DynamicStringEvent record and updates various data structures used for performance reporting.

    This function handles three types of events:
    - Event: Adds a timing entry for an event.
    - Function, Crossmodule, or Inmodule begin: Records the start time of an event.
    - Function, Crossmodule, or Inmodule end: Calculates the duration of an event and adds it to the timing list.

    Args:
        record (ET.Element): The XML element representing the event record.
        guids (dict[str, str]): A dictionary mapping GUIDs to their string representations.
        timing_list (list[tuple[int, str, str, str, str, float, float]]): A list to store timing information.
        start_records_dict (dict[str, float]): A dictionary to track start times of events by label.
        cross_module_start_guid_dict (dict[str, tuple[str, str]]): A dictionary to track GUIDs for cross-module events.
        messages (list[tuple[str, str]]): A list to store error or informational messages.
        id_counter (int): A counter for assigning unique IDs to events.
        unrecognized_records (int): A counter for tracking unrecognized records.

    Returns:
        tuple[int, int]: Updated values of `id_counter` and `unrecognized_records`.

    Raises:
        ValueError: If a negative time duration is calculated for an event.
    """
    progress_id_string = f"0x{int(record.find('ProgressID').attrib['Value'], 16):04X}"
    progress_id_string_minus_one = f"0x{int(record.find('ProgressID').attrib['Value'], 16) - 1:04X}"

    # Can be an Event:
    if progress_id_string == EVENT_PROGRESS_ID:
        guid = record.find("GUID").attrib["Value"]
        guid_string = (
            guids[guid] if (guid in guids) else f"UNKNOWN-{hashlib.sha256(guid.encode('utf-8')).hexdigest()[0:4]}"
        )
        string_value = record.find("String").attrib["Value"]
        start_time = float(record.find("Timestamp").attrib["ValueInMilliseconds"])
        length = 0.000001
        #                    (<ID#>, <Type>, <GUID>, <GuidValue>, <String>, <StartTime>, <Length>)
        timing_list.append(
            (
                id_counter,
                "Event",
                guid,
                guid_string,
                f"Event measurement from module {guid_string} with label {string_value}",
                start_time,
                length,
            )
        )
        id_counter += 1

    # Can be Function, Crossmodule, or Inmodule begin
    elif progress_id_string in DYNAMIC_STRING_PROGRESS_IDS:
        # Create an entry for a label:start_time dict, start_records_dict

        type = PROGRESS_ID_LABEL_DICT[progress_id_string]
        guid = record.find("GUID").attrib["Value"]
        guid_string = (
            guids[guid] if (guid in guids) else f"UNKNOWN-{hashlib.sha256(guid.encode('utf-8')).hexdigest()[0:4]}"
        )
        string_value = record.find("String").attrib["Value"]

        if type == "Crossmodule":
            # Label is <type>_<string>
            label = f"{type}_{string_value}"
            # Preserve the GUID and the guid_string of the start record
            cross_module_start_guid_dict[label] = (guid, guid_string)
        else:
            # Label is <type>_<guid_string>_<string>
            label = f"{type}_{guid_string}_{string_value}"

        start_time = float(record.find("Timestamp").attrib["ValueInMilliseconds"])

        # Place this into the starts dictionary, but check if one with the same label is already there
        if label in start_records_dict:
            logging.error(f"Error! Start record with label {label} already in dict!")
            messages.append(("Error", f"Start record with label {label} already in dict!"))
        else:
            start_records_dict[label] = start_time

    # Can be Function, Crossmodule, or Inmodule end
    elif progress_id_string_minus_one in DYNAMIC_STRING_PROGRESS_IDS:
        # Label is <type>_<guid_string>_<string>
        type = PROGRESS_ID_LABEL_DICT[progress_id_string_minus_one]
        guid = record.find("GUID").attrib["Value"]
        guid_string = (
            guids[guid] if (guid in guids) else f"UNKNOWN-{hashlib.sha256(guid.encode('utf-8')).hexdigest()[0:4]}"
        )
        string_value = record.find("String").attrib["Value"]

        if type == "Crossmodule":
            # Label is <type>_<string>
            label = f"{type}_{string_value}"
        else:
            # Label is <type>_<guid_string>_<string>
            label = f"{type}_{guid_string}_{string_value}"

        if label in start_records_dict:
            start_time = start_records_dict[label]
            del start_records_dict[label]
            length = float(record.find("Timestamp").attrib["ValueInMilliseconds"]) - start_time
            if length < 0:
                logging.error("Error! Cannot have negative time!")

            if type == "Crossmodule":
                #                 (<ID#>, <Type>, <GUID>, <GuidValue>, <String>, <StartTime>, <Length>)
                description_string = (
                    f"{type} measurement from {cross_module_start_guid_dict[label][1]} to {guid_string} "
                    f"with label {string_value}"
                )
                timing_list.append(
                    (
                        id_counter,
                        type,
                        f"{cross_module_start_guid_dict[label][0]}, {guid}",
                        f"{cross_module_start_guid_dict[label][1]}, {guid_string}",
                        description_string,
                        start_time,
                        length,
                    )
                )
            else:
                timing_list.append(
                    (
                        id_counter,
                        type,
                        guid,
                        guid_string,
                        f"{type} measurement from module {guid_string} with label {string_value}",
                        start_time,
                        length,
                    )
                )

            id_counter += 1
        else:
            logging.error(f"Error! Can't find a start event in the dict for label {label}!")
            messages.append(("Error", f"Can't find a start event in the dict for label {label}!"))
    else:
        logging.critical(f"Error! Unrecognized progress ID {progress_id_string}")
        messages.append(("Error", f"Unrecognized progress ID {progress_id_string}"))
        unrecognized_records += 1

    return id_counter, unrecognized_records


def _process_guid_qword_event(
    record: ET.Element,
    guids: dict[str, str],
    timing_list: list[tuple[int, str, str, str, str, float, float]],
    start_records_dict: dict[str, float],
    controller_handle_dict: dict[str, str],
    messages: list[tuple[str, str]],
    id_counter: int,
    unrecognized_records: int,
) -> tuple[int, int]:
    """Processes a GuidQwordEvent record and updates timing information, start records, and messages.

    This function handles both "start" and "end" events for various types of records, such as
    LoadImage and binding-related events. It calculates the duration of events, associates them
    with appropriate labels, and appends the results to the timing list.

    Args:
        record (ET.Element): The XML element representing the GuidQwordEvent record.
        guids (dict[str, str]): A dictionary mapping GUIDs to their string representations.
        timing_list (list[tuple[int, str, str, str, str, float, float]]): A list to store timing
            information for processed events. Each entry is a tuple containing:
            (<ID#>, <Type>, <GUID>, <GuidValue>, <String>, <StartTime>, <Length>).
        start_records_dict (dict[str, float]): A dictionary to track start times of events,
            keyed by their labels.
        controller_handle_dict (dict[str, str]): A dictionary mapping Qword values to device
            string representations.
        messages (list[tuple[str, str]]): A list to store error or warning messages. Each entry
            is a tuple containing (<MessageType>, <Message>).
        id_counter (int): A counter for assigning unique IDs to processed events.
        unrecognized_records (int): A counter for tracking the number of unrecognized records.

    Returns:
        tuple[int, int]: A tuple containing the updated `id_counter` and `unrecognized_records`.

    Notes:
        - The function distinguishes between "start" and "end" events based on the ProgressID
          value and its mapping in GUID_QWORD_PROGRESS_IDS.
        - For "start" events, the function adds the event's label and start time to
          `start_records_dict`.
        - For "end" events, the function calculates the duration, removes the corresponding
          start record, and appends the timing information to `timing_list`.
        - If a GUID is not found in the `guids` dictionary, a placeholder string is generated
          using a hash of the GUID.
        - Errors are logged for duplicate start records, missing start events, or unrecognized
          ProgressIDs.
    """
    progress_id_string = f"0x{int(record.find('ProgressID').attrib['Value'], 16):04X}"
    progress_id_string_minus_one = f"0x{int(record.find('ProgressID').attrib['Value'], 16) - 1:04X}"

    # Can be load_image, binding_support, binding_start, binding_stop begin
    if progress_id_string in GUID_QWORD_PROGRESS_IDS:
        # here we need to create an entry for a label:start_time dict, start_records_dict

        # label here will depend on type
        event_type = PROGRESS_ID_LABEL_DICT[progress_id_string]

        if event_type == "LoadImage":
            # label here is <type>_<qword> because guid is only populated in the end record
            qword = record.find("Qword").attrib["Value"]
            label = f"{event_type}_{qword}"
        else:
            # otherwise this is a binding-related record and GUID is of the driver
            # thus the label is <type>_<guid_string>_<qword>
            guid = record.find("GUID").attrib["Value"]
            if "554E-4B4E484E444C" in guid:
                guid_string = f"HANDLE-NOT-FOUND-{hashlib.sha256(guid.encode('utf-8')).hexdigest()[0:4]}"
            else:
                guid_string = (
                    guids[guid]
                    if (guid in guids)
                    else f"UNKNOWN-{hashlib.sha256(guid.encode('utf-8')).hexdigest()[0:4]}"
                )
            qword = record.find("Qword").attrib["Value"]
            label = f"{event_type}_{guid_string}_{qword}"

        start_time = float(record.find("Timestamp").attrib["ValueInMilliseconds"])

        # place this into the starts dictionary, but check if one with same label is already there
        if label in start_records_dict:
            logging.error(f"Error! Start record with label {label} already in dict!")
            messages.append(("Error", f"Start record with label {label} already in dict!"))
        else:
            start_records_dict[label] = start_time

    # Can be load_image, binding_support, binding_stop end
    elif progress_id_string_minus_one in GUID_QWORD_PROGRESS_IDS:
        # label here will depend on type
        event_type = PROGRESS_ID_LABEL_DICT[progress_id_string_minus_one]

        if event_type == "LoadImage":
            # label here is <type>_<qword> because guid is only populated in the end record
            qword = record.find("Qword").attrib["Value"]
            label = f"{event_type}_{qword}"
        else:
            # otherwise this is a binding-related record and GUID is of the driver
            # thus the label is <type>_<guid_string>_<qword>
            guid = record.find("GUID").attrib["Value"]
            if "554E-4B4E484E444C" in guid:
                guid_string = f"HANDLE-NOT-FOUND-{hashlib.sha256(guid.encode('utf-8')).hexdigest()[0:4]}"
            else:
                guid_string = (
                    guids[guid]
                    if (guid in guids)
                    else f"UNKNOWN-{hashlib.sha256(guid.encode('utf-8')).hexdigest()[0:4]}"
                )
            qword = record.find("Qword").attrib["Value"]
            label = f"{event_type}_{guid_string}_{qword}"

        if label in start_records_dict:
            start_time = start_records_dict[label]
            del start_records_dict[label]
            length = float(record.find("Timestamp").attrib["ValueInMilliseconds"]) - start_time
            if length < 0:
                logging.error("Error! Cannot have negative time!")

            if event_type == "LoadImage":
                guid = record.find("GUID").attrib["Value"]
                if "554E-4B4E484E444C" in guid:
                    guid_string = f"HANDLE-NOT-FOUND-{hashlib.sha256(guid.encode('utf-8')).hexdigest()[0:4]}"
                else:
                    guid_string = (
                        guids[guid]
                        if (guid in guids)
                        else f"UNKNOWN-{hashlib.sha256(guid.encode('utf-8')).hexdigest()[0:4]}"
                    )
                timing_list.append(
                    (
                        id_counter,
                        event_type,
                        guid,
                        guid_string,
                        f"LoadImage measurement for module {guid_string}",
                        start_time,
                        length,
                    )
                )
                id_counter += 1
            else:
                # then this must be binding_support, binding_stop end
                guid = record.find("GUID").attrib["Value"]
                if "554E-4B4E484E444C" in guid:
                    guid_string = f"HANDLE-NOT-FOUND-{hashlib.sha256(guid.encode('utf-8')).hexdigest()[0:4]}"
                else:
                    guid_string = (
                        guids[guid]
                        if (guid in guids)
                        else f"UNKNOWN-{hashlib.sha256(guid.encode('utf-8')).hexdigest()[0:4]}"
                    )
                qword = record.find("Qword").attrib["Value"]
                string_value = controller_handle_dict[qword] if (qword in controller_handle_dict) else "Unknown Device"

                #                 (<ID#>, <Type>, <GUID>, <GuidValue>, <String>, <StartTime>, <Length>)
                timing_list.append(
                    (
                        id_counter,
                        event_type,
                        guid,
                        guid_string,
                        f"{event_type} measurement for module {guid_string} and device {string_value}",
                        start_time,
                        length,
                    )
                )
                id_counter += 1
        else:
            logging.error(f"Error! Can't find a start event in the dict for label {label}!")
            messages.append(("Error", f"Can't find a start event in the dict for label {label}!"))
    else:
        logging.critical(f"Error! Unrecognized progress ID {progress_id_string}")
        messages.append(("Error", f"Unrecognized progress ID {progress_id_string}"))
        unrecognized_records += 1

    return id_counter, unrecognized_records


def _process_guid_qword_string_event(
    record: ET.Element,
    guids: dict[str, str],
    timing_list: list[tuple[int, str, str, str, str, float, float]],
    start_records_dict: dict[str, float],
    messages: list[tuple[str, str]],
    id_counter: int,
    unrecognized_records: int,
) -> tuple[int, int]:
    """Processes a GuidQwordStringEvent record and updates timing information, messages, and counters.

    Args:
        record (ET.Element): The XML element representing the event record.
        guids (dict[str, str]): A dictionary mapping GUIDs to their string representations.
        timing_list (list[tuple[int, str, str, str, str, float, float]]): A list to store timing information.
        start_records_dict (dict[str, float]): A dictionary containing start event labels and their timestamps.
        messages (list[tuple[str, str]]): A list to store error or informational messages.
        id_counter (int): A counter for assigning unique IDs to timing entries.
        unrecognized_records (int): A counter for tracking unrecognized records.

    Returns:
        tuple[int, int]: Updated id_counter and unrecognized_records values.

    Notes:
        - The function checks if the progress ID is recognized and processes the event accordingly.
        - If a matching start event is found, it calculates the duration and appends the timing information.
        - If no matching start event is found, an error message is logged and added to the messages list.
        - Handles GUIDs that are not found in the provided dictionary by generating a placeholder string.
    """
    progress_id_string_minus_one = f"0x{int(record.find('ProgressID').attrib['Value'], 16) - 1:04X}"

    # Check that the progress ID is decodeable
    if progress_id_string_minus_one not in PROGRESS_ID_LABEL_DICT:
        logging.critical(f"Error! Unrecognized progress ID {progress_id_string_minus_one}")
        messages.append(("Error", f"Unrecognized progress ID {progress_id_string_minus_one}"))
        unrecognized_records += 1
        return id_counter, unrecognized_records

    # Should only be binding_start end
    event_type = PROGRESS_ID_LABEL_DICT[progress_id_string_minus_one]

    # the type should be binding_start

    # the label is <type>_<guid_string>_<qword>
    guid = record.find("GUID").attrib["Value"]
    if "554E-4B4E484E444C" in guid:
        guid_string = f"HANDLE-NOT-FOUND-{hashlib.sha256(guid.encode('utf-8')).hexdigest()[0:4]}"
    else:
        guid_string = (
            guids[guid] if (guid in guids) else f"UNKNOWN-{hashlib.sha256(guid.encode('utf-8')).hexdigest()[0:4]}"
        )
    qword = record.find("Qword").attrib["Value"]
    label = f"{event_type}_{guid_string}_{qword}"

    if label in start_records_dict:
        start_time = start_records_dict[label]
        del start_records_dict[label]
        length = float(record.find("Timestamp").attrib["ValueInMilliseconds"]) - start_time
        if length < 0:
            logging.error("Error! Cannot have negative time!")

        string_value = record.find("String").attrib["Value"]
        timing_list.append(
            (
                id_counter,
                event_type,
                guid,
                guid_string,
                f"{event_type} measurement for module {guid_string} and device {string_value}",
                start_time,
                length,
            )
        )
        id_counter += 1

    else:
        logging.error(f"Error! Can't find a start event in the dict for label {label}!")
        messages.append(("Error", f"Can't find a start event in the dict for label {label}!"))

    return id_counter, unrecognized_records


def _process_guid_event(
    record: ET.Element,
    guids: dict[str, str],
    timing_list: list[tuple[int, str, str, str, str, float, float]],
    start_records_dict: dict[str, float],
    messages: list[tuple[str, str]],
    id_counter: int,
    unrecognized_records: int,
) -> tuple[int, int]:
    """Processes a GUID event record based on the event type (start or end).

    Args:
        record (ET.Element): The XML element representing the GUID event record.
        guids (dict[str, str]): A dictionary mapping GUIDs to their string representations.
        timing_list (list[tuple[int, str, str, str, str, float, float]]): A list to store timing information
            for processed events. Each entry contains:
            (<ID#>, <Type>, <GUID>, <GuidValue>, <String>, <StartTime>, <Length>).
        start_records_dict (dict[str, float]): A dictionary to track start times of events by their labels.
        messages (list[tuple[str, str]]): A list to store error or informational messages.
        id_counter (int): A counter for generating unique IDs for timing entries.
        unrecognized_records (int): A counter for tracking unrecognized progress IDs.

    Returns:
        tuple[int, int]: Updated values of `id_counter` and `unrecognized_records`.

    Behavior:
        - If the event is a start event, it adds the start time to `start_records_dict`.
        - If the event is an end event, it calculates the duration, updates `timing_list`,
          and removes the corresponding start entry from `start_records_dict`.
        - Logs errors and appends messages for duplicate start events, missing start events,
          or unrecognized progress IDs.
    """
    # this must be an entrypoint record, start or end
    progress_id_string = f"0x{int(record.find('ProgressID').attrib['Value'], 16):04X}"
    progress_id_string_minus_one = f"0x{int(record.find('ProgressID').attrib['Value'], 16) - 1:04X}"

    if progress_id_string == GUID_PROGRESS_ID:
        # here we need to create an entry for a label:start_time dict, start_records_dict

        # label is <type>_<guid_string>
        event_type = PROGRESS_ID_LABEL_DICT[progress_id_string]
        guid = record.find("GUID").attrib["Value"]
        if "554E-4B4E484E444C" in guid:
            guid_string = f"HANDLE-NOT-FOUND-{hashlib.sha256(guid.encode('utf-8')).hexdigest()[0:4]}"
        else:
            guid_string = (
                guids[guid] if (guid in guids) else f"UNKNOWN-{hashlib.sha256(guid.encode('utf-8')).hexdigest()[0:4]}"
            )
        label = f"{event_type}_{guid_string}"

        start_time = float(record.find("Timestamp").attrib["ValueInMilliseconds"])

        # place this into the starts dictionary, but check if one with same label is already there
        if label in start_records_dict:
            logging.error(f"Error! Start record with label {label} already in dict!")
            messages.append(("Error", f"Start record with label {label} already in dict!"))
        else:
            start_records_dict[label] = start_time

    elif progress_id_string_minus_one == GUID_PROGRESS_ID:
        # label is <type>_<guid_string>
        event_type = PROGRESS_ID_LABEL_DICT[progress_id_string_minus_one]
        guid = record.find("GUID").attrib["Value"]
        if "554E-4B4E484E444C" in guid:
            guid_string = f"HANDLE-NOT-FOUND-{hashlib.sha256(guid.encode('utf-8')).hexdigest()[0:4]}"
        else:
            guid_string = (
                guids[guid] if (guid in guids) else f"UNKNOWN-{hashlib.sha256(guid.encode('utf-8')).hexdigest()[0:4]}"
            )
        label = f"{event_type}_{guid_string}"

        if label in start_records_dict:
            start_time = start_records_dict[label]
            del start_records_dict[label]
            length = float(record.find("Timestamp").attrib["ValueInMilliseconds"]) - start_time
            if length < 0:
                logging.error("Error! Cannot have negative time!")

            #                 (<ID#>, <Type>, <GUID>, <GuidValue>, <String>, <StartTime>, <Length>)
            timing_list.append(
                (
                    id_counter,
                    event_type,
                    guid,
                    guid_string,
                    f"{event_type} measurement for module {guid_string}",
                    start_time,
                    length,
                )
            )
            id_counter += 1
        else:
            logging.error(f"Error! Can't find a start event in the dict for label {label}!")
            messages.append(("Error", f"Can't find a start event in the dict for label {label}!"))
    else:
        logging.critical(f"Error! Unrecognized progress ID {progress_id_string}")
        messages.append(("Error", f"Unrecognized progress ID {progress_id_string}"))
        unrecognized_records += 1

    return id_counter, unrecognized_records


def _process_dual_guid_string_event(
    record: ET.Element,
    guids: dict[str, str],
    timing_list: list[tuple[int, str, str, str, str, float, float]],
    start_records_dict: dict[str, float],
    messages: list[tuple[str, str]],
    id_counter: int,
    unrecognized_records: int,
) -> tuple[int, int]:
    """Process a DualGuidStringEvent record and update timing information, start records, and messages.

    This function handles two types of events:

    1. Start events: Adds a start time entry to the `start_records_dict` for a specific label.
    2. End events: Calculates the duration of an event, removes the corresponding start time entry,
       and appends the timing information to the `timing_list`.

    Args:
        record (ET.Element): The XML element representing the event record.
        guids (dict[str, str]): A dictionary mapping GUIDs to their string representations.
        timing_list (list[tuple[int, str, str, str, str, float, float]]): A list to store timing information.
            Each entry is a tuple containing:
            - ID (int)
            - Event type (str)
            - GUIDs (str)
            - GUID string representations (str)
            - Description (str)
            - Start time (float)
            - Duration (float)
        start_records_dict (dict[str, float]): A dictionary mapping event labels to their start times.
        messages (list[tuple[str, str]]): A list to store error or informational messages.
            Each entry is a tuple containing:
            - Message type (str)
            - Message content (str)
        id_counter (int): A counter for generating unique IDs for timing entries.
        unrecognized_records (int): A counter for tracking unrecognized records.

    Returns:
        tuple[int, int]: Updated values for:
            - `id_counter` (int): The incremented ID counter.
            - `unrecognized_records` (int): The updated count of unrecognized records.

    Raises:
        ValueError: If a negative time duration is calculated.

    Notes:
        - If a start event with the same label already exists in `start_records_dict`, an error is logged,
          and a message is appended to `messages`.
        - If an end event is encountered without a corresponding start event, an error is logged,
          and a message is appended to `messages`.
        - If the progress ID is unrecognized, an error is logged, and the `unrecognized_records` counter is incremented.
    """
    progress_id_string = f"0x{int(record.find('ProgressID').attrib['Value'], 16):04X}"
    progress_id_string_minus_one = f"0x{int(record.find('ProgressID').attrib['Value'], 16) - 1:04X}"

    # Can be event_signal or callback begin
    if progress_id_string in DUAL_GUID_STRING_PROGRESS_IDS:
        # here we need to create an entry for a label:start_time dict, start_records_dict

        event_type = PROGRESS_ID_LABEL_DICT[progress_id_string]
        guid1 = record.find("GUID1").attrib["Value"]
        guid_string1 = (
            guids[guid1] if (guid1 in guids) else f"UNKNOWN-{hashlib.sha256(guid1.encode('utf-8')).hexdigest()[0:4]}"
        )
        guid2 = record.find("GUID2").attrib["Value"]
        guid_string2 = (
            guids[guid2] if (guid2 in guids) else f"UNKNOWN-{hashlib.sha256(guid2.encode('utf-8')).hexdigest()[0:4]}"
        )
        string_value = record.find("String").attrib["Value"]
        label = f"{event_type}_{guid_string1}_{guid_string2}_{string_value}"

        start_time = float(record.find("Timestamp").attrib["ValueInMilliseconds"])

        # place this into the starts dictionary, but check if one with same label is already there
        if label in start_records_dict:
            logging.error(f"Error! Start record with label {label} already in dict!")
            messages.append(("Error", f"Start record with label {label} already in dict!"))
        else:
            start_records_dict[label] = start_time

    # Can be event_signal or callback end
    elif progress_id_string_minus_one in DUAL_GUID_STRING_PROGRESS_IDS:
        event_type = PROGRESS_ID_LABEL_DICT[progress_id_string_minus_one]
        guid1 = record.find("GUID1").attrib["Value"]
        guid_string1 = (
            guids[guid1] if (guid1 in guids) else f"UNKNOWN-{hashlib.sha256(guid1.encode('utf-8')).hexdigest()[0:4]}"
        )
        guid2 = record.find("GUID2").attrib["Value"]
        guid_string2 = (
            guids[guid2] if (guid2 in guids) else f"UNKNOWN-{hashlib.sha256(guid2.encode('utf-8')).hexdigest()[0:4]}"
        )
        string_value = record.find("String").attrib["Value"]
        label = f"{event_type}_{guid_string1}_{guid_string2}_{string_value}"

        if label in start_records_dict:
            start_time = start_records_dict[label]
            del start_records_dict[label]
            length = float(record.find("Timestamp").attrib["ValueInMilliseconds"]) - start_time
            if length < 0:
                logging.error("Error! Cannot have negative time!")

            #                  (<ID#>,  <Type>, <GUID>, <GuidValue>, <String>, <StartTime>, <Length>)
            description_string = f"{event_type} measurement from module {guid_string2} and trigger/event {guid_string1}"
            timing_list.append(
                (
                    id_counter,
                    event_type,
                    f"{guid2}, {guid1}",
                    f"{guid_string2}, {guid_string1}",
                    description_string,
                    start_time,
                    length,
                )
            )
            id_counter += 1
        else:
            logging.error(f"Error! Can't find a start event in the dict for label {label}!")
            messages.append(("Error", f"Can't find a start event in the dict for label {label}!"))
    else:
        logging.error(f"Error! Unrecognized progress ID {progress_id_string}")
        messages.append(("Error", f"Unrecognized progress ID {progress_id_string}"))
        unrecognized_records += 1

    return id_counter, unrecognized_records


def _check_unmatched_start_records(start_records_dict: dict[str, float], messages: list[tuple[str, str]]) -> None:
    """Check for unmatched start records.

    Args:
        start_records_dict (dict[str, float]): Dictionary of start records with their start times.
        messages (list[tuple[str, str]]): List to store error or informational messages.
    """
    if len(start_records_dict) != 0:
        logging.error(
            f"Error! {len(start_records_dict)} start record(s) with no matching end record(s) found:\n   "
            f"{start_records_dict}"
        )
        messages.append(
            (
                "Error",
                f"{len(start_records_dict)} start record(s) with no matching end record(s) found: {start_records_dict}",
            )
        )


def _write_text_output(timing_list: list[tuple[int, str, str, str, str, float, float]], text_log: "TextIO") -> None:
    """Write timing list to the text log.

    Note: `text_log` is expected to be a file object opened in write mode.

    Args:
        timing_list (list[tuple[int, str, str, str, str, float, float]]): List of timing data tuples.
        text_log (TextIO): File object for the text log.
    """
    logging.critical("Writing text log output")
    for timing in timing_list:
        text_log.write(f"{timing}\n")
    text_log.close()


def write_html_report(
    input_xml_file: str,
    timing_list: list[tuple[str, str, str, str, str, float, float]],
    messages: list[tuple[str, str]],
    html_report: "TextIO",
) -> None:
    """Write the timing list and messages to an HTML report.

    Args:
        input_xml_file (str): Path to the input XML file with raw FPDT data.
        timing_list (list[tuple[str, str, str, str, str, float, float]]): List of timing data tuples.
        messages (list[tuple[str, str]]): List of message tuples.
        html_report (TextIO): File object for the HTML report.
    """
    logging.critical("Writing HTML Report")
    uefi_version_xml = ET.parse(input_xml_file).find("UEFIVersion")
    model_xml = ET.parse(input_xml_file).find("Model")
    date_collected_xml = ET.parse(input_xml_file).find("DateCollected")
    fpdt_parser_version_xml = ET.parse(input_xml_file).find("FpdtParserVersion")

    script_dir = os.path.dirname(os.path.abspath(__file__))
    template = open(os.path.join(script_dir, "perf_report_template.html"), "r")
    for line in template.readlines():
        if "%TO_BE_FILLED_IN_BY_PYTHON_SCRIPT%" in line:
            html_report.write('        var JsonData = {"Data": {')
            html_report.write(f'"Model": "{model_xml.attrib["Value"]}",')
            html_report.write(f'"UefiVersion": "{uefi_version_xml.attrib["Value"]}",')
            html_report.write(f'"DateCollected": "{date_collected_xml.attrib["Value"]}",')
            html_report.write(f'"ReportGenVersion": "{REPORT_GENERATOR_VER}",')
            html_report.write(f'"FpdtParserVersion": "{fpdt_parser_version_xml.attrib["Value"]}",')
            html_report.write('"TimingData": [')
            first = True
            for timing in timing_list:
                if not first:
                    html_report.write(",")
                first = False
                html_report.write(
                    f'{{"ID": "{timing[0]}","Type": "{timing[1]}","GUID": "{timing[2]}","GuidValue": "{timing[3]}",'
                    f'"String": "{timing[4]}","StartTime": "{timing[5]:.6f}","Length": "{timing[6]:.6f}"}}'
                )
            html_report.write("],")
            html_report.write('"Messages": [')
            first = True
            for message in messages:
                if not first:
                    html_report.write(",")
                first = False
                html_report.write(f'{{"Type": "{message[0]}", "Message": "{message[1]}"}}')
            html_report.write("]}};")
        else:
            html_report.write(line)
    template.close()
    html_report.close()


if __name__ == "__main__":
    # setup main console as logger
    logger = logging.getLogger("")
    logger.setLevel(logging.DEBUG)
    formatter = logging.Formatter("%(levelname)s - %(message)s")
    console = logging.StreamHandler()
    console.setLevel(logging.CRITICAL)
    console.setFormatter(formatter)
    logger.addHandler(console)

    # call main worker function
    retcode = main()

    if retcode != 0:
        logging.critical(f"Test Failed.  Return Code: {retcode}")
    # end logging
    logging.shutdown()
    sys.exit(retcode)
