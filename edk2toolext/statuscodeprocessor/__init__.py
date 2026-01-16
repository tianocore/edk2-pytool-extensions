"""UEFI Status Code Processor.

Copyright (c) Microsoft Corporation
SPDX-License-Identifier: BSD-2-Clause-Patent

A tool for parsing and decoding UEFI/EDK2 status codes from debug logs.
Supports both standard PI specification codes and platform-specific custom codes,
with automatic header discovery, macro resolution, and GUID-to-module name lookup.
"""

from .statuscodeprocessor import (
    discover_status_code_headers,
    find_guid_in_files,
    main,
    parse_platform_status_codes,
    parse_single_header_file,
    parse_status_code_type,
    parse_status_code_value,
    process_error_code,
    process_progress_code,
)

__all__ = [
    "discover_status_code_headers",
    "find_guid_in_files",
    "main",
    "parse_platform_status_codes",
    "parse_single_header_file",
    "parse_status_code_type",
    "parse_status_code_value",
    "process_error_code",
    "process_progress_code",
]
