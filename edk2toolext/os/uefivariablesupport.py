# @file uefivariablesupport.py
#
# Exports Class to allow OS level interaction
# with UEFI variables. Includes Windows and
# Linux support.
#
#
# Copyright (c), Microsoft Corporation
# SPDX-License-Identifier: BSD-2-Clause-Patent
#
# GetUefiAllVarNames linux implementation is based on information from
# https://github.com/awslabs/python-uefivars/blob/main/pyuefivars/efivarfs.py
#
# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: MIT
"""Exports UefiVariables class to allow OS level interaction with Uefi Variables. Includes Windows and Linux support.

This module provides:
- UefiVariable: Class to interfact with Uefi Variables from OS.
"""

import logging
import os
import struct
import uuid
from ctypes import create_string_buffer

if os.name == 'nt':
    from ctypes import WinError, c_int, c_void_p, c_wchar_p, pointer, windll
    from ctypes.wintypes import DWORD

    from win32 import win32api, win32process, win32security


EFI_VAR_MAX_BUFFER_SIZE = 1024 * 1024


class UefiVariable(object):
    """Class to interact with Uefi Variables under Windows or Linux.

    Methods:
    -------
    GetUefiVar - Get a single Uefi Variable's data
    GetUefiAllVarNames - Get all Uefi variables
    SetUefiVar - Set (or delete) a single Uefi variable.
    """
    ERROR_ENVVAR_NOT_FOUND = 0xcb

    def __init__(self) -> None:
        """Initialize Class."""
        if os.name == 'nt':
            # enable required SeSystemEnvironmentPrivilege privilege
            privilege = win32security.LookupPrivilegeValue(
                None, "SeSystemEnvironmentPrivilege"
            )
            token = win32security.OpenProcessToken(
                win32process.GetCurrentProcess(),
                win32security.TOKEN_READ | win32security.TOKEN_ADJUST_PRIVILEGES,
            )
            win32security.AdjustTokenPrivileges(
                token, False, [(privilege, win32security.SE_PRIVILEGE_ENABLED)]
            )
            win32api.CloseHandle(token)

            # import firmware variable API
            try:
                self._GetFirmwareEnvironmentVariable = (
                    windll.kernel32.GetFirmwareEnvironmentVariableW
                )
                self._GetFirmwareEnvironmentVariable.restype = c_int
                self._GetFirmwareEnvironmentVariable.argtypes = [
                    c_wchar_p,
                    c_wchar_p,
                    c_void_p,
                    c_int,
                ]
                self._EnumerateFirmwareEnvironmentVariable = (
                    windll.ntdll.NtEnumerateSystemEnvironmentValuesEx
                )
                self._EnumerateFirmwareEnvironmentVariable.restype = c_int
                self._EnumerateFirmwareEnvironmentVariable.argtypes = [
                    c_int,
                    c_void_p,
                    c_void_p
                ]
                self._SetFirmwareEnvironmentVariable = (
                    windll.kernel32.SetFirmwareEnvironmentVariableW
                )
                self._SetFirmwareEnvironmentVariable.restype = c_int
                self._SetFirmwareEnvironmentVariable.argtypes = [
                    c_wchar_p,
                    c_wchar_p,
                    c_void_p,
                    c_int,
                ]
                self._SetFirmwareEnvironmentVariableEx = (
                    windll.kernel32.SetFirmwareEnvironmentVariableExW
                )
                self._SetFirmwareEnvironmentVariableEx.restype = c_int
                self._SetFirmwareEnvironmentVariableEx.argtypes = [
                    c_wchar_p,
                    c_wchar_p,
                    c_void_p,
                    c_int,
                    c_int,
                ]
            except Exception:
                logging.warn(
                    "G[S]etFirmwareEnvironmentVariableW function doesn't seem to exist"
                )
        else:
            pass

    def GetUefiVar(self, name: str, guid: str) -> tuple[int, str]:
        """_Retrieve Uefi Variable from the system.

        Args:
            name (str): String corresponding to the Unicode Name of the variable.
            guid (str): String corresponding to the Uefi Guid of the variable.

        Returns:
            Tuple: (error code, string of variable data)
        """
        err = 0
        if os.name == 'nt':
            efi_var = create_string_buffer(EFI_VAR_MAX_BUFFER_SIZE)
            if self._GetFirmwareEnvironmentVariable is not None:
                logging.info(
                    "calling GetFirmwareEnvironmentVariable( name='%s', GUID='%s' ).."
                    % (name, "{%s}" % guid)
                )
                length = self._GetFirmwareEnvironmentVariable(
                    name, "{%s}" % guid, efi_var, EFI_VAR_MAX_BUFFER_SIZE
                )
            if (0 == length) or (efi_var is None):
                err = windll.kernel32.GetLastError()
                if err != 0 and err != UefiVariable.ERROR_ENVVAR_NOT_FOUND:
                    logging.error(
                        "GetFirmwareEnvironmentVariable[Ex] failed (GetLastError = 0x%x)" % err
                    )
                    logging.error(WinError())
                if efi_var is None:
                    return (err, None)
            return (err, efi_var[:length])

        else:
            # the variable name is VariableName-Guid
            path = '/sys/firmware/efi/efivars/' + name + '-%s' % guid

            if not os.path.exists(path):
                err = UefiVariable.ERROR_ENVVAR_NOT_FOUND
                return (err, None)

            efi_var = create_string_buffer(EFI_VAR_MAX_BUFFER_SIZE)
            with open(path, 'rb') as fd:
                efi_var = fd.read()

            return (err, efi_var[:length])

    def GetUefiAllVarNames(self) -> tuple[int, bytes]:
        """Get all Uefi Variables in the system, and return a byte packed byte string.

        Raises:
            Exception: Returned variable could not be parsed.

        Returns:
            tuple[int, bytes]:
            Integer is return status, 0 for error, non-zero for success.
            Bytes are the packed structure for each variable.
                struct _VARIABLE_NAME {
                    ULONG NextEntryOffset;
                    GUID VendorGuid;
                    WCHAR Name[ANYSIZE_ARRAY];
                }
        """
        status = 0
        if os.name == 'nt':
            # From NTSTATUS definition:
            # (https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-erref/596a1078-e883-4972-9bbc-49e60bebca55)
            STATUS_BUFFER_TOO_SMALL = 0xC0000023
            VARIABLE_INFORMATION_NAMES = 1

            length = DWORD(0)
            efi_var_names = create_string_buffer(length.value)
            if self._EnumerateFirmwareEnvironmentVariable is not None:
                logging.info(
                    "calling _EnumerateFirmwareEnvironmentVariable to get size.."
                )
                status = self._EnumerateFirmwareEnvironmentVariable(
                    VARIABLE_INFORMATION_NAMES, efi_var_names, pointer(length))
                # Only inspect the lower 32 bits.
                status = (0xFFFFFFFF & status)
                if status == STATUS_BUFFER_TOO_SMALL:
                    logging.info(
                        "calling _EnumerateFirmwareEnvironmentVariable again to get data..")
                    efi_var_names = create_string_buffer(length.value)
                    status = self._EnumerateFirmwareEnvironmentVariable(
                        VARIABLE_INFORMATION_NAMES, efi_var_names, pointer(
                            length))
            if (0 != status):
                logging.error(
                    "EnumerateFirmwareEnvironmentVariable failed (GetLastError = 0x%x)" % status
                )
                return (status, None)
            return (status, efi_var_names)
        else:
            # implementation borrowed from https://github.com/awslabs/python-uefivars/blob/main/pyuefivars/efivarfs.py
            path = '/sys/firmware/efi/efivars'
            if not os.path.exists(path):
                status = UefiVariable.ERROR_ENVVAR_NOT_FOUND
                return (status, None)

            vars = os.listdir(path)

            # get the total buffer length, converting to unicode
            length = 0
            offset = 0
            for var in vars:
                split_string = var.split('-')
                name = '-'.join(split_string[:-5])
                name = name.encode('utf-16-le')
                name_len = len(name)
                length += (4 + 16 + name_len)

            efi_var_names = create_string_buffer(length)

            for var in vars:
                # efivarfs stores vars as NAME-GUID
                split_string = var.split('-')
                try:
                    # GUID is last 5 elements of split_string
                    guid = uuid.UUID('-'.join(split_string[-5:])).bytes_le
                except ValueError:
                    raise Exception(f'Could not parse "{var}"')

                # the other part is the name
                name = '-'.join(split_string[:-5])
                name = name.encode('utf-16-le')
                name_len = len(name)

                # NextEntryOffset
                struct.pack_into('<I', efi_var_names,
                                 offset, 4 + 16 + name_len)
                offset += 4

                # VendorGuid
                struct.pack_into('=16s', efi_var_names, offset, guid)
                offset += 16

                # Name
                struct.pack_into(f'={name_len}s', efi_var_names, offset, name)
                offset += name_len

            return (status, efi_var_names)

    def SetUefiVar(self, name: str, guid: str, var: str = None, attrs: int = None) -> int:
        """_Set a Uefi Variable into the system.

        Args:
            name (str): Unicode name of variable to set
            guid (str): Guid to use when setting the variable
            var (bytes, optional): Bytes to set to the variable. Defaults to None.
            attrs (_type_, optional): Attributes to use when setting the variable. Defaults to None.

        Returns:
            int: 0 for a failure, non-zero for success
        """
        success = 0  # Fail

        if os.name == 'nt':
            var_len = 0
            err = 0
            if var is None:
                var = bytes(0)
            else:
                var_len = len(var)
            success = 0  # Fail
            if attrs is None:
                if self._SetFirmwareEnvironmentVariable is not None:
                    logging.info(
                        "Calling SetFirmwareEnvironmentVariable (name='%s', Guid='%s')..."
                        % (
                            name,
                            "{%s}" % guid,
                        )
                    )
                    success = self._SetFirmwareEnvironmentVariable(
                        name, "{%s}" % guid, var, var_len
                    )
            else:
                attrs = int(attrs)
                if self._SetFirmwareEnvironmentVariableEx is not None:
                    logging.info(
                        f"SetFirmwareEnvironmentVariableEx( name={name},"
                        + f"GUID={guid}, length={var_len}, attributes={attrs} )"
                        )
                    success = self._SetFirmwareEnvironmentVariableEx(
                        name, "{%s}" % guid, var, var_len, attrs
                    )

            if 0 == success:
                err = windll.kernel32.GetLastError()
                logging.error(
                    "SetFirmwareEnvironmentVariable failed (GetLastError = 0x%x)" % err
                )
                logging.error(WinError())
            return success
        else:
            # There is a null terminator at the end of the name
            path = '/sys/firmware/efi/efivars/' + name[:-1] + '-' + str(guid)
            if var is None:
                # we are deleting the variable
                if (os.path.exists(path)):
                    os.remove(path)
                    success = 1  # expect non-zero success
                return success

            if attrs is None:
                attrs = 0x7

            # if the file exists, remove the immutable flag
            if (os.path.exists(path)):
                os.system('sudo chattr -i ' + path)

            with open(path, 'wb') as fd:
                # var data is attribute (UINT32) followed by data
                packed = struct.pack('=I', attrs)
                packed += var
                fd.write(packed)

        return 1
