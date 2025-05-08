# @file test_perf_report_generator.py
# This contains unit tests for the performance report generator module.
##
# Copyright (c) Microsoft Corporation
#
# SPDX-License-Identifier: BSD-2-Clause-Patent
##
"""Unit test for the performance report generator module."""

import io
import os
import shutil
import tempfile
import unittest
import xml
from collections import namedtuple
from unittest.mock import mock_open, patch

from edk2toolext.perf.perf_report_generator import (
    _format_guid,
    add_guid,
    parse_fpdt_records,
    parse_guids_in_directory,
    write_html_report,
)

# Allow some test data lines to be long to preserve expected formatting
# flake8: noqa: E501

# DEC test file content
DEC_GUIDS = {
    "487784C5-6299-4BA6-B096-5CC5277CF757": "gEdkiiCapsuleUpdatePolicyProtocolGuid",
    "40B2D964-FE11-40DC-8283-2EFBDA295356": "gFmpDevicePkgTokenSpaceGuid",
}

FMP_DEVICE_PKG_DEC_CONTENTS = """## @file
# Firmware Management Protocol Device Package
#
# This package provides an implementation of a Firmware Management Protocol
# instance that supports the update of firmware storage devices using UEFI
# Capsules.  The behavior of the Firmware Management Protocol instance is
# customized using libraries and PCDs.
#
# Copyright (c) 2016, Microsoft Corporation. All rights reserved.<BR>
# Copyright (c) 2018 - 2020, Intel Corporation. All rights reserved.<BR>
#
# SPDX-License-Identifier: BSD-2-Clause-Patent
#
##

[Defines]
  DEC_SPECIFICATION = 0x00010005
  PACKAGE_NAME      = FmpDevicePkg
  PACKAGE_UNI_FILE  = FmpDevicePkg.uni
  PACKAGE_GUID      = 080b5b4f-27c6-11e8-84d1-f8597177a00a
  PACKAGE_VERSION   = 0.1

[Includes]
  Include

[Includes.Common.Private]
  PrivateInclude

[LibraryClasses]
  ##  @libraryclass  Provides platform policy services used during a capsule
  #                  update.
  CapsuleUpdatePolicyLib|Include/Library/CapsuleUpdatePolicyLib.h

  ##  @libraryclass  Provides firmware device specific services to support
  #                  updates of a firmware image stored in a firmware device.
  FmpDeviceLib|Include/Library/FmpDeviceLib.h

  ##  @libraryclass  Provides generic services to support capsule dependency
  #                  expression evaluation.
  FmpDependencyLib|Include/Library/FmpDependencyLib.h

  ##  @libraryclass  Provides platform specific services to support dependency
  #                  check during update of firmware image.
  FmpDependencyCheckLib|Include/Library/FmpDependencyCheckLib.h

  ##  @libraryclass  Provides firmware device specific services to support
  #                  saving dependency to firmware device and getting dependency
  #                  from firmware device.
  FmpDependencyDeviceLib|Include/Library/FmpDependencyDeviceLib.h

[LibraryClasses.Common.Private]
  ##  @libraryclass  Provides services to retrieve values from a capsule's FMP
  #                  Payload Header.  The structure is not included in the
  #                  library class.  Instead, services are provided to retrieve
  #                  information from the FMP Payload Header.  If information is
  #                  added to the FMP Payload Header, then new services may be
  #                  added to this library class to retrieve the new information.
  FmpPayloadHeaderLib|PrivateInclude/Library/FmpPayloadHeaderLib.h

[Guids]
  ## Firmware Management Protocol Device Package Token Space GUID
  gFmpDevicePkgTokenSpaceGuid = { 0x40b2d964, 0xfe11, 0x40dc, { 0x82, 0x83, 0x2e, 0xfb, 0xda, 0x29, 0x53, 0x56 } }

[Protocols.Common.Private]
  ## Capsule Update Policy Protocol
  gEdkiiCapsuleUpdatePolicyProtocolGuid = { 0x487784c5, 0x6299, 0x4ba6, { 0xb0, 0x96, 0x5c, 0xc5, 0x27, 0x7c, 0xf7, 0x57 } }

[PcdsFeatureFlag]
  ## Indicates if the Firmware Management Protocol supports access to
  #  to a firmware storage device.  If set to FALSE, then only GetImageInfo()
  #  is supported.  This is used by FMP drivers that require the smallest
  #  possible Firmware Management Protocol implementation that supports
  #  advertising the updatable firmware device in the ESRT.<BR>
  #    TRUE  - All Firmware Management Protocol services supported.<BR>
  #    FALSE - Firmware Management Protocol returns EFI_UNSUPPORTED for
  #            all services except GetImageInfo().<BR>
  # @Prompt Firmware Device Storage Access Enabled.
  gFmpDevicePkgTokenSpaceGuid.PcdFmpDeviceStorageAccessEnable|TRUE|BOOLEAN|0x40000011

[PcdsFixedAtBuild]
  ## The SHA-256 hash of a PKCS7 test key that is used to detect if a test key
  #  is being used to authenticate capsules.  Test key detection is disabled by
  #  setting the value to {0}.
  # @Prompt SHA-256 hash of PKCS7 test key.
  gFmpDevicePkgTokenSpaceGuid.PcdFmpDeviceTestKeySha256Digest|{0x2E, 0x97, 0x89, 0x1B, 0xDB, 0xE7, 0x08, 0xAA,  0x8C, 0xB2, 0x8F, 0xAD, 0x20, 0xA9, 0x83, 0xC7,  0x84, 0x7D, 0x4F, 0xEE, 0x48, 0x25, 0xE9, 0x4D,  0x39, 0xFA, 0x34, 0x9A, 0xB8, 0xB1, 0xC4, 0x26}|VOID*|0x40000009

[PcdsFixedAtBuild, PcdsPatchableInModule]
  ## The color of the progress bar during a firmware update.  Each firmware
  #  device can set its own color.  The default color is white.<BR><BR>
  #  Bits  7..0  - Red<BR>
  #  Bits 15..8  - Green<BR>
  #  Bits 23..16 - Blue<BR>
  # @Prompt Firmware Device Progress Bar Color.
  gFmpDevicePkgTokenSpaceGuid.PcdFmpDeviceProgressColor|0x00FFFFFF|UINT32|0x40000004

  ## The Null-terminated Unicode string used to fill in the ImageIdName field of
  #  the EFI_FIRMWARE_IMAGE_DESCRIPTOR structure that is returned by the
  #  GetImageInfo() service of the Firmware Management Protocol for the firmware
  #  device.  An ImageIdName string must be provided for each firmware device.
  #  The default value is an empty string.
  # @Prompt Firmware Device ImageIdName string.
  gFmpDevicePkgTokenSpaceGuid.PcdFmpDeviceImageIdName|L""|VOID*|0x40000007

  ## The build time value used to fill in the LowestSupportedVersion field of
  #  the EFI_FIRMWARE_IMAGE_DESCRIPTOR structure that is returned by the
  #  GetImageInfo() service of the Firmware Management Protocol.  This value is
  #  only used if the firmware device does not provide a method to report the
  #  lowest supported version value from the current firmware image and the
  #  UEFI variable used to provide the lowest supported version value does not
  #  exist.  The default value is 0.
  # @Prompt Build Time Firmware Device Lowest Support Version.
  gFmpDevicePkgTokenSpaceGuid.PcdFmpDeviceBuildTimeLowestSupportedVersion|0x0|UINT32|0x4000000C

  ## The time in seconds to arm a watchdog timer during the update of a firmware
  #  device.  The watchdog is re-armed each time the FmpDeviceLib calls the
  #  Progress() function passed into FmpDeviceSetImage() function.  The
  #  FmpDeviceLib calls Progress() to update the percent completion of a
  #  firmware update.  If the watchdog timer expires, the system reboots.  A
  #  value of 0 disables the watchdog timer.  The default value is 0 (watchdog
  #  disabled).
  # @Prompt Firmware Device Watchdog Time in Seconds.
  gFmpDevicePkgTokenSpaceGuid.PcdFmpDeviceProgressWatchdogTimeInSeconds|0x0|UINT8|0x4000000D

  ## The Image Type ID to use if one is not provided by FmpDeviceLib. If this
  #  PCD is not a valid GUID value, then gEfiCallerIdGuid is used.
  # @Prompt Firmware Device Image Type ID
  gFmpDevicePkgTokenSpaceGuid.PcdFmpDeviceImageTypeIdGuid|{0}|VOID*|0x40000010

[PcdsFixedAtBuild, PcdsPatchableInModule, PcdsDynamic, PcdsDynamicEx]
  ## One or more PKCS7 certificates used to verify a firmware device capsule
  #  update image.  Encoded using the Variable-Length Opaque Data format of RFC
  #  4506 External Data Representation Standard (XDR).  The default value is
  #  empty with 0 certificates.
  # @Prompt One or more XDR encoded PKCS7 certificates used to verify firmware device capsule update images.
  gFmpDevicePkgTokenSpaceGuid.PcdFmpDevicePkcs7CertBufferXdr|{0x0}|VOID*|0x4000000E

  ## An event GUID that locks the firmware device when the event is signaled.
  #  If this PCD is not a valid GUID value, then the firmware device is locked
  #  when gEfiEndOfDxeEventGroupGuid (End of DXE Phase) is signaled.  The
  #  default value is empty, so by default the firmware device is locked at the
  #  end of the DXE phase.
  # @Prompt Firmware Device Lock Event GUID.
  gFmpDevicePkgTokenSpaceGuid.PcdFmpDeviceLockEventGuid|{0}|VOID*|0x4000000F

[UserExtensions.TianoCore."ExtraFiles"]
  FmpDevicePkgExtra.uni
"""


# Simple FDF file content (OVMF/QEMU snippets)
FdfTestModule = namedtuple("FdfTestModule", ["guid", "name"])

FDF_TEST_MODULE = FdfTestModule("12345678-1234-1234-1234-123456789ABC", "TestModule")
FDF_TEST_MODULE2 = FdfTestModule("ABCDEF12-3456-7890-1234-56789ABCDEF0", "TestModule2")

QEMU_FDF_CONTENT = (
    """## @file
#  Open Virtual Machine Firmware for Q35 VM using Project Mu: FDF
#
#  Copyright(c) Microsoft Corporation
#  Copyright (c) 2006 - 2019, Intel Corporation. All rights reserved.<BR>
#  (C) Copyright 2016 Hewlett Packard Enterprise Development LP<BR>
#
#  SPDX-License-Identifier: BSD-2-Clause-Patent
#
##

################################################################################

[Defines]
DEFINE BLOCK_SIZE        = 0x1000

DEFINE VARS_SIZE         = 0x84000
DEFINE VARS_BLOCKS       = 0x84
DEFINE VARS_LIVE_SIZE    = 0x40000
DEFINE VARS_SPARE_SIZE   = 0x42000

DEFINE FW_BASE_ADDRESS   = 0xFFC00000
DEFINE FW_SIZE           = 0x00400000
DEFINE FW_BLOCKS         = 0x400
DEFINE CODE_BASE_ADDRESS = 0xFFC84000
DEFINE CODE_SIZE         = 0x0037C000
DEFINE CODE_BLOCKS       = 0x37C
DEFINE FVMAIN_SIZE       = 0x00348000
DEFINE SECFV_OFFSET      = 0x003CC00
DEFINE SECFV_SIZE        = 0x34000

SET gUefiQemuQ35PkgTokenSpaceGuid.PcdOvmfFdBaseAddress     = $(FW_BASE_ADDRESS)
SET gUefiQemuQ35PkgTokenSpaceGuid.PcdOvmfFirmwareFdSize    = $(FW_SIZE)

[FD.QEMUQ35_VARS]
BaseAddress   = $(FW_BASE_ADDRESS)
Size          = $(VARS_SIZE)
ErasePolarity = 1
BlockSize     = $(BLOCK_SIZE)
NumBlocks     = $(VARS_BLOCKS)

0x00000000|0x00040000
#NV_VARIABLE_STORE
DATA = {
    ## This is the EFI_FIRMWARE_VOLUME_HEADER
    # ZeroVector []
    (
        0x00,
        0x00,
        0x00,
        0x00,
        0x00,
        0x00,
        0x00,
        0x00,
    )
}

[FV.SECFV]
FvNameGuid         = 763BED0D-DE9F-48F5-81F1-3E90E1B1A015
BlockSize          = 0x1000
FvAlignment        = 16
ERASE_POLARITY     = 1
MEMORY_MAPPED      = TRUE
STICKY_WRITE       = TRUE
LOCK_CAP           = TRUE
LOCK_STATUS        = TRUE
WRITE_DISABLED_CAP = TRUE
WRITE_ENABLED_CAP  = TRUE
WRITE_STATUS       = TRUE
WRITE_LOCK_CAP     = TRUE
WRITE_LOCK_STATUS  = TRUE
READ_DISABLED_CAP  = TRUE
READ_ENABLED_CAP   = TRUE
READ_STATUS        = TRUE
READ_LOCK_CAP      = TRUE
"""
    f"""SECTION UI = \"{FDF_TEST_MODULE.name}\"
FILE DRIVER = {FDF_TEST_MODULE.guid} {{ }}

!if FEATURE_ENABLED
  # Comment
  SECTION UI = \"{FDF_TEST_MODULE2.name}\"
  FILE DRIVER = {FDF_TEST_MODULE2.guid} {{ }}
!endif
"""
)


# Simple INF file content
DEBUG_LIB_NULL_BASE_NAME = "BaseDebugLibNull"
DEBUG_LIB_NULL_FILE_GUID = "9BA1D976-0624-41A3-8650-28165E8D9AE8"

DEBUG_LIB_NULL_INF_CONTENTS = f"""## @file
#  Debug Library with empty functions.
#
#  Copyright (c) 2007 - 2018, Intel Corporation. All rights reserved.<BR>
#
#  SPDX-License-Identifier: BSD-2-Clause-Patent
#
#
##

[Defines]
  INF_VERSION                    = 0x00010005
  BASE_NAME                      = {DEBUG_LIB_NULL_BASE_NAME}
  MODULE_UNI_FILE                = {DEBUG_LIB_NULL_BASE_NAME}.uni
  FILE_GUID                      = 9ba1d976-0624-41a3-8650-28165e8d9ae8
  MODULE_TYPE                    = BASE
  VERSION_STRING                 = 1.0
  LIBRARY_CLASS                  = DebugLib


#
#  VALID_ARCHITECTURES           = IA32 X64 EBC
#

[Sources]
  DebugLib.c


[Packages]
  MdePkg/MdePkg.dec
"""


# More complex INF file content
BASE_LIB_BASE_NAME = "BaseLib"
BASE_LIB_FILE_GUID = "27D67720-EA68-48AE-93DA-A3A074C90E30"

BASE_LIB_INF_CONTENTS = f"""## @file
#  Base Library implementation.
#
#  Copyright (c) 2007 - 2021, Intel Corporation. All rights reserved.<BR>
#  Portions copyright (c) 2008 - 2009, Apple Inc. All rights reserved.<BR>
#  Portions copyright (c) 2011 - 2013, ARM Ltd. All rights reserved.<BR>
#  Copyright (c) 2020 - 2021, Hewlett Packard Enterprise Development LP. All rights reserved.<BR>
#
#  SPDX-License-Identifier: BSD-2-Clause-Patent
#
#
##

[Defines]
  INF_VERSION                    = 0x00010005
  BASE_NAME                      = {BASE_LIB_BASE_NAME}
  MODULE_UNI_FILE                = {BASE_LIB_BASE_NAME}.uni
  FILE_GUID                      = {BASE_LIB_FILE_GUID}
  MODULE_TYPE                    = BASE
  VERSION_STRING                 = 1.1
  LIBRARY_CLASS                  = {BASE_LIB_BASE_NAME}

#
#  VALID_ARCHITECTURES           = IA32 X64 EBC ARM AARCH64 RISCV64 LOONGARCH64
#

[Sources]
  CheckSum.c
  SwitchStack.c
  SwapBytes64.c
  SwapBytes32.c
  SwapBytes16.c
  LongJump.c
  SetJump.c
  QuickSort.c
  RShiftU64.c
  RRotU64.c
  RRotU32.c
  MultU64x64.c
  MultU64x32.c
  MultS64x64.c
  ModU64x32.c
  LShiftU64.c
  LRotU64.c
  LRotU32.c
  LowBitSet64.c
  LowBitSet32.c
  HighBitSet64.c
  HighBitSet32.c
  GetPowerOfTwo64.c
  GetPowerOfTwo32.c
  DivU64x64Remainder.c
  DivU64x32Remainder.c
  DivU64x32.c
  DivS64x64Remainder.c
  ARShiftU64.c
  BitField.c
  CpuDeadLoop.c
  Cpu.c
  LinkedList.c
  SafeString.c
  String.c
  FilePaths.c
  BaseLibInternals.h

[Sources.Ia32]
  Ia32/WriteTr.nasm
  Ia32/Lfence.nasm

  Ia32/Wbinvd.c | MSFT
  Ia32/WriteMm7.c | MSFT
  Ia32/WriteMm6.c | MSFT
  Ia32/WriteMm5.c | MSFT
  Ia32/WriteMm4.c | MSFT
  Ia32/WriteMm3.c | MSFT
  Ia32/WriteMm2.c | MSFT
  Ia32/WriteMm1.c | MSFT
  Ia32/WriteMm0.c | MSFT
  Ia32/WriteLdtr.c | MSFT
  Ia32/WriteIdtr.c | MSFT
  Ia32/WriteGdtr.c | MSFT
  Ia32/WriteDr7.c | MSFT
  Ia32/WriteDr6.c | MSFT
  Ia32/WriteDr5.c | MSFT
  Ia32/WriteDr4.c | MSFT
  Ia32/WriteDr3.c | MSFT
  Ia32/WriteDr2.c | MSFT
  Ia32/WriteDr1.c | MSFT
  Ia32/WriteDr0.c | MSFT
  Ia32/WriteCr4.c | MSFT
  Ia32/WriteCr3.c | MSFT
  Ia32/WriteCr2.c | MSFT
  Ia32/WriteCr0.c | MSFT
  Ia32/WriteMsr64.c | MSFT
  Ia32/SwapBytes64.c | MSFT
  Ia32/RRotU64.c | MSFT
  Ia32/RShiftU64.c | MSFT
  Ia32/ReadPmc.c | MSFT
  Ia32/ReadTsc.c | MSFT
  Ia32/ReadLdtr.c | MSFT
  Ia32/ReadIdtr.c | MSFT
  Ia32/ReadGdtr.c | MSFT
  Ia32/ReadTr.c | MSFT
  Ia32/ReadSs.c | MSFT
  Ia32/ReadGs.c | MSFT
  Ia32/ReadFs.c | MSFT
  Ia32/ReadEs.c | MSFT
  Ia32/ReadDs.c | MSFT
  Ia32/ReadCs.c | MSFT
  Ia32/ReadMsr64.c | MSFT
  Ia32/ReadMm7.c | MSFT
  Ia32/ReadMm6.c | MSFT
  Ia32/ReadMm5.c | MSFT
  Ia32/ReadMm4.c | MSFT
  Ia32/ReadMm3.c | MSFT
  Ia32/ReadMm2.c | MSFT
  Ia32/ReadMm1.c | MSFT
  Ia32/ReadMm0.c | MSFT
  Ia32/ReadEflags.c | MSFT
  Ia32/ReadDr7.c | MSFT
  Ia32/ReadDr6.c | MSFT
  Ia32/ReadDr5.c | MSFT
  Ia32/ReadDr4.c | MSFT
  Ia32/ReadDr3.c | MSFT
  Ia32/ReadDr2.c | MSFT
  Ia32/ReadDr1.c | MSFT
  Ia32/ReadDr0.c | MSFT
  Ia32/ReadCr4.c | MSFT
  Ia32/ReadCr3.c | MSFT
  Ia32/ReadCr2.c | MSFT
  Ia32/ReadCr0.c | MSFT
  Ia32/Mwait.c | MSFT
  Ia32/Monitor.c | MSFT
  Ia32/ModU64x32.c | MSFT
  Ia32/MultU64x64.c | MSFT
  Ia32/MultU64x32.c | MSFT
  Ia32/LShiftU64.c | MSFT
  Ia32/LRotU64.c | MSFT
  Ia32/Invd.c | MSFT
  Ia32/FxRestore.c | MSFT
  Ia32/FxSave.c | MSFT
  Ia32/FlushCacheLine.c | MSFT
  Ia32/EnablePaging32.c | MSFT
  Ia32/EnableInterrupts.c | MSFT
  Ia32/EnableDisableInterrupts.c | MSFT
  Ia32/DivU64x32Remainder.c | MSFT
  Ia32/DivU64x32.c | MSFT
  Ia32/DisablePaging32.c | MSFT
  Ia32/DisableInterrupts.c | MSFT
  Ia32/CpuPause.c | MSFT
  Ia32/CpuIdEx.c | MSFT
  Ia32/CpuId.c | MSFT
  Ia32/CpuBreakpoint.c | MSFT
  Ia32/ARShiftU64.c | MSFT
  Ia32/EnableCache.c | MSFT
  Ia32/DisableCache.c | MSFT


  Ia32/GccInline.c | GCC
  Ia32/GccInlinePriv.c | GCC
  Ia32/Thunk16.nasm
  Ia32/EnableDisableInterrupts.nasm| GCC
  Ia32/EnablePaging64.nasm
  Ia32/DisablePaging32.nasm| GCC
  Ia32/EnablePaging32.nasm| GCC
  Ia32/Mwait.nasm| GCC
  Ia32/Monitor.nasm| GCC
  Ia32/CpuIdEx.nasm| GCC
  Ia32/CpuId.nasm| GCC
  Ia32/LongJump.nasm
  Ia32/SetJump.nasm
  Ia32/SwapBytes64.nasm| GCC
  Ia32/DivU64x64Remainder.nasm
  Ia32/DivU64x32Remainder.nasm| GCC
  Ia32/ModU64x32.nasm| GCC
  Ia32/DivU64x32.nasm| GCC
  Ia32/MultU64x64.nasm| GCC
  Ia32/MultU64x32.nasm| GCC
  Ia32/RRotU64.nasm| GCC
  Ia32/LRotU64.nasm| GCC
  Ia32/ARShiftU64.nasm| GCC
  Ia32/RShiftU64.nasm| GCC
  Ia32/LShiftU64.nasm| GCC
  Ia32/EnableCache.nasm| GCC
  Ia32/DisableCache.nasm| GCC
  Ia32/RdRand.nasm
  Ia32/XGetBv.nasm
  Ia32/XSetBv.nasm
  Ia32/VmgExit.nasm
  Ia32/VmgExitSvsm.nasm

  Ia32/DivS64x64Remainder.c
  Ia32/InternalSwitchStack.c | MSFT
  Ia32/InternalSwitchStack.nasm | GCC
  Ia32/Non-existing.c
  Unaligned.c
  X86WriteIdtr.c
  X86WriteGdtr.c
  X86Thunk.c
  X86ReadIdtr.c
  X86ReadGdtr.c
  X86Msr.c
  X86MemoryFence.c | MSFT
  X86GetInterruptState.c
  X86FxSave.c
  X86FxRestore.c
  X86EnablePaging64.c
  X86EnablePaging32.c
  X86DisablePaging64.c
  X86DisablePaging32.c
  X86RdRand.c
  X86PatchInstruction.c
  X86SpeculationBarrier.c
  IntelTdxNull.c

[Sources.X64]
  X64/Thunk16.nasm
  X64/CpuIdEx.nasm
  X64/CpuId.nasm
  X64/LongJump.nasm
  X64/SetJump.nasm
  X64/SwitchStack.nasm
  X64/EnableCache.nasm
  X64/DisableCache.nasm
  X64/WriteTr.nasm
  X64/Lfence.nasm
  X64/CpuBreakpoint.c | MSFT
  X64/WriteMsr64.c | MSFT
  X64/ReadMsr64.c | MSFT
  X64/CpuPause.nasm| MSFT
  X64/DisableInterrupts.nasm| MSFT
  X64/EnableInterrupts.nasm| MSFT
  X64/FlushCacheLine.nasm| MSFT
  X64/Invd.nasm| MSFT
  X64/Wbinvd.nasm| MSFT
  X64/Mwait.nasm| MSFT
  X64/Monitor.nasm| MSFT
  X64/ReadPmc.nasm| MSFT
  X64/ReadTsc.nasm| MSFT
  X64/WriteMm7.nasm| MSFT
  X64/WriteMm6.nasm| MSFT
  X64/WriteMm5.nasm| MSFT
  X64/WriteMm4.nasm| MSFT
  X64/WriteMm3.nasm| MSFT
  X64/WriteMm2.nasm| MSFT
  X64/WriteMm1.nasm| MSFT
  X64/WriteMm0.nasm| MSFT
  X64/ReadMm7.nasm| MSFT
  X64/ReadMm6.nasm| MSFT
  X64/ReadMm5.nasm| MSFT
  X64/ReadMm4.nasm| MSFT
  X64/ReadMm3.nasm| MSFT
  X64/ReadMm2.nasm| MSFT
  X64/ReadMm1.nasm| MSFT
  X64/ReadMm0.nasm| MSFT
  X64/FxRestore.nasm| MSFT
  X64/FxSave.nasm| MSFT
  X64/WriteLdtr.nasm| MSFT
  X64/ReadLdtr.nasm| MSFT
  X64/WriteIdtr.nasm| MSFT
  X64/ReadIdtr.nasm| MSFT
  X64/WriteGdtr.nasm| MSFT
  X64/ReadGdtr.nasm| MSFT
  X64/ReadTr.nasm| MSFT
  X64/ReadSs.nasm| MSFT
  X64/ReadGs.nasm| MSFT
  X64/ReadFs.nasm| MSFT
  X64/ReadEs.nasm| MSFT
  X64/ReadDs.nasm| MSFT
  X64/ReadCs.nasm| MSFT
  X64/WriteDr7.nasm| MSFT
  X64/WriteDr6.nasm| MSFT
  X64/WriteDr5.nasm| MSFT
  X64/WriteDr4.nasm| MSFT
  X64/WriteDr3.nasm| MSFT
  X64/WriteDr2.nasm| MSFT
  X64/WriteDr1.nasm| MSFT
  X64/WriteDr0.nasm| MSFT
  X64/ReadDr7.nasm| MSFT
  X64/ReadDr6.nasm| MSFT
  X64/ReadDr5.nasm| MSFT
  X64/ReadDr4.nasm| MSFT
  X64/ReadDr3.nasm| MSFT
  X64/ReadDr2.nasm| MSFT
  X64/ReadDr1.nasm| MSFT
  X64/ReadDr0.nasm| MSFT
  X64/WriteCr4.nasm| MSFT
  X64/WriteCr3.nasm| MSFT
  X64/WriteCr2.nasm| MSFT
  X64/WriteCr0.nasm| MSFT
  X64/ReadCr4.nasm| MSFT
  X64/ReadCr3.nasm| MSFT
  X64/ReadCr2.nasm| MSFT
  X64/ReadCr0.nasm| MSFT
  X64/ReadEflags.nasm| MSFT

  X64/TdCall.nasm
  X64/TdVmcall.nasm
  X64/TdProbe.c

  X64/Non-existing.c
  Math64.c
  Unaligned.c
  X86WriteIdtr.c
  X86WriteGdtr.c
  X86Thunk.c
  X86ReadIdtr.c
  X86ReadGdtr.c
  X86Msr.c
  X86MemoryFence.c | MSFT
  X86GetInterruptState.c
  X86FxSave.c
  X86FxRestore.c
  X86EnablePaging64.c
  X86EnablePaging32.c
  X86DisablePaging64.c
  X86DisablePaging32.c
  X86RdRand.c
  X86PatchInstruction.c
  X86SpeculationBarrier.c
  X64/GccInline.c | GCC
  X64/GccInlinePriv.c | GCC
  X64/EnableDisableInterrupts.nasm
  X64/DisablePaging64.nasm
  X64/Pvalidate.nasm
  X64/RdRand.nasm
  X64/RmpAdjust.nasm
  X64/XGetBv.nasm
  X64/XSetBv.nasm
  X64/VmgExit.nasm
  X64/VmgExitSvsm.nasm
  ChkStkGcc.c  | GCC

[Sources.EBC]
  Ebc/CpuBreakpoint.c
  Ebc/SetJumpLongJump.c
  Ebc/SwitchStack.c
  Ebc/SpeculationBarrier.c
  Unaligned.c
  Math64.c

[Sources.ARM]
  Arm/InternalSwitchStack.c
  Arm/Unaligned.c
  Math64.c                   | MSFT

  Arm/SwitchStack.asm        | MSFT
  Arm/SetJumpLongJump.asm    | MSFT
  Arm/DisableInterrupts.asm  | MSFT
  Arm/EnableInterrupts.asm   | MSFT
  Arm/GetInterruptsState.asm | MSFT
  Arm/CpuPause.asm           | MSFT
  Arm/CpuBreakpoint.asm      | MSFT
  Arm/MemoryFence.asm        | MSFT
  Arm/SpeculationBarrier.asm | MSFT

  Arm/Math64.S                  | GCC
  Arm/SwitchStack.S             | GCC
  Arm/EnableInterrupts.S        | GCC
  Arm/DisableInterrupts.S       | GCC
  Arm/GetInterruptsState.S      | GCC
  Arm/SetJumpLongJump.S         | GCC
  Arm/CpuBreakpoint.S           | GCC
  Arm/MemoryFence.S             | GCC
  Arm/SpeculationBarrier.S      | GCC

[Sources.AARCH64]
  Arm/InternalSwitchStack.c
  Arm/Unaligned.c
  Math64.c

  AArch64/MemoryFence.S             | GCC
  AArch64/SwitchStack.S             | GCC
  AArch64/EnableInterrupts.S        | GCC
  AArch64/DisableInterrupts.S       | GCC
  AArch64/GetInterruptsState.S      | GCC
  AArch64/SetJumpLongJump.S         | GCC
  AArch64/CpuBreakpoint.S           | GCC
  AArch64/SpeculationBarrier.S      | GCC
  AArch64/ArmReadIdAA64Isar0Reg.S   | GCC

  AArch64/MemoryFence.asm           | MSFT
  AArch64/SwitchStack.asm           | MSFT
  AArch64/EnableInterrupts.asm      | MSFT
  AArch64/DisableInterrupts.asm     | MSFT
  AArch64/GetInterruptsState.asm    | MSFT
  AArch64/SetJumpLongJump.asm       | MSFT
  AArch64/CpuBreakpoint.asm         | MSFT
  AArch64/SpeculationBarrier.asm    | MSFT
  AArch64/ArmReadIdAA64Isar0Reg.asm | MSFT

[Sources.RISCV64]
  Math64.c
  Unaligned.c
  RiscV64/InternalSwitchStack.c
  RiscV64/CpuBreakpoint.c
  RiscV64/GetInterruptState.c
  RiscV64/DisableInterrupts.c
  RiscV64/EnableInterrfupts.c
  RiscV64/CpuPause.c
  RiscV64/MemoryFence.S             | GCC
  RiscV64/RiscVSetJumpLongJump.S    | GCC
  RiscV64/SwitchStack.S             | GCC
  RiscV64/RiscVCpuBreakpoint.S      | GCC
  RiscV64/RiscVCpuPause.S           | GCC
  RiscV64/RiscVInterrupt.S          | GCC
  RiscV64/RiscVCacheMgmt.S          | GCC
  RiscV64/CpuScratch.S              | GCC
  RiscV64/ReadTimer.S               | GCC
  RiscV64/RiscVMmu.S                | GCC
  RiscV64/SpeculationBarrier.S      | GCC

[Sources.LOONGARCH64]
  Math64.c
  Unaligned.c
  LoongArch64/Csr.c
  LoongArch64/InternalSwitchStack.c
  LoongArch64/AsmCsr.S              | GCC
  LoongArch64/IoCsr.S               | GCC
  LoongArch64/GetInterruptState.S   | GCC
  LoongArch64/EnableInterrupts.S    | GCC
  LoongArch64/DisableInterrupts.S   | GCC
  LoongArch64/Barrier.S             | GCC
  LoongArch64/MemoryFence.S         | GCC
  LoongArch64/CpuBreakpoint.S       | GCC
  LoongArch64/CpuPause.S            | GCC
  LoongArch64/SetJumpLongJump.S     | GCC
  LoongArch64/SwitchStack.S         | GCC
  LoongArch64/ExceptionBase.S       | GCC
  LoongArch64/Cpucfg.S              | GCC
  LoongArch64/ReadStableCounter.S   | GCC

[Packages]
  MdePkg/MdePkg.dec

[LibraryClasses]
  PcdLib
  DebugLib
  BaseMemoryLib

[LibraryClasses.X64, LibraryClasses.IA32]
  RegisterFilterLib

[Pcd]
  gEfiMdePkgTokenSpaceGuid.PcdMaximumLinkedListLength      ## SOMETIMES_CONSUMES
  gEfiMdePkgTokenSpaceGuid.PcdMaximumAsciiStringLength     ## SOMETIMES_CONSUMES
  gEfiMdePkgTokenSpaceGuid.PcdMaximumUnicodeStringLength   ## SOMETIMES_CONSUMES
  gEfiMdePkgTokenSpaceGuid.PcdControlFlowEnforcementPropertyMask   ## SOMETIMES_CONSUMES
  gEfiMdePkgTokenSpaceGuid.PcdSpeculationBarrierType       ## SOMETIMES_CONSUMES

[FeaturePcd]
  gEfiMdePkgTokenSpaceGuid.PcdVerifyNodeInList  ## CONSUMES
"""


SIMPLE_XML_FILE_CONTENTS = """<FpdtParserData>
    <UEFIVersion Value="Hyper-V UEFI Release v4.1" />
    <Model Value="Virtual Machine" />
    <DateCollected Value="5/1/2025" />
    <FpdtParserVersion Value="3.00" />
    <AcpiTableHeader Signature="FPDT" Length="0x34" Revision="0x1" Checksum="0x50" OEMID="b'VRTUAL'" OEMTableID="b'MICROSFT'" OEMRevision="0x1" CreatorID="b'MSFT'" CreatorRevision="0x1" />
    <FwBasicBootPerformanceRecord PerformanceRecordType="0x0" RecordLength="0x10" Revision="0x1" Reserved="0x0" FBPTPointer="0x3FFC8000" />
    <Fbpt Signature="FBPT" Length="0x38">
        <FirmwareBasicBootPerformanceEvent PerformanceRecordType="0x2" RecordLength="0x30" Revision="0x2">
            <ResetEnd RawValue="0x0" ValueInMilliseconds="0.000000" />
            <OSLoaderLoadImageStart RawValue="0x1858C060" ValueInMilliseconds="408.469600" />
            <OSLoaderStartImageStart RawValue="0x1ABBF908" ValueInMilliseconds="448.526600" />
            <ExitBootServicesEntry RawValue="0x577F5100" ValueInMilliseconds="1467.961600" />
            <ExitBootServicesExit RawValue="0x578E4AFC" ValueInMilliseconds="1468.943100" />
        </FirmwareBasicBootPerformanceEvent>
    </Fbpt>
</FpdtParserData>"""


class TestAddGuid(unittest.TestCase):
    """Test adding GUIDs to the GUID dictionary."""

    def setUp(self) -> None:
        """Set up the test environment."""
        self.guid_dict = {}

    def test_add_new_guid(self) -> None:
        """Test adding a new GUID to the dictionary."""
        guid = "12345678-1234-1234-1234-123456789ABC"
        name = "TestGUID"
        add_guid(guid, name, self.guid_dict)
        self.assertIn(guid.upper(), self.guid_dict)
        self.assertEqual(self.guid_dict[guid.upper()], name)

    def test_add_duplicate_guid(self) -> None:
        """Test adding a duplicate GUID logs a warning."""
        guid = "12345678-1234-1234-1234-123456789ABC"
        name = "TestGUID"
        self.guid_dict[guid.upper()] = name
        with self.assertLogs(level="WARNING") as log:
            add_guid(guid, "DuplicateGUID", self.guid_dict)
            self.assertIn(f"Duplicate GUID found: {guid}", log.output[0])

    def test_add_guid_case_insensitivity(self) -> None:
        """Test that GUIDs are treated case-insensitively."""
        guid = "12345678-1234-1234-1234-123456789ABC"
        name = "TestGUID"
        add_guid(guid.lower(), name, self.guid_dict)
        self.assertIn(guid.upper(), self.guid_dict)
        self.assertEqual(self.guid_dict[guid.upper()], name)


class TestParseGuidsInDirectory(unittest.TestCase):
    """Test parsing GUIDs from files in a directory."""

    def setUp(self) -> None:
        """Set up the test environment."""
        self.guid_dict = {}
        self.test_dir = "test_directory"

    @patch("os.walk")
    @patch(
        "builtins.open",
        new_callable=mock_open,
        read_data="BASE_NAME = TestBaseLib\nFILE_GUID = 12345678-1234-1234-1234-123456789ABC\n",
    )
    def test_parse_simple_inf_file(self, _: callable, mock_walk: callable) -> None:
        """Test parsing GUIDs from an INF file."""
        mock_walk.return_value = [(self.test_dir, [], ["test.inf"])]
        parse_guids_in_directory(self.test_dir, self.guid_dict)
        self.assertIn("12345678-1234-1234-1234-123456789ABC", self.guid_dict)
        self.assertEqual(self.guid_dict["12345678-1234-1234-1234-123456789ABC"], "TestBaseLib")

    @patch("os.walk")
    @patch("builtins.open", new_callable=mock_open, read_data=DEBUG_LIB_NULL_INF_CONTENTS)
    def test_parse_simple_inf_file_2(self, _: callable, mock_walk: callable) -> None:
        """Test parsing GUIDs from an INF file."""
        mock_walk.return_value = [(self.test_dir, [], ["test.inf"])]
        parse_guids_in_directory(self.test_dir, self.guid_dict)
        self.assertIn(DEBUG_LIB_NULL_FILE_GUID, self.guid_dict)
        self.assertEqual(self.guid_dict[DEBUG_LIB_NULL_FILE_GUID], DEBUG_LIB_NULL_BASE_NAME)

    @patch("os.walk")
    @patch("builtins.open", new_callable=mock_open, read_data=BASE_LIB_INF_CONTENTS)
    def test_parse_complex_inf_file(self, _: callable, mock_walk: callable) -> None:
        """Test parsing GUIDs from an INF file."""
        mock_walk.return_value = [(self.test_dir, [], ["test.inf"])]
        parse_guids_in_directory(self.test_dir, self.guid_dict)
        self.assertIn(BASE_LIB_FILE_GUID, self.guid_dict)
        self.assertEqual(self.guid_dict[BASE_LIB_FILE_GUID], BASE_LIB_BASE_NAME)

    @patch("os.walk")
    @patch("builtins.open", new_callable=mock_open, read_data=FMP_DEVICE_PKG_DEC_CONTENTS)
    def test_parse_dec_file(self, _: callable, mock_walk: callable) -> None:
        """Test parsing GUIDs from a DEC file."""
        mock_walk.return_value = [(self.test_dir, [], ["test.dec"])]
        parse_guids_in_directory(self.test_dir, self.guid_dict)

        for guid in DEC_GUIDS:
            self.assertIn(guid, self.guid_dict)
            self.assertEqual(self.guid_dict[guid], DEC_GUIDS[guid])

    @patch("os.walk")
    @patch("builtins.open", new_callable=mock_open, read_data=QEMU_FDF_CONTENT)
    def test_parse_fdf_file_guid(self, _: callable, mock_walk: callable) -> None:
        """Test parsing GUIDs from an FDF file."""
        mock_walk.return_value = [(self.test_dir, [], ["test.fdf"])]
        parse_guids_in_directory(self.test_dir, self.guid_dict)
        for guid in [FDF_TEST_MODULE.guid, FDF_TEST_MODULE2.guid]:
            self.assertIn(guid, self.guid_dict)
            self.assertEqual(
                self.guid_dict[guid],
                (FDF_TEST_MODULE.name if guid == FDF_TEST_MODULE.guid else FDF_TEST_MODULE2.name),
            )

    @patch("os.walk")
    def test_no_files_found(self, mock_walk: callable) -> None:
        """Test when no files are found in the directory."""
        mock_walk.return_value = [(self.test_dir, [], [])]
        parse_guids_in_directory(self.test_dir, self.guid_dict)
        self.assertEqual(len(self.guid_dict), 0)

    @patch("os.walk")
    @patch("builtins.open", new_callable=mock_open, read_data="")
    def test_empty_file(self, _: callable, mock_walk: callable) -> None:
        """Test parsing an empty file."""
        mock_walk.return_value = [(self.test_dir, [], ["empty.dec"])]
        parse_guids_in_directory(self.test_dir, self.guid_dict)
        self.assertEqual(len(self.guid_dict), 0)

    def test__format_guid(self) -> None:
        """Test formatting a GUID."""
        guid_groups = ("skip", "12345678", "1234", "1234", "12", "34", "123456789ABC")
        formatted_guid = _format_guid(guid_groups)
        expected_guid = "12345678-1234-1234-1234-123456789ABC"
        self.assertEqual(formatted_guid, expected_guid)


class TestParseSourceTree(unittest.TestCase):
    """Test source tree parsing."""

    def setUp(self) -> None:
        """Set up a temporary directory for testing."""
        self.guid_dict = {}
        self.test_dir = tempfile.mkdtemp()

        with open(os.path.join(self.test_dir, "test.inf"), "w") as inf_file:
            inf_file.write(BASE_LIB_INF_CONTENTS)

        with open(os.path.join(self.test_dir, "test.dec"), "w") as dec_file:
            dec_file.write(FMP_DEVICE_PKG_DEC_CONTENTS)

    def tearDown(self) -> None:
        """Remove the temporary test directory."""
        for root, dirs, files in os.walk(self.test_dir, topdown=False):
            for file in files:
                os.remove(os.path.join(root, file))
            for dir in dirs:
                os.rmdir(os.path.join(root, dir))
        os.rmdir(self.test_dir)

    @patch("os.walk")
    def test_parse_source_tree(self, mock_walk: callable) -> None:
        """Test parsing GUIDs from a source tree."""
        mock_walk.return_value = [(self.test_dir, [], ["test.inf", "test.dec"])]
        parse_guids_in_directory(self.test_dir, self.guid_dict)
        self.assertIn(BASE_LIB_FILE_GUID, self.guid_dict)
        self.assertEqual(self.guid_dict[BASE_LIB_FILE_GUID], "BaseLib")


class TestParseFdptRecords(unittest.TestCase):
    """Test FPDT record parsing."""

    def setUp(self) -> None:
        """Set up a temporary directory for testing."""
        self.guid_dict = {}
        self.test_dir = tempfile.mkdtemp()

    def tearDown(self) -> None:
        """Remove the temporary test directory."""
        for root, dirs, files in os.walk(self.test_dir, topdown=False):
            for file in files:
                os.remove(os.path.join(root, file))
            for dir in dirs:
                os.rmdir(os.path.join(root, dir))
        os.rmdir(self.test_dir)

    @patch("os.walk")
    @patch("builtins.open", new_callable=mock_open)
    def test_expected_guids_present(self, mock_open: callable, mock_walk: callable) -> None:
        """Test parsing GUIDs from FDPT records."""
        mock_walk.return_value = [(self.test_dir, [], ["test.inf", "test.dec"])]

        def mock_file_open(file: str, mode: str = "r") -> io.StringIO:
            if file.endswith(".inf"):
                return io.StringIO(BASE_LIB_INF_CONTENTS)
            elif file.endswith(".dec"):
                return io.StringIO(FMP_DEVICE_PKG_DEC_CONTENTS)
            else:
                raise FileNotFoundError

        mock_open.side_effect = mock_file_open

        parse_guids_in_directory(self.test_dir, self.guid_dict)
        self.assertIn(BASE_LIB_FILE_GUID, self.guid_dict)
        self.assertEqual(self.guid_dict[BASE_LIB_FILE_GUID], BASE_LIB_BASE_NAME)

        for guid in DEC_GUIDS:
            self.assertIn(guid, self.guid_dict)
            self.assertEqual(self.guid_dict[guid], DEC_GUIDS[guid])

    def test_parse_fbpt_records_verify_basic_parsing(self) -> None:
        """Test parsing FPBT records."""
        # Create a temporary XML file with FPDT records
        xml_file_path = os.path.join(self.test_dir, "basic_records.xml")
        with open(xml_file_path, "w") as xml_file:
            xml_file.write(SIMPLE_XML_FILE_CONTENTS)

        # (timing list, messages, unrecognized records)
        # Expected: Basic timings, no messages, no unrecognized records
        expected_data_tuple = (
            [
                (1, "Event", "N/A", "N/A", "ResetEnd", 0.0, 1e-06),
                (2, "Event", "N/A", "N/A", "OSLoaderLoadImageStart", 408.4696, 1e-06),
                (3, "Event", "N/A", "N/A", "OSLoaderStartImageStart", 448.5266, 1e-06),
                (
                    4,
                    "Process",
                    "N/A",
                    "N/A",
                    "ExitBootServices",
                    1467.9616,
                    0.981499999999869,
                ),
            ],
            [],
            0,
        )

        # Call without a text log
        record_data = parse_fpdt_records(xml_file_path, None, {})
        self.assertEqual(record_data, expected_data_tuple)

        [
            (1, "Event", "N/A", "N/A", "ResetEnd", 0.0, 1e-06),
            (2, "Event", "N/A", "N/A", "OSLoaderLoadImageStart", 408.4696, 1e-06),
            (3, "Event", "N/A", "N/A", "OSLoaderStartImageStart", 448.5266, 1e-06),
            (
                4,
                "Process",
                "N/A",
                "N/A",
                "ExitBootServices",
                1467.9616,
                0.981499999999869,
            ),
        ]
        with open(os.path.join(self.test_dir, "log.txt"), "w") as text_log:
            # Call with a text log
            parse_fpdt_records(xml_file_path, text_log, {})

        # Verify the text log has the expected event data
        with open(os.path.join(self.test_dir, "log.txt"), "r") as text_log:
            log_contents = text_log.read()
            self.assertIn("(1, 'Event', 'N/A', 'N/A', 'ResetEnd', 0.0, 1e-06)", log_contents)
            self.assertIn(
                "(2, 'Event', 'N/A', 'N/A', 'OSLoaderLoadImageStart', 408.4696, 1e-06)",
                log_contents,
            )
            self.assertIn(
                "(3, 'Event', 'N/A', 'N/A', 'OSLoaderStartImageStart', 448.5266, 1e-06)",
                log_contents,
            )
            self.assertIn(
                "(4, 'Process', 'N/A', 'N/A', 'ExitBootServices', 1467.9616, 0.981499999999869)",
                log_contents,
            )

    def test_parse_fpdt_records_verify_more_complex_parsing(self) -> None:
        """Test parsing FPDT records."""
        # Create a temporary XML file with FPDT records
        xml_file_path = os.path.join(
            os.path.dirname(os.path.abspath(__file__)),
            "testdata",
            "fpdt_complex_data.xml",
        )

        # (timing list, messages, unrecognized records)
        # Expected: Basic timings, messages, no unrecognized records

        expected_data_tuple = (
            [
                (1, "Event", "N/A", "N/A", "ResetEnd", 1127.243597, 1e-06),
                (
                    5,
                    "Event",
                    "52C05B14-0B98-496C-BC3B-04B50211D680",
                    "UNKNOWN-fc49",
                    "Event measurement from module UNKNOWN-fc49 with label SEC",
                    1219.308632,
                    1e-06,
                ),
                (
                    158,
                    "Crossmodule",
                    "52C05B14-0B98-496C-BC3B-04B50211D680, D6A2CB7F-6A18-4E2F-B43B-9920A733700A",
                    "UNKNOWN-fc49, UNKNOWN-6c05",
                    "Crossmodule measurement from UNKNOWN-fc49 to UNKNOWN-6c05 with label PEI",
                    1219.31242,
                    99747.40240199999,
                ),
                (
                    74,
                    "Inmodule",
                    "52C05B14-0B98-496C-BC3B-04B50211D680",
                    "UNKNOWN-fc49",
                    "Inmodule measurement from module UNKNOWN-fc49 with label PreMem",
                    1219.314683,
                    98400.48379,
                ),
                (
                    152,
                    "Function",
                    "52C05B14-0B98-496C-BC3B-04B50211D680",
                    "UNKNOWN-fc49",
                    "Function measurement from module UNKNOWN-fc49 with label PeiDispatcher",
                    1223.416774,
                    99732.455025,
                ),
                (
                    6,
                    "LoadImage",
                    "9B3ADA4F-AE56-4C24-8DEA-F03B7558AE50",
                    "UNKNOWN-61e8",
                    "LoadImage measurement for module UNKNOWN-61e8",
                    1223.44667,
                    0.16137299999991228,
                ),
                (
                    7,
                    "Entrypoint",
                    "9B3ADA4F-AE56-4C24-8DEA-F03B7558AE50",
                    "UNKNOWN-61e8",
                    "Entrypoint measurement for module UNKNOWN-61e8",
                    1223.610233,
                    7.704498999999942,
                ),
                (
                    8,
                    "LoadImage",
                    "A3610442-E69F-4DF3-82CA-2360C4031A23",
                    "UNKNOWN-b402",
                    "LoadImage measurement for module UNKNOWN-b402",
                    1231.319755,
                    0.03133900000011636,
                ),
                (
                    9,
                    "Entrypoint",
                    "A3610442-E69F-4DF3-82CA-2360C4031A23",
                    "UNKNOWN-b402",
                    "Entrypoint measurement for module UNKNOWN-b402",
                    1231.353337,
                    0.014543000000003303,
                ),
                (
                    10,
                    "LoadImage",
                    "254B3E77-863A-43A0-9287-8979B2D0513F",
                    "UNKNOWN-b767",
                    "LoadImage measurement for module UNKNOWN-b767",
                    1231.373121,
                    0.024081000000023778,
                ),
                (
                    11,
                    "Entrypoint",
                    "254B3E77-863A-43A0-9287-8979B2D0513F",
                    "UNKNOWN-b767",
                    "Entrypoint measurement for module UNKNOWN-b767",
                    1231.406015,
                    0.06172799999990275,
                ),
                (
                    12,
                    "LoadImage",
                    "57A2921A-7BC2-43C5-AA5D-064EDCBB992F",
                    "UNKNOWN-776a",
                    "LoadImage measurement for module UNKNOWN-776a",
                    1231.47289,
                    0.024286999999958425,
                ),
                (
                    13,
                    "Entrypoint",
                    "57A2921A-7BC2-43C5-AA5D-064EDCBB992F",
                    "UNKNOWN-776a",
                    "Entrypoint measurement for module UNKNOWN-776a",
                    1231.506005,
                    2.5760190000000875,
                ),
                (
                    14,
                    "LoadImage",
                    "0D1CE46B-72D9-4BA7-95DA-23511865E661",
                    "UNKNOWN-d8c2",
                    "LoadImage measurement for module UNKNOWN-d8c2",
                    1234.08689,
                    0.19721899999990455,
                ),
                (
                    15,
                    "Entrypoint",
                    "0D1CE46B-72D9-4BA7-95DA-23511865E661",
                    "UNKNOWN-d8c2",
                    "Entrypoint measurement for module UNKNOWN-d8c2",
                    1234.286383,
                    5.648600000000215,
                ),
                (
                    16,
                    "LoadImage",
                    "AAC33064-9ED0-4B89-A5AD-3EA767960B22",
                    "UNKNOWN-4d68",
                    "LoadImage measurement for module UNKNOWN-4d68",
                    1239.940208,
                    0.18408900000008543,
                ),
                (
                    17,
                    "Entrypoint",
                    "AAC33064-9ED0-4B89-A5AD-3EA767960B22",
                    "UNKNOWN-4d68",
                    "Entrypoint measurement for module UNKNOWN-4d68",
                    1240.126536,
                    5.797463000000107,
                ),
                (
                    18,
                    "LoadImage",
                    "34C8C28F-B61C-45A2-8F2E-89E46BECC63B",
                    "UNKNOWN-031f",
                    "LoadImage measurement for module UNKNOWN-031f",
                    1245.92913,
                    0.04376000000002023,
                ),
                (
                    19,
                    "Entrypoint",
                    "34C8C28F-B61C-45A2-8F2E-89E46BECC63B",
                    "UNKNOWN-031f",
                    "Entrypoint measurement for module UNKNOWN-031f",
                    1245.975172,
                    5.6467190000000755,
                ),
                (
                    20,
                    "LoadImage",
                    "AFA9EB37-AA99-4A60-A47F-50DFF428D93B",
                    "UNKNOWN-48b6",
                    "LoadImage measurement for module UNKNOWN-48b6",
                    1251.626653,
                    0.1967130000000452,
                ),
                (
                    21,
                    "Entrypoint",
                    "AFA9EB37-AA99-4A60-A47F-50DFF428D93B",
                    "UNKNOWN-48b6",
                    "Entrypoint measurement for module UNKNOWN-48b6",
                    1251.825595,
                    5.641969000000017,
                ),
                (
                    22,
                    "LoadImage",
                    "6141E486-7543-4F1A-A579-FF532ED78E75",
                    "UNKNOWN-f8e4",
                    "LoadImage measurement for module UNKNOWN-f8e4",
                    1257.472221,
                    0.19636300000001938,
                ),
                (
                    23,
                    "Entrypoint",
                    "6141E486-7543-4F1A-A579-FF532ED78E75",
                    "UNKNOWN-f8e4",
                    "Entrypoint measurement for module UNKNOWN-f8e4",
                    1257.670819,
                    5.643481000000065,
                ),
                (
                    24,
                    "LoadImage",
                    "3FECFD95-7CB2-4A6E-8FAC-DEFD9947E35E",
                    "UNKNOWN-99c6",
                    "LoadImage measurement for module UNKNOWN-99c6",
                    1263.319417,
                    0.18373399999995854,
                ),
                (
                    27,
                    "Entrypoint",
                    "3FECFD95-7CB2-4A6E-8FAC-DEFD9947E35E",
                    "UNKNOWN-99c6",
                    "Entrypoint measurement for module UNKNOWN-99c6",
                    1263.505387,
                    148.11890100000005,
                ),
                (
                    25,
                    "Inmodule",
                    "3FECFD95-7CB2-4A6E-8FAC-DEFD9947E35E",
                    "UNKNOWN-99c6",
                    "Inmodule measurement from module UNKNOWN-99c6 with label Verify FV FFE00000:1000",
                    1266.358181,
                    42.006421000000046,
                ),
                (
                    26,
                    "Inmodule",
                    "3FECFD95-7CB2-4A6E-8FAC-DEFD9947E35E",
                    "UNKNOWN-99c6",
                    "Inmodule measurement from module UNKNOWN-99c6 with label Verify FV FFE83000:1150",
                    1312.193997,
                    99.34690499999988,
                ),
                (
                    28,
                    "LoadImage",
                    "163CFEB7-26DF-4764-ABAE-FFFBFB0F521B",
                    "UNKNOWN-8f58",
                    "LoadImage measurement for module UNKNOWN-8f58",
                    1411.64015,
                    0.032744000000093365,
                ),
                (
                    30,
                    "Entrypoint",
                    "163CFEB7-26DF-4764-ABAE-FFFBFB0F521B",
                    "UNKNOWN-8f58",
                    "Entrypoint measurement for module UNKNOWN-8f58",
                    1411.675301,
                    2.4256339999999454,
                ),
                (
                    29,
                    "Function",
                    "163CFEB7-26DF-4764-ABAE-FFFBFB0F521B",
                    "UNKNOWN-8f58",
                    "Function measurement from module UNKNOWN-8f58 with label ProduceBootPathReasonHo",
                    1411.739249,
                    2.2991750000001048,
                ),
                (
                    31,
                    "LoadImage",
                    "9EC96AC4-CA4C-4C91-9B1E-0E21093FD8EC",
                    "UNKNOWN-87ce",
                    "LoadImage measurement for module UNKNOWN-87ce",
                    1414.106387,
                    0.029680999999982305,
                ),
                (
                    32,
                    "Entrypoint",
                    "9EC96AC4-CA4C-4C91-9B1E-0E21093FD8EC",
                    "UNKNOWN-87ce",
                    "Entrypoint measurement for module UNKNOWN-87ce",
                    1414.139612,
                    5.644287000000077,
                ),
                (
                    33,
                    "LoadImage",
                    "82BAF12F-0B63-46B9-B4CC-42424C0955D5",
                    "UNKNOWN-1d7f",
                    "LoadImage measurement for module UNKNOWN-1d7f",
                    1419.789195,
                    0.1845419999999649,
                ),
                (
                    34,
                    "Entrypoint",
                    "82BAF12F-0B63-46B9-B4CC-42424C0955D5",
                    "UNKNOWN-1d7f",
                    "Entrypoint measurement for module UNKNOWN-1d7f",
                    1419.97607,
                    5.647560000000112,
                ),
                (
                    35,
                    "LoadImage",
                    "9C20E9A3-582C-45A5-88F5-76A86E6354C0",
                    "UNKNOWN-0f23",
                    "LoadImage measurement for module UNKNOWN-0f23",
                    1425.629896,
                    0.18456000000014683,
                ),
                (
                    43,
                    "Entrypoint",
                    "9C20E9A3-582C-45A5-88F5-76A86E6354C0",
                    "UNKNOWN-0f23",
                    "Entrypoint measurement for module UNKNOWN-0f23",
                    1425.816726,
                    9.164815999999973,
                ),
                (
                    36,
                    "Inmodule",
                    "9C20E9A3-582C-45A5-88F5-76A86E6354C0",
                    "UNKNOWN-0f23",
                    "Inmodule measurement from module UNKNOWN-0f23 with label DetermineBootPathDueToH",
                    1428.648717,
                    0.032011999999895124,
                ),
                (
                    37,
                    "Inmodule",
                    "9C20E9A3-582C-45A5-88F5-76A86E6354C0",
                    "UNKNOWN-0f23",
                    "Inmodule measurement from module UNKNOWN-0f23 with label DetermineBootPathDueToB",
                    1428.68315,
                    0.00293599999986327,
                ),
                (
                    38,
                    "Inmodule",
                    "9C20E9A3-582C-45A5-88F5-76A86E6354C0",
                    "UNKNOWN-0f23",
                    "Inmodule measurement from module UNKNOWN-0f23 with label DetermineBootPathDueToV",
                    1428.688394,
                    0.2761049999999159,
                ),
                (
                    39,
                    "Inmodule",
                    "9C20E9A3-582C-45A5-88F5-76A86E6354C0",
                    "UNKNOWN-0f23",
                    "Inmodule measurement from module UNKNOWN-0f23 with label DetermineBootPathDueToP",
                    1428.966816,
                    0.5367569999998523,
                ),
                (
                    40,
                    "Inmodule",
                    "9C20E9A3-582C-45A5-88F5-76A86E6354C0",
                    "UNKNOWN-0f23",
                    "Inmodule measurement from module UNKNOWN-0f23 with label GetBootPathDueToFamilyS",
                    1429.505937,
                    0.014633000000003449,
                ),
                (
                    41,
                    "Inmodule",
                    "9C20E9A3-582C-45A5-88F5-76A86E6354C0",
                    "UNKNOWN-0f23",
                    "Inmodule measurement from module UNKNOWN-0f23 with label GetPersistentBootPathDu",
                    1429.522828,
                    0.027559000000110245,
                ),
                (
                    42,
                    "Inmodule",
                    "9C20E9A3-582C-45A5-88F5-76A86E6354C0",
                    "UNKNOWN-0f23",
                    "Inmodule measurement from module UNKNOWN-0f23 with label PublishFamilyBootPathRe",
                    1429.552682,
                    0.002287999999907697,
                ),
                (
                    44,
                    "LoadImage",
                    "AF83E96A-EB26-4DCF-A097-84D9E5692FFE",
                    "UNKNOWN-f490",
                    "LoadImage measurement for module UNKNOWN-f490",
                    1434.987285,
                    0.1845210000001316,
                ),
                (
                    49,
                    "Entrypoint",
                    "AF83E96A-EB26-4DCF-A097-84D9E5692FFE",
                    "UNKNOWN-f490",
                    "Entrypoint measurement for module UNKNOWN-f490",
                    1435.174051,
                    5.6485170000000835,
                ),
                (
                    45,
                    "Inmodule",
                    "AF83E96A-EB26-4DCF-A097-84D9E5692FFE",
                    "UNKNOWN-f490",
                    "Inmodule measurement from module UNKNOWN-f490 with label ProduceProductDataHobs",
                    1438.013487,
                    0.5233640000001287,
                ),
                (
                    46,
                    "Inmodule",
                    "AF83E96A-EB26-4DCF-A097-84D9E5692FFE",
                    "UNKNOWN-f490",
                    "Inmodule measurement from module UNKNOWN-f490 with label ProduceFamilySpecificDa",
                    1438.539388,
                    0.010742000000163898,
                ),
                (
                    47,
                    "Inmodule",
                    "AF83E96A-EB26-4DCF-A097-84D9E5692FFE",
                    "UNKNOWN-f490",
                    "Inmodule measurement from module UNKNOWN-f490 with label GetProductDataValidity",
                    1438.552503,
                    0.011449000000084197,
                ),
                (
                    48,
                    "Inmodule",
                    "AF83E96A-EB26-4DCF-A097-84D9E5692FFE",
                    "UNKNOWN-f490",
                    "Inmodule measurement from module UNKNOWN-f490 with label PerformFamilySpecificDa",
                    1438.56625,
                    0.010598999999956504,
                ),
                (
                    50,
                    "LoadImage",
                    "2413D304-AA41-4079-A81E-31B8D7C3FD6B",
                    "UNKNOWN-9a37",
                    "LoadImage measurement for module UNKNOWN-9a37",
                    1440.827737,
                    0.18442800000002535,
                ),
                (
                    51,
                    "Entrypoint",
                    "2413D304-AA41-4079-A81E-31B8D7C3FD6B",
                    "UNKNOWN-9a37",
                    "Entrypoint measurement for module UNKNOWN-9a37",
                    1441.014436,
                    10.423682000000099,
                ),
                (
                    52,
                    "LoadImage",
                    "EEEE611D-F78F-4FB9-B868-55907F169280",
                    "UNKNOWN-f1fa",
                    "LoadImage measurement for module UNKNOWN-f1fa",
                    1451.44402,
                    0.1968890000000556,
                ),
                (
                    54,
                    "Entrypoint",
                    "EEEE611D-F78F-4FB9-B868-55907F169280",
                    "UNKNOWN-f1fa",
                    "Entrypoint measurement for module UNKNOWN-f1fa",
                    1451.64316,
                    51.317476999999826,
                ),
                (
                    53,
                    "Inmodule",
                    "EEEE611D-F78F-4FB9-B868-55907F169280",
                    "UNKNOWN-f1fa",
                    "Inmodule measurement from module UNKNOWN-f1fa with label RunPlatformInitScripts",
                    1495.002405,
                    5.129877000000079,
                ),
                (
                    55,
                    "LoadImage",
                    "49785B11-2712-40DD-9562-FB861AAAEF56",
                    "UNKNOWN-88df",
                    "LoadImage measurement for module UNKNOWN-88df",
                    1502.969088,
                    0.18445299999984854,
                ),
                (
                    56,
                    "Entrypoint",
                    "49785B11-2712-40DD-9562-FB861AAAEF56",
                    "UNKNOWN-88df",
                    "Entrypoint measurement for module UNKNOWN-88df",
                    1503.155702,
                    5.645191999999952,
                ),
                (
                    57,
                    "LoadImage",
                    "2D586AF2-47C4-47BB-A860-89495D5BBFEB",
                    "UNKNOWN-55ba",
                    "LoadImage measurement for module UNKNOWN-55ba",
                    1508.806479,
                    0.18423999999981788,
                ),
                (
                    58,
                    "Entrypoint",
                    "2D586AF2-47C4-47BB-A860-89495D5BBFEB",
                    "UNKNOWN-55ba",
                    "Entrypoint measurement for module UNKNOWN-55ba",
                    1508.992966,
                    5.648965999999973,
                ),
                (
                    59,
                    "LoadImage",
                    "BAEB5BEE-5B33-480A-8AB7-B29C85E7CEAB",
                    "UNKNOWN-896b",
                    "LoadImage measurement for module UNKNOWN-896b",
                    1514.663583,
                    2.5186690000000453,
                ),
                (
                    60,
                    "Entrypoint",
                    "BAEB5BEE-5B33-480A-8AB7-B29C85E7CEAB",
                    "UNKNOWN-896b",
                    "Entrypoint measurement for module UNKNOWN-896b",
                    1517.18445,
                    5.641607000000022,
                ),
                (
                    61,
                    "LoadImage",
                    "88C17E54-EBFE-4531-A992-581029F58126",
                    "UNKNOWN-88e2",
                    "LoadImage measurement for module UNKNOWN-88e2",
                    1522.83106,
                    1.559635999999955,
                ),
                (
                    62,
                    "Entrypoint",
                    "88C17E54-EBFE-4531-A992-581029F58126",
                    "UNKNOWN-88e2",
                    "Entrypoint measurement for module UNKNOWN-88e2",
                    1524.392952,
                    5.645436000000018,
                ),
                (
                    63,
                    "LoadImage",
                    "55BDA60B-1D0F-42D5-9F09-2D3D3067B899",
                    "UNKNOWN-838a",
                    "LoadImage measurement for module UNKNOWN-838a",
                    1530.043362,
                    1.7536620000000767,
                ),
                (
                    64,
                    "Entrypoint",
                    "55BDA60B-1D0F-42D5-9F09-2D3D3067B899",
                    "UNKNOWN-838a",
                    "Entrypoint measurement for module UNKNOWN-838a",
                    1531.799261,
                    5.641565000000128,
                ),
                (
                    65,
                    "LoadImage",
                    "2413D304-AA41-4079-A81E-31B8D7C3FD6B",
                    "UNKNOWN-9a37",
                    "LoadImage measurement for module UNKNOWN-9a37",
                    1537.445478,
                    6.035800999999992,
                ),
                (
                    66,
                    "Entrypoint",
                    "2413D304-AA41-4079-A81E-31B8D7C3FD6B",
                    "UNKNOWN-9a37",
                    "Entrypoint measurement for module UNKNOWN-9a37",
                    1543.483568,
                    5.6544269999999415,
                ),
                (
                    67,
                    "LoadImage",
                    "627FBCC3-41F0-4378-99B6-533DCE8850A0",
                    "UNKNOWN-4980",
                    "LoadImage measurement for module UNKNOWN-4980",
                    1549.142552,
                    1.3525970000000598,
                ),
                (
                    68,
                    "Entrypoint",
                    "627FBCC3-41F0-4378-99B6-533DCE8850A0",
                    "UNKNOWN-4980",
                    "Entrypoint measurement for module UNKNOWN-4980",
                    1550.497409,
                    5.649312000000009,
                ),
                (
                    69,
                    "LoadImage",
                    "5B7CC220-E183-481C-87F4-27A92D8DB88F",
                    "UNKNOWN-c933",
                    "LoadImage measurement for module UNKNOWN-c933",
                    1556.151953,
                    2.051091000000042,
                ),
                (
                    70,
                    "Entrypoint",
                    "5B7CC220-E183-481C-87F4-27A92D8DB88F",
                    "UNKNOWN-c933",
                    "Entrypoint measurement for module UNKNOWN-c933",
                    1558.20529,
                    6.807628999999906,
                ),
                (
                    73,
                    "Inmodule",
                    "EEEE611D-F78F-4FB9-B868-55907F169280",
                    "UNKNOWN-f1fa",
                    "Inmodule measurement from module UNKNOWN-f1fa with label WaitForPreMemScriptsToC",
                    1568.801207,
                    0.024912999999969543,
                ),
                (
                    72,
                    "Function",
                    "52C05B14-0B98-496C-BC3B-04B50211D680",
                    "UNKNOWN-fc49",
                    "Function measurement from module UNKNOWN-fc49 with label PeiDelayedDispatchWaitO",
                    1568.804397,
                    0.01900799999998526,
                ),
                (
                    71,
                    "EventSignal",
                    "F043D836-1308-4392-A3F5-BC8D37A77CF2, 52C05B14-0B98-496C-BC3B-04B50211D680",
                    "UNKNOWN-c107, UNKNOWN-fc49",
                    "EventSignal measurement from module UNKNOWN-c107 and trigger/event UNKNOWN-fc49",
                    1568.815057,
                    0.005270999999993364,
                ),
                (
                    153,
                    "Inmodule",
                    "52C05B14-0B98-496C-BC3B-04B50211D680",
                    "UNKNOWN-fc49",
                    "Inmodule measurement from module UNKNOWN-fc49 with label PostMem",
                    99620.161285,
                    1335.7126150000113,
                ),
                (
                    76,
                    "Inmodule",
                    "52C05B14-0B98-496C-BC3B-04B50211D680",
                    "UNKNOWN-fc49",
                    "Inmodule measurement from module UNKNOWN-fc49 with label DisMem",
                    99733.781112,
                    40.50984100000642,
                ),
                (
                    75,
                    "Inmodule",
                    "EEEE611D-F78F-4FB9-B868-55907F169280",
                    "UNKNOWN-f1fa",
                    "Inmodule measurement from module UNKNOWN-f1fa with label RunPlatformInitScripts",
                    99736.78065,
                    1.2949490000028163,
                ),
                (
                    77,
                    "LoadImage",
                    "9B3ADA4F-AE56-4C24-8DEA-F03B7558AE50",
                    "UNKNOWN-61e8",
                    "LoadImage measurement for module UNKNOWN-61e8",
                    99774.329687,
                    0.485114999988582,
                ),
                (
                    78,
                    "Entrypoint",
                    "9B3ADA4F-AE56-4C24-8DEA-F03B7558AE50",
                    "UNKNOWN-61e8",
                    "Entrypoint measurement for module UNKNOWN-61e8",
                    99774.817208,
                    0.0203520000068238,
                ),
                (
                    79,
                    "LoadImage",
                    "0D1CE46B-72D9-4BA7-95DA-23511865E661",
                    "UNKNOWN-d8c2",
                    "LoadImage measurement for module UNKNOWN-d8c2",
                    99774.868798,
                    2.055216000007931,
                ),
                (
                    80,
                    "Entrypoint",
                    "0D1CE46B-72D9-4BA7-95DA-23511865E661",
                    "UNKNOWN-d8c2",
                    "Entrypoint measurement for module UNKNOWN-d8c2",
                    99776.926185,
                    0.018345999997109175,
                ),
                (
                    81,
                    "LoadImage",
                    "9E1CC850-6731-4848-8752-6673C7005EEE",
                    "UNKNOWN-36da",
                    "LoadImage measurement for module UNKNOWN-36da",
                    99776.978745,
                    1.2957599999936065,
                ),
                (
                    82,
                    "Entrypoint",
                    "9E1CC850-6731-4848-8752-6673C7005EEE",
                    "UNKNOWN-36da",
                    "Entrypoint measurement for module UNKNOWN-36da",
                    99778.276845,
                    1.1290989999979502,
                ),
                (
                    83,
                    "LoadImage",
                    "10D70125-BAA3-4296-A62F-602BEBBB9010",
                    "UNKNOWN-fb34",
                    "LoadImage measurement for module UNKNOWN-fb34",
                    99779.485696,
                    0.9081959999894025,
                ),
                (
                    84,
                    "Entrypoint",
                    "10D70125-BAA3-4296-A62F-602BEBBB9010",
                    "UNKNOWN-fb34",
                    "Entrypoint measurement for module UNKNOWN-fb34",
                    99780.39612,
                    4.86551899999904,
                ),
                (
                    85,
                    "Inmodule",
                    "3FECFD95-7CB2-4A6E-8FAC-DEFD9947E35E",
                    "UNKNOWN-99c6",
                    "Inmodule measurement from module UNKNOWN-99c6 with label Verify FV FF580000:8000",
                    99786.028539,
                    29.72482299999683,
                ),
                (
                    87,
                    "Function",
                    "10D70125-BAA3-4296-A62F-602BEBBB9010",
                    "UNKNOWN-fb34",
                    "Function measurement from module UNKNOWN-fb34 with label CustomGuidedSectionExtr",
                    99815.885561,
                    6.97406900000351,
                ),
                (
                    86,
                    "Inmodule",
                    "10D70125-BAA3-4296-A62F-602BEBBB9010",
                    "UNKNOWN-fb34",
                    "Inmodule measurement from module UNKNOWN-fb34 with label Extract guided section",
                    99815.92194,
                    6.934943000000203,
                ),
                (
                    91,
                    "Inmodule",
                    "3FECFD95-7CB2-4A6E-8FAC-DEFD9947E35E",
                    "UNKNOWN-99c6",
                    "Inmodule measurement from module UNKNOWN-99c6 with label FV@FF680000:80000",
                    99823.26398,
                    136.24569199999678,
                ),
                (
                    88,
                    "Inmodule",
                    "3FECFD95-7CB2-4A6E-8FAC-DEFD9947E35E",
                    "UNKNOWN-99c6",
                    "Inmodule measurement from module UNKNOWN-99c6 with label Verify FV FF680000:8000",
                    99823.307448,
                    34.511604999992414,
                ),
                (
                    90,
                    "Function",
                    "10D70125-BAA3-4296-A62F-602BEBBB9010",
                    "UNKNOWN-fb34",
                    "Function measurement from module UNKNOWN-fb34 with label CustomGuidedSectionExtr",
                    99857.864358,
                    101.35111299999699,
                ),
                (
                    89,
                    "Inmodule",
                    "10D70125-BAA3-4296-A62F-602BEBBB9010",
                    "UNKNOWN-fb34",
                    "Inmodule measurement from module UNKNOWN-fb34 with label Extract guided section",
                    99857.872841,
                    101.34012799999618,
                ),
                (
                    92,
                    "LoadImage",
                    "86D70125-BAA3-4296-A62F-602BEBBB9081",
                    "UNKNOWN-a8ab",
                    "LoadImage measurement for module UNKNOWN-a8ab",
                    99959.623281,
                    0.12608100000943523,
                ),
                (
                    93,
                    "Entrypoint",
                    "86D70125-BAA3-4296-A62F-602BEBBB9081",
                    "UNKNOWN-a8ab",
                    "Entrypoint measurement for module UNKNOWN-a8ab",
                    99959.751771,
                    0.11949700000695884,
                ),
                (
                    94,
                    "LoadImage",
                    "EDADEB9D-DDBA-48BD-9D22-C1C169C8C5C6",
                    "UNKNOWN-0c21",
                    "LoadImage measurement for module UNKNOWN-0c21",
                    99959.900746,
                    0.036871000003884546,
                ),
                (
                    95,
                    "Entrypoint",
                    "EDADEB9D-DDBA-48BD-9D22-C1C169C8C5C6",
                    "UNKNOWN-0c21",
                    "Entrypoint measurement for module UNKNOWN-0c21",
                    99959.945992,
                    70.18612500000745,
                ),
                (
                    96,
                    "LoadImage",
                    "75862FE4-4FC6-4188-804B-29DC7733178B",
                    "UNKNOWN-dff7",
                    "LoadImage measurement for module UNKNOWN-dff7",
                    100030.176441,
                    0.02631400000245776,
                ),
                (
                    97,
                    "Entrypoint",
                    "75862FE4-4FC6-4188-804B-29DC7733178B",
                    "UNKNOWN-dff7",
                    "Entrypoint measurement for module UNKNOWN-dff7",
                    100030.211631,
                    2.11408400000073,
                ),
                (
                    98,
                    "LoadImage",
                    "13827527-82DF-46FA-8665-B53E5C3D346A",
                    "UNKNOWN-17e2",
                    "LoadImage measurement for module UNKNOWN-17e2",
                    100032.330488,
                    0.18995299999369308,
                ),
                (
                    99,
                    "Entrypoint",
                    "13827527-82DF-46FA-8665-B53E5C3D346A",
                    "UNKNOWN-17e2",
                    "Entrypoint measurement for module UNKNOWN-17e2",
                    100032.522491,
                    5.642633000010392,
                ),
                (
                    100,
                    "Inmodule",
                    "13827527-82DF-46FA-8665-B53E5C3D346A",
                    "UNKNOWN-17e2",
                    "Inmodule measurement from module UNKNOWN-17e2 with label CopySetup",
                    100045.673639,
                    0.024537999997846782,
                ),
                (
                    123,
                    "Inmodule",
                    "13827527-82DF-46FA-8665-B53E5C3D346A",
                    "UNKNOWN-17e2",
                    "Inmodule measurement from module UNKNOWN-17e2 with label FvCopy",
                    100045.700239,
                    339.07417700000224,
                ),
                (
                    101,
                    "LoadImage",
                    "FE9356EC-F0EE-45B1-A5DA-1D1EA81E7C4E",
                    "UNKNOWN-0f61",
                    "LoadImage measurement for module UNKNOWN-0f61",
                    100050.352624,
                    0.18768799999088515,
                ),
                (
                    102,
                    "Entrypoint",
                    "FE9356EC-F0EE-45B1-A5DA-1D1EA81E7C4E",
                    "UNKNOWN-0f61",
                    "Entrypoint measurement for module UNKNOWN-0f61",
                    100050.542361,
                    5.666635999994469,
                ),
                (
                    103,
                    "LoadImage",
                    "26AC2A04-BA59-4988-909E-FF553F22B5D8",
                    "UNKNOWN-1b81",
                    "LoadImage measurement for module UNKNOWN-1b81",
                    100056.216932,
                    0.1885560000082478,
                ),
                (
                    104,
                    "Entrypoint",
                    "26AC2A04-BA59-4988-909E-FF553F22B5D8",
                    "UNKNOWN-1b81",
                    "Entrypoint measurement for module UNKNOWN-1b81",
                    100056.407591,
                    5.62715400000161,
                ),
                (
                    105,
                    "LoadImage",
                    "A7290DBE-F769-40F2-8CC0-D4A6B37E8126",
                    "UNKNOWN-f228",
                    "LoadImage measurement for module UNKNOWN-f228",
                    100074.227177,
                    0.18061800001305528,
                ),
                (
                    106,
                    "Entrypoint",
                    "A7290DBE-F769-40F2-8CC0-D4A6B37E8126",
                    "UNKNOWN-f228",
                    "Entrypoint measurement for module UNKNOWN-f228",
                    100074.409877,
                    5.671394000004511,
                ),
                (
                    107,
                    "LoadImage",
                    "59ADD62D-A1C0-44C5-A90F-A1168770468C",
                    "UNKNOWN-10eb",
                    "LoadImage measurement for module UNKNOWN-10eb",
                    100080.101383,
                    0.16561300000466872,
                ),
                (
                    111,
                    "Entrypoint",
                    "59ADD62D-A1C0-44C5-A90F-A1168770468C",
                    "UNKNOWN-10eb",
                    "Entrypoint measurement for module UNKNOWN-10eb",
                    100080.268958,
                    7.912106000003405,
                ),
                (
                    110,
                    "Inmodule",
                    "59ADD62D-A1C0-44C5-A90F-A1168770468C",
                    "UNKNOWN-10eb",
                    "Inmodule measurement from module UNKNOWN-10eb with label WaitForPreMemScriptsToC",
                    100083.102815,
                    0.31629199998860713,
                ),
                (
                    109,
                    "Function",
                    "52C05B14-0B98-496C-BC3B-04B50211D680",
                    "UNKNOWN-fc49",
                    "Function measurement from module UNKNOWN-fc49 with label PeiDelayedDispatchWaitO",
                    100083.240065,
                    0.17652299998735543,
                ),
                (
                    108,
                    "EventSignal",
                    "F043D836-1308-4392-A3F5-BC8D37A77CF2, 52C05B14-0B98-496C-BC3B-04B50211D680",
                    "UNKNOWN-c107, UNKNOWN-fc49",
                    "EventSignal measurement from module UNKNOWN-c107 and trigger/event UNKNOWN-fc49",
                    100083.361786,
                    0.05238400000962429,
                ),
                (
                    112,
                    "LoadImage",
                    "A0C98B77-CBA5-4BB8-993B-4AF6CE33ECE4",
                    "UNKNOWN-5a3e",
                    "LoadImage measurement for module UNKNOWN-5a3e",
                    100098.085064,
                    0.19464000000152737,
                ),
                (
                    113,
                    "Entrypoint",
                    "A0C98B77-CBA5-4BB8-993B-4AF6CE33ECE4",
                    "UNKNOWN-5a3e",
                    "Entrypoint measurement for module UNKNOWN-5a3e",
                    100098.28178,
                    8.953781999996863,
                ),
                (
                    114,
                    "Function",
                    "A0C98B77-CBA5-4BB8-993B-4AF6CE33ECE4",
                    "UNKNOWN-5a3e",
                    "Function measurement from module UNKNOWN-5a3e with label MeasureMainBios",
                    100114.106935,
                    0.022495999990496784,
                ),
                (
                    115,
                    "LoadImage",
                    "ADF01BF6-47D6-495D-B95B-687777807214",
                    "UNKNOWN-9f37",
                    "LoadImage measurement for module UNKNOWN-9f37",
                    100125.38404,
                    0.18752500000118744,
                ),
                (
                    116,
                    "Entrypoint",
                    "ADF01BF6-47D6-495D-B95B-687777807214",
                    "UNKNOWN-9f37",
                    "Entrypoint measurement for module UNKNOWN-9f37",
                    100125.57362,
                    5.645528000008198,
                ),
                (
                    117,
                    "LoadImage",
                    "7E40245F-A0EB-4A02-849F-A12D9C5FDB0D",
                    "UNKNOWN-d221",
                    "LoadImage measurement for module UNKNOWN-d221",
                    100131.22665,
                    0.17513899999903515,
                ),
                (
                    118,
                    "Entrypoint",
                    "7E40245F-A0EB-4A02-849F-A12D9C5FDB0D",
                    "UNKNOWN-d221",
                    "Entrypoint measurement for module UNKNOWN-d221",
                    100131.417311,
                    16.764758000004804,
                ),
                (
                    119,
                    "LoadImage",
                    "15446019-9170-436A-A981-CC7521E9D7F9",
                    "UNKNOWN-fa18",
                    "LoadImage measurement for module UNKNOWN-fa18",
                    100160.442269,
                    0.20949299998756032,
                ),
                (
                    120,
                    "Entrypoint",
                    "15446019-9170-436A-A981-CC7521E9D7F9",
                    "UNKNOWN-fa18",
                    "Entrypoint measurement for module UNKNOWN-fa18",
                    100160.653784,
                    5.632641000003787,
                ),
                (
                    121,
                    "LoadImage",
                    "15C8DCEF-E7D9-41E2-A89C-8D1C61F07E9C",
                    "UNKNOWN-26e8",
                    "LoadImage measurement for module UNKNOWN-26e8",
                    100166.316284,
                    8.205619000000297,
                ),
                (
                    122,
                    "Entrypoint",
                    "15C8DCEF-E7D9-41E2-A89C-8D1C61F07E9C",
                    "UNKNOWN-26e8",
                    "Entrypoint measurement for module UNKNOWN-26e8",
                    100174.52875,
                    0.7464840000029653,
                ),
                (
                    124,
                    "Inmodule",
                    "13827527-82DF-46FA-8665-B53E5C3D346A",
                    "UNKNOWN-17e2",
                    "Inmodule measurement from module UNKNOWN-17e2 with label DecompSetup",
                    100384.784121,
                    0.041147999989334494,
                ),
                (
                    129,
                    "Inmodule",
                    "13827527-82DF-46FA-8665-B53E5C3D346A",
                    "UNKNOWN-17e2",
                    "Inmodule measurement from module UNKNOWN-17e2 with label DecompFv",
                    100384.829435,
                    328.49711399999796,
                ),
                (
                    125,
                    "LoadImage",
                    "131B73AC-C033-4DE1-8794-6DAB08E731CF",
                    "UNKNOWN-23c4",
                    "LoadImage measurement for module UNKNOWN-23c4",
                    100389.456995,
                    1.2607480000006035,
                ),
                (
                    126,
                    "Entrypoint",
                    "131B73AC-C033-4DE1-8794-6DAB08E731CF",
                    "UNKNOWN-23c4",
                    "Entrypoint measurement for module UNKNOWN-23c4",
                    100390.722001,
                    5.649978000001283,
                ),
                (
                    127,
                    "LoadImage",
                    "183BB3E1-A1E5-4445-8AC9-0E83B6547E0E",
                    "UNKNOWN-3265",
                    "LoadImage measurement for module UNKNOWN-3265",
                    100396.38763,
                    1.9256040000036592,
                ),
                (
                    128,
                    "Entrypoint",
                    "183BB3E1-A1E5-4445-8AC9-0E83B6547E0E",
                    "UNKNOWN-3265",
                    "Entrypoint measurement for module UNKNOWN-3265",
                    100398.317135,
                    310.94837699999334,
                ),
                (
                    133,
                    "Inmodule",
                    "13827527-82DF-46FA-8665-B53E5C3D346A",
                    "UNKNOWN-17e2",
                    "Inmodule measurement from module UNKNOWN-17e2 with label FV@6041A000:200000",
                    100713.337613,
                    47.96876699999848,
                ),
                (
                    130,
                    "Inmodule",
                    "13827527-82DF-46FA-8665-B53E5C3D346A",
                    "UNKNOWN-17e2",
                    "Inmodule measurement from module UNKNOWN-17e2 with label Verify FV 6041A000:2000",
                    100713.34363,
                    20.738444000002346,
                ),
                (
                    132,
                    "Function",
                    "10D70125-BAA3-4296-A62F-602BEBBB9010",
                    "UNKNOWN-fb34",
                    "Function measurement from module UNKNOWN-fb34 with label CustomGuidedSectionExtr",
                    100734.170331,
                    1.3038030000025174,
                ),
                (
                    131,
                    "Inmodule",
                    "10D70125-BAA3-4296-A62F-602BEBBB9010",
                    "UNKNOWN-fb34",
                    "Inmodule measurement from module UNKNOWN-fb34 with label Extract guided section",
                    100734.285012,
                    1.1841830000048503,
                ),
                (
                    134,
                    "LoadImage",
                    "54D7CC18-492A-4B43-AD9E-A461D81F82B5",
                    "UNKNOWN-f7e3",
                    "LoadImage measurement for module UNKNOWN-f7e3",
                    100761.455535,
                    0.46649599999364,
                ),
                (
                    135,
                    "Entrypoint",
                    "54D7CC18-492A-4B43-AD9E-A461D81F82B5",
                    "UNKNOWN-f7e3",
                    "Entrypoint measurement for module UNKNOWN-f7e3",
                    100761.926383,
                    4.648256000000401,
                ),
                (
                    136,
                    "LoadImage",
                    "EEE8D8EC-40C2-159B-71C7-8796EEEF3FBC",
                    "UNKNOWN-538b",
                    "LoadImage measurement for module UNKNOWN-538b",
                    100766.581422,
                    1.3494700000010198,
                ),
                (
                    137,
                    "Entrypoint",
                    "EEE8D8EC-40C2-159B-71C7-8796EEEF3FBC",
                    "UNKNOWN-538b",
                    "Entrypoint measurement for module UNKNOWN-538b",
                    100767.935111,
                    5.6585310000082245,
                ),
                (
                    138,
                    "LoadImage",
                    "29CBB005-C972-49F3-960F-292E2202CECD",
                    "UNKNOWN-43ec",
                    "LoadImage measurement for module UNKNOWN-43ec",
                    100773.600221,
                    2.3218099999940023,
                ),
                (
                    139,
                    "Entrypoint",
                    "29CBB005-C972-49F3-960F-292E2202CECD",
                    "UNKNOWN-43ec",
                    "Entrypoint measurement for module UNKNOWN-43ec",
                    100775.925706,
                    5.65014300000621,
                ),
                (
                    140,
                    "LoadImage",
                    "EA7F0916-B5C8-493F-A006-565CC2041044",
                    "UNKNOWN-8370",
                    "LoadImage measurement for module UNKNOWN-8370",
                    100781.582362,
                    1.642982999997912,
                ),
                (
                    141,
                    "Entrypoint",
                    "EA7F0916-B5C8-493F-A006-565CC2041044",
                    "UNKNOWN-8370",
                    "Entrypoint measurement for module UNKNOWN-8370",
                    100783.22902,
                    5.6621480000030715,
                ),
                (
                    142,
                    "LoadImage",
                    "8B555AE2-4254-43A2-839E-4869604CCC9A",
                    "UNKNOWN-21de",
                    "LoadImage measurement for module UNKNOWN-21de",
                    100788.897889,
                    2.1302189999987604,
                ),
                (
                    143,
                    "Entrypoint",
                    "8B555AE2-4254-43A2-839E-4869604CCC9A",
                    "UNKNOWN-21de",
                    "Entrypoint measurement for module UNKNOWN-21de",
                    100791.03179,
                    95.24237900000298,
                ),
                (
                    144,
                    "LoadImage",
                    "E6D1F588-F107-41DE-9832-CEA334B33C1F",
                    "UNKNOWN-48b2",
                    "LoadImage measurement for module UNKNOWN-48b2",
                    100886.320504,
                    0.03427799999190029,
                ),
                (
                    147,
                    "Entrypoint",
                    "E6D1F588-F107-41DE-9832-CEA334B33C1F",
                    "UNKNOWN-48b2",
                    "Entrypoint measurement for module UNKNOWN-48b2",
                    100886.356209,
                    2.2335429999948246,
                ),
                (
                    146,
                    "Function",
                    "52C05B14-0B98-496C-BC3B-04B50211D680",
                    "UNKNOWN-fc49",
                    "Function measurement from module UNKNOWN-fc49 with label PeiDelayedDispatchWaitO",
                    100886.415558,
                    0.07949800000642426,
                ),
                (
                    145,
                    "EventSignal",
                    "8F0DDF8E-3D51-46A7-9C64-72D60DEFDD37, 52C05B14-0B98-496C-BC3B-04B50211D680",
                    "UNKNOWN-cc14, UNKNOWN-fc49",
                    "EventSignal measurement from module UNKNOWN-cc14 and trigger/event UNKNOWN-fc49",
                    100886.419941,
                    0.07352400000672787,
                ),
                (
                    149,
                    "Function",
                    "52C05B14-0B98-496C-BC3B-04B50211D680",
                    "UNKNOWN-fc49",
                    "Function measurement from module UNKNOWN-fc49 with label PeiDelayedDispatchWaitO",
                    100888.592109,
                    0.007040999989840202,
                ),
                (
                    148,
                    "EventSignal",
                    "8F0DDF8E-3D51-46A7-9C64-72D60DEFDD37, 52C05B14-0B98-496C-BC3B-04B50211D680",
                    "UNKNOWN-cc14, UNKNOWN-fc49",
                    "EventSignal measurement from module UNKNOWN-cc14 and trigger/event UNKNOWN-fc49",
                    100888.595427,
                    0.0022480000043287873,
                ),
                (
                    150,
                    "Inmodule",
                    "E6D1F588-F107-41DE-9832-CEA334B33C1F",
                    "UNKNOWN-48b2",
                    "Inmodule measurement from module UNKNOWN-48b2 with label Locate X64 relay module",
                    100898.494148,
                    0.1975479999964591,
                ),
                (
                    151,
                    "Inmodule",
                    "E6D1F588-F107-41DE-9832-CEA334B33C1F",
                    "UNKNOWN-48b2",
                    "Inmodule measurement from module UNKNOWN-48b2 with label Switch to X64 to initia",
                    100898.694131,
                    9.138151999999536,
                ),
                (
                    157,
                    "EventSignal",
                    "605EA650-C65C-42E1-BA80-91A52AB618C6, 86D70125-BAA3-4296-A62F-602BEBBB9081",
                    "UNKNOWN-a042, UNKNOWN-a8ab",
                    "EventSignal measurement from module UNKNOWN-a042 and trigger/event UNKNOWN-a8ab",
                    100956.356017,
                    10.040450000000419,
                ),
                (
                    154,
                    "Inmodule",
                    "52C05B14-0B98-496C-BC3B-04B50211D680",
                    "UNKNOWN-fc49",
                    "Inmodule measurement from module UNKNOWN-fc49 with label PerfDelayedDispatchEndO",
                    100956.497394,
                    2.2444719999912195,
                ),
                (
                    155,
                    "Inmodule",
                    "59ADD62D-A1C0-44C5-A90F-A1168770468C",
                    "UNKNOWN-10eb",
                    "Inmodule measurement from module UNKNOWN-10eb with label RunPlatformInitScripts",
                    100958.974806,
                    0.1327000000019325,
                ),
                (
                    156,
                    "Callback",
                    "605EA650-C65C-42E1-BA80-91A52AB618C6, A0C98B77-CBA5-4BB8-993B-4AF6CE33ECE4",
                    "UNKNOWN-a042, UNKNOWN-5a3e",
                    "Callback measurement from module UNKNOWN-a042 and trigger/event UNKNOWN-5a3e",
                    100959.135634,
                    0.004781999989063479,
                ),
                (
                    345,
                    "Crossmodule",
                    "D6A2CB7F-6A18-4E2F-B43B-9920A733700A, 6D33944A-EC75-4855-A54D-809C75241F6C",
                    "UNKNOWN-6c05, UNKNOWN-b2b2",
                    "Crossmodule measurement from UNKNOWN-6c05 to UNKNOWN-b2b2 with label DXE",
                    100966.716056,
                    699.1598789999989,
                ),
                (
                    159,
                    "Function",
                    "D6A2CB7F-6A18-4E2F-B43B-9920A733700A",
                    "UNKNOWN-6c05",
                    "Function measurement from module UNKNOWN-6c05 with label CoreInitializeDispatche",
                    100977.407653,
                    1.232864999998128,
                ),
                (
                    344,
                    "Function",
                    "D6A2CB7F-6A18-4E2F-B43B-9920A733700A",
                    "UNKNOWN-6c05",
                    "Function measurement from module UNKNOWN-6c05 with label CoreDispatcher",
                    100978.641691,
                    684.4183360000025,
                ),
                (
                    160,
                    "LoadImage",
                    "80CF7257-87AB-47F9-A3FE-D50B76D89541",
                    "UNKNOWN-3a94",
                    "LoadImage measurement for module UNKNOWN-3a94",
                    100978.773958,
                    0.07925099998828955,
                ),
                (
                    161,
                    "Entrypoint",
                    "80CF7257-87AB-47F9-A3FE-D50B76D89541",
                    "UNKNOWN-3a94",
                    "Entrypoint measurement for module UNKNOWN-3a94",
                    100978.859778,
                    0.03181899999617599,
                ),
                (
                    162,
                    "LoadImage",
                    "B601F8C4-43B7-4784-95B1-F4226CB40CEE",
                    "UNKNOWN-138a",
                    "LoadImage measurement for module UNKNOWN-138a",
                    100979.020816,
                    0.07355200000165496,
                ),
                (
                    163,
                    "Entrypoint",
                    "B601F8C4-43B7-4784-95B1-F4226CB40CEE",
                    "UNKNOWN-138a",
                    "Entrypoint measurement for module UNKNOWN-138a",
                    100979.09916,
                    0.019381000005523674,
                ),
                (
                    164,
                    "LoadImage",
                    "E9BADBB6-0228-43FB-A367-5F3677CDC9E0",
                    "UNKNOWN-ff3d",
                    "LoadImage measurement for module UNKNOWN-ff3d",
                    100979.120631,
                    0.06860300000698771,
                ),
                (
                    165,
                    "Entrypoint",
                    "E9BADBB6-0228-43FB-A367-5F3677CDC9E0",
                    "UNKNOWN-ff3d",
                    "Entrypoint measurement for module UNKNOWN-ff3d",
                    100979.194811,
                    0.008916999999200925,
                ),
                (
                    166,
                    "LoadImage",
                    "9B680FCE-AD6B-4F3A-B60B-F59899003443",
                    "UNKNOWN-74ab",
                    "LoadImage measurement for module UNKNOWN-74ab",
                    100979.206047,
                    0.07703099999343976,
                ),
                (
                    167,
                    "Entrypoint",
                    "9B680FCE-AD6B-4F3A-B60B-F59899003443",
                    "UNKNOWN-74ab",
                    "Entrypoint measurement for module UNKNOWN-74ab",
                    100979.288864,
                    0.0173380000051111,
                ),
                (
                    168,
                    "LoadImage",
                    "96B5C032-DF4C-4B6E-8232-438DCF448D0E",
                    "UNKNOWN-89a3",
                    "LoadImage measurement for module UNKNOWN-89a3",
                    100979.308418,
                    0.066739999994752,
                ),
                (
                    169,
                    "Entrypoint",
                    "96B5C032-DF4C-4B6E-8232-438DCF448D0E",
                    "UNKNOWN-89a3",
                    "Entrypoint measurement for module UNKNOWN-89a3",
                    100979.380864,
                    0.011195999992196448,
                ),
                (
                    170,
                    "LoadImage",
                    "4B28E4C7-FF36-4E10-93CF-A82159E777C5",
                    "UNKNOWN-80d1",
                    "LoadImage measurement for module UNKNOWN-80d1",
                    100979.394117,
                    0.07354599999962375,
                ),
                (
                    171,
                    "Entrypoint",
                    "4B28E4C7-FF36-4E10-93CF-A82159E777C5",
                    "UNKNOWN-80d1",
                    "Entrypoint measurement for module UNKNOWN-80d1",
                    100979.47343,
                    0.02776300000550691,
                ),
                (
                    172,
                    "LoadImage",
                    "A0BAD9F7-AB78-491B-B583-C52B7F84B9E0",
                    "UNKNOWN-0008",
                    "LoadImage measurement for module UNKNOWN-0008",
                    100979.5033,
                    0.07310200000938494,
                ),
                (
                    173,
                    "Entrypoint",
                    "A0BAD9F7-AB78-491B-B583-C52B7F84B9E0",
                    "UNKNOWN-0008",
                    "Entrypoint measurement for module UNKNOWN-0008",
                    100979.581721,
                    1.3408239999989746,
                ),
                (
                    174,
                    "LoadImage",
                    "A19B1FE7-C1BC-49F8-875F-54A5D542443F",
                    "UNKNOWN-c391",
                    "LoadImage measurement for module UNKNOWN-c391",
                    100980.924773,
                    0.06931199999235105,
                ),
                (
                    175,
                    "Entrypoint",
                    "A19B1FE7-C1BC-49F8-875F-54A5D542443F",
                    "UNKNOWN-c391",
                    "Entrypoint measurement for module UNKNOWN-c391",
                    100980.999639,
                    0.011721999995643273,
                ),
                (
                    176,
                    "LoadImage",
                    "1A1E4886-9517-440E-9FDE-3BE44CEE2136",
                    "UNKNOWN-e288",
                    "LoadImage measurement for module UNKNOWN-e288",
                    100981.013543,
                    0.09658100000524428,
                ),
                (
                    177,
                    "Entrypoint",
                    "1A1E4886-9517-440E-9FDE-3BE44CEE2136",
                    "UNKNOWN-e288",
                    "Entrypoint measurement for module UNKNOWN-e288",
                    100981.116094,
                    83.83568299999752,
                ),
                (
                    178,
                    "LoadImage",
                    "A7EBBFED-CD82-4278-94DC-80F0CDE46FE4",
                    "UNKNOWN-788b",
                    "LoadImage measurement for module UNKNOWN-788b",
                    101064.955802,
                    0.17603499999677297,
                ),
                (
                    179,
                    "Entrypoint",
                    "A7EBBFED-CD82-4278-94DC-80F0CDE46FE4",
                    "UNKNOWN-788b",
                    "Entrypoint measurement for module UNKNOWN-788b",
                    101065.152806,
                    0.06098399999609683,
                ),
                (
                    180,
                    "LoadImage",
                    "E5327F8D-C7FD-4133-BCE9-C87A275834D8",
                    "UNKNOWN-4b8e",
                    "LoadImage measurement for module UNKNOWN-4b8e",
                    101065.216221,
                    0.1631970000016736,
                ),
                (
                    181,
                    "Entrypoint",
                    "E5327F8D-C7FD-4133-BCE9-C87A275834D8",
                    "UNKNOWN-4b8e",
                    "Entrypoint measurement for module UNKNOWN-4b8e",
                    101065.398808,
                    0.10403600000427105,
                ),
                (
                    182,
                    "LoadImage",
                    "BB7D62EB-AD70-4151-A1D4-12C53E50CB11",
                    "UNKNOWN-a842",
                    "LoadImage measurement for module UNKNOWN-a842",
                    101065.505213,
                    0.153015999996569,
                ),
                (
                    183,
                    "Entrypoint",
                    "BB7D62EB-AD70-4151-A1D4-12C53E50CB11",
                    "UNKNOWN-a842",
                    "Entrypoint measurement for module UNKNOWN-a842",
                    101065.675722,
                    0.031638000000384636,
                ),
                (
                    184,
                    "LoadImage",
                    "348C4D62-BFBD-4882-9ECE-C80BB1C4783B",
                    "UNKNOWN-3e0d",
                    "LoadImage measurement for module UNKNOWN-3e0d",
                    101065.709769,
                    0.1949590000003809,
                ),
                (
                    185,
                    "Entrypoint",
                    "348C4D62-BFBD-4882-9ECE-C80BB1C4783B",
                    "UNKNOWN-3e0d",
                    "Entrypoint measurement for module UNKNOWN-3e0d",
                    101065.925346,
                    0.09758799998962786,
                ),
                (
                    186,
                    "LoadImage",
                    "C8339973-A563-4561-B858-D8476F9DEFC4",
                    "UNKNOWN-ce10",
                    "LoadImage measurement for module UNKNOWN-ce10",
                    101066.025481,
                    0.15239099999598693,
                ),
                (
                    187,
                    "Entrypoint",
                    "C8339973-A563-4561-B858-D8476F9DEFC4",
                    "UNKNOWN-ce10",
                    "Entrypoint measurement for module UNKNOWN-ce10",
                    101066.19817,
                    0.03502999999909662,
                ),
                (
                    188,
                    "LoadImage",
                    "5AAB83E5-F027-4CA7-BFD0-16358CC9E453",
                    "UNKNOWN-d373",
                    "LoadImage measurement for module UNKNOWN-d373",
                    101066.235734,
                    0.15738299999793526,
                ),
                (
                    189,
                    "Entrypoint",
                    "5AAB83E5-F027-4CA7-BFD0-16358CC9E453",
                    "UNKNOWN-d373",
                    "Entrypoint measurement for module UNKNOWN-d373",
                    101066.411433,
                    0.05621199999586679,
                ),
                (
                    190,
                    "LoadImage",
                    "0B92B7F9-A0C3-4650-8AB5-5AE7EDF74D05",
                    "UNKNOWN-79ca",
                    "LoadImage measurement for module UNKNOWN-79ca",
                    101066.470244,
                    0.20770400000037625,
                ),
                (
                    191,
                    "Entrypoint",
                    "0B92B7F9-A0C3-4650-8AB5-5AE7EDF74D05",
                    "UNKNOWN-79ca",
                    "Entrypoint measurement for module UNKNOWN-79ca",
                    101066.699258,
                    0.05789200001163408,
                ),
                (
                    192,
                    "LoadImage",
                    "7F2E29EF-FD95-47BA-8843-865934F268D1",
                    "UNKNOWN-088f",
                    "LoadImage measurement for module UNKNOWN-088f",
                    101066.759694,
                    0.16414000000804663,
                ),
                (
                    193,
                    "Entrypoint",
                    "7F2E29EF-FD95-47BA-8843-865934F268D1",
                    "UNKNOWN-088f",
                    "Entrypoint measurement for module UNKNOWN-088f",
                    101066.941499,
                    0.06740400000126101,
                ),
                (
                    194,
                    "LoadImage",
                    "FEA01457-E381-4135-9475-C6AFD0076C61",
                    "UNKNOWN-7c15",
                    "LoadImage measurement for module UNKNOWN-7c15",
                    101067.01159,
                    0.6091290000040317,
                ),
                (
                    195,
                    "Entrypoint",
                    "FEA01457-E381-4135-9475-C6AFD0076C61",
                    "UNKNOWN-7c15",
                    "Entrypoint measurement for module UNKNOWN-7c15",
                    101067.642904,
                    0.026143000010051765,
                ),
                (
                    196,
                    "LoadImage",
                    "B981A835-6EE8-4F4C-AE0B-210AA0BFBF01",
                    "UNKNOWN-039b",
                    "LoadImage measurement for module UNKNOWN-039b",
                    101067.671472,
                    0.1523589999997057,
                ),
                (
                    197,
                    "Entrypoint",
                    "B981A835-6EE8-4F4C-AE0B-210AA0BFBF01",
                    "UNKNOWN-039b",
                    "Entrypoint measurement for module UNKNOWN-039b",
                    101067.844984,
                    0.03600900000310503,
                ),
                (
                    198,
                    "LoadImage",
                    "9622E42C-8E38-4A08-9E8F-54F784652F6B",
                    "UNKNOWN-3311",
                    "LoadImage measurement for module UNKNOWN-3311",
                    101067.88349,
                    0.15919400000711903,
                ),
                (
                    199,
                    "Entrypoint",
                    "9622E42C-8E38-4A08-9E8F-54F784652F6B",
                    "UNKNOWN-3311",
                    "Entrypoint measurement for module UNKNOWN-3311",
                    101068.064851,
                    0.06618300000263844,
                ),
                (
                    200,
                    "LoadImage",
                    "D93CE3D8-A7EB-4730-8C8E-CC466A9ECC3C",
                    "UNKNOWN-a3f7",
                    "LoadImage measurement for module UNKNOWN-a3f7",
                    101068.133541,
                    0.21119699999690056,
                ),
                (
                    201,
                    "Entrypoint",
                    "D93CE3D8-A7EB-4730-8C8E-CC466A9ECC3C",
                    "UNKNOWN-a3f7",
                    "Entrypoint measurement for module UNKNOWN-a3f7",
                    101068.367515,
                    0.07025199999043252,
                ),
                (
                    202,
                    "LoadImage",
                    "06E49122-4EF4-45FE-9766-E2EAF2F9472F",
                    "UNKNOWN-0ec7",
                    "LoadImage measurement for module UNKNOWN-0ec7",
                    101068.440518,
                    0.1658339999994496,
                ),
                (
                    204,
                    "Entrypoint",
                    "06E49122-4EF4-45FE-9766-E2EAF2F9472F",
                    "UNKNOWN-0ec7",
                    "Entrypoint measurement for module UNKNOWN-0ec7",
                    101068.629467,
                    0.1324449999956414,
                ),
                (
                    203,
                    "Inmodule",
                    "06E49122-4EF4-45FE-9766-E2EAF2F9472F",
                    "UNKNOWN-0ec7",
                    "Inmodule measurement from module UNKNOWN-0ec7 with label AdvLogger All files",
                    101068.726485,
                    0.002977999989525415,
                ),
                (
                    205,
                    "LoadImage",
                    "00B46EC9-2712-486B-A6A4-E2933581C28B",
                    "UNKNOWN-cc92",
                    "LoadImage measurement for module UNKNOWN-cc92",
                    101068.76414,
                    0.1582170000037877,
                ),
                (
                    206,
                    "Entrypoint",
                    "00B46EC9-2712-486B-A6A4-E2933581C28B",
                    "UNKNOWN-cc92",
                    "Entrypoint measurement for module UNKNOWN-cc92",
                    101068.945262,
                    0.05345600000873674,
                ),
                (
                    207,
                    "LoadImage",
                    "1BBCF923-4EAD-4DC0-B3C9-FE7AE6EC0DC9",
                    "UNKNOWN-2a24",
                    "LoadImage measurement for module UNKNOWN-2a24",
                    101069.00067,
                    0.16173900000285357,
                ),
                (
                    208,
                    "Entrypoint",
                    "1BBCF923-4EAD-4DC0-B3C9-FE7AE6EC0DC9",
                    "UNKNOWN-2a24",
                    "Entrypoint measurement for module UNKNOWN-2a24",
                    101069.185886,
                    1.3890429999883054,
                ),
                (
                    209,
                    "LoadImage",
                    "E1297918-E3D5-444F-89CF-61B3E001D60C",
                    "UNKNOWN-c2ac",
                    "LoadImage measurement for module UNKNOWN-c2ac",
                    101070.577024,
                    0.1606210000027204,
                ),
                (
                    210,
                    "Entrypoint",
                    "E1297918-E3D5-444F-89CF-61B3E001D60C",
                    "UNKNOWN-c2ac",
                    "Entrypoint measurement for module UNKNOWN-c2ac",
                    101070.760898,
                    0.23280500000691973,
                ),
                (
                    211,
                    "LoadImage",
                    "3B7668B8-766F-4E05-86FD-E4444FBF825F",
                    "UNKNOWN-8985",
                    "LoadImage measurement for module UNKNOWN-8985",
                    101070.995912,
                    0.15629400000034366,
                ),
                (
                    212,
                    "Entrypoint",
                    "3B7668B8-766F-4E05-86FD-E4444FBF825F",
                    "UNKNOWN-8985",
                    "Entrypoint measurement for module UNKNOWN-8985",
                    101071.173607,
                    0.018771000002743676,
                ),
                (
                    213,
                    "LoadImage",
                    "F0825F4F-D6A2-4F61-A6C0-5F01A86C80FF",
                    "UNKNOWN-0a93",
                    "LoadImage measurement for module UNKNOWN-0a93",
                    101071.328753,
                    0.2167020000051707,
                ),
                (
                    214,
                    "Entrypoint",
                    "F0825F4F-D6A2-4F61-A6C0-5F01A86C80FF",
                    "UNKNOWN-0a93",
                    "Entrypoint measurement for module UNKNOWN-0a93",
                    101071.56221,
                    12.867098000002443,
                ),
                (
                    215,
                    "LoadImage",
                    "00160F8D-2B35-4DF2-BBE0-B272A8D631F0",
                    "UNKNOWN-ee60",
                    "LoadImage measurement for module UNKNOWN-ee60",
                    101084.431469,
                    0.16121399999246933,
                ),
                (
                    216,
                    "Entrypoint",
                    "00160F8D-2B35-4DF2-BBE0-B272A8D631F0",
                    "UNKNOWN-ee60",
                    "Entrypoint measurement for module UNKNOWN-ee60",
                    101084.612803,
                    0.028665000005275942,
                ),
                (
                    217,
                    "LoadImage",
                    "FDBC2130-2A17-4830-8477-544F3669772F",
                    "UNKNOWN-a894",
                    "LoadImage measurement for module UNKNOWN-a894",
                    101084.643738,
                    0.15964700000768062,
                ),
                (
                    218,
                    "Entrypoint",
                    "FDBC2130-2A17-4830-8477-544F3669772F",
                    "UNKNOWN-a894",
                    "Entrypoint measurement for module UNKNOWN-a894",
                    101084.820206,
                    1.6022410000005038,
                ),
                (
                    219,
                    "LoadImage",
                    "6CE6B0DE-781C-4F6C-B42D-98346C614BEC",
                    "UNKNOWN-54a2",
                    "LoadImage measurement for module UNKNOWN-54a2",
                    101086.425174,
                    0.19398899999214336,
                ),
                (
                    220,
                    "Entrypoint",
                    "6CE6B0DE-781C-4F6C-B42D-98346C614BEC",
                    "UNKNOWN-54a2",
                    "Entrypoint measurement for module UNKNOWN-54a2",
                    101086.645459,
                    0.20920599999953993,
                ),
                (
                    221,
                    "LoadImage",
                    "F80697E9-7FD6-4665-8646-88E33EF71DFC",
                    "UNKNOWN-6ec9",
                    "LoadImage measurement for module UNKNOWN-6ec9",
                    101086.857139,
                    0.22755700000561774,
                ),
                (
                    222,
                    "Entrypoint",
                    "F80697E9-7FD6-4665-8646-88E33EF71DFC",
                    "UNKNOWN-6ec9",
                    "Entrypoint measurement for module UNKNOWN-6ec9",
                    101087.110529,
                    0.12535099999513477,
                ),
                (
                    223,
                    "LoadImage",
                    "128FB770-5E79-4176-9E51-9BB268A17DD1",
                    "UNKNOWN-ca9a",
                    "LoadImage measurement for module UNKNOWN-ca9a",
                    101087.238453,
                    0.2534040000027744,
                ),
                (
                    224,
                    "Entrypoint",
                    "128FB770-5E79-4176-9E51-9BB268A17DD1",
                    "UNKNOWN-ca9a",
                    "Entrypoint measurement for module UNKNOWN-ca9a",
                    101087.519243,
                    0.36035000000265427,
                ),
                (
                    225,
                    "LoadImage",
                    "995F045B-0265-46A4-8D21-001211A24A4F",
                    "UNKNOWN-8ef3",
                    "LoadImage measurement for module UNKNOWN-8ef3",
                    101087.881622,
                    0.18862099999387283,
                ),
                (
                    226,
                    "Entrypoint",
                    "995F045B-0265-46A4-8D21-001211A24A4F",
                    "UNKNOWN-8ef3",
                    "Entrypoint measurement for module UNKNOWN-8ef3",
                    101088.092049,
                    0.07781499999691732,
                ),
                (
                    227,
                    "LoadImage",
                    "C5D0E6B2-A841-4C67-A0E3-92354DE07E51",
                    "UNKNOWN-73fd",
                    "LoadImage measurement for module UNKNOWN-73fd",
                    101088.172908,
                    0.2027350000134902,
                ),
                (
                    228,
                    "Entrypoint",
                    "C5D0E6B2-A841-4C67-A0E3-92354DE07E51",
                    "UNKNOWN-73fd",
                    "Entrypoint measurement for module UNKNOWN-73fd",
                    101088.397331,
                    0.04906999999366235,
                ),
                (
                    229,
                    "LoadImage",
                    "B8BA8298-AF29-4FA3-9D10-27A8478BB6A7",
                    "UNKNOWN-0c43",
                    "LoadImage measurement for module UNKNOWN-0c43",
                    101088.60542,
                    1.7235559999971883,
                ),
                (
                    230,
                    "Entrypoint",
                    "B8BA8298-AF29-4FA3-9D10-27A8478BB6A7",
                    "UNKNOWN-0c43",
                    "Entrypoint measurement for module UNKNOWN-0c43",
                    101093.095561,
                    0.03191700000024866,
                ),
                (
                    231,
                    "LoadImage",
                    "4BD0EB2F-3A2D-442E-822D-753516F75424",
                    "UNKNOWN-ea31",
                    "LoadImage measurement for module UNKNOWN-ea31",
                    101095.917231,
                    0.25854399999661837,
                ),
                (
                    232,
                    "Entrypoint",
                    "4BD0EB2F-3A2D-442E-822D-753516F75424",
                    "UNKNOWN-ea31",
                    "Entrypoint measurement for module UNKNOWN-ea31",
                    101098.941766,
                    0.2547139999951469,
                ),
                (
                    233,
                    "LoadImage",
                    "F099D67F-71AE-4C36-B2A3-DCEB0EB2B7D8",
                    "UNKNOWN-1596",
                    "LoadImage measurement for module UNKNOWN-1596",
                    101101.762863,
                    0.263598000005004,
                ),
                (
                    234,
                    "Entrypoint",
                    "F099D67F-71AE-4C36-B2A3-DCEB0EB2B7D8",
                    "UNKNOWN-1596",
                    "Entrypoint measurement for module UNKNOWN-1596",
                    101104.783364,
                    0.04222899999876972,
                ),
                (
                    235,
                    "LoadImage",
                    "9F7DCADE-11EA-448A-A46F-76E003657DD1",
                    "UNKNOWN-678c",
                    "LoadImage measurement for module UNKNOWN-678c",
                    101107.609658,
                    0.2914969999983441,
                ),
                (
                    241,
                    "Entrypoint",
                    "9F7DCADE-11EA-448A-A46F-76E003657DD1",
                    "UNKNOWN-678c",
                    "Entrypoint measurement for module UNKNOWN-678c",
                    101110.632357,
                    7.209412000011071,
                ),
                (
                    236,
                    "Function",
                    "E9BADBB6-0228-43FB-A367-5F3677CDC9E0",
                    "UNKNOWN-ff3d",
                    "Function measurement from module UNKNOWN-ff3d with label EvaluateRequestedRegion",
                    101111.124623,
                    0.9083300000056624,
                ),
                (
                    237,
                    "Function",
                    "E9BADBB6-0228-43FB-A367-5F3677CDC9E0",
                    "UNKNOWN-ff3d",
                    "Function measurement from module UNKNOWN-ff3d with label EvaluateRequestedRegion",
                    101112.298724,
                    0.9038850000069942,
                ),
                (
                    238,
                    "Function",
                    "E9BADBB6-0228-43FB-A367-5F3677CDC9E0",
                    "UNKNOWN-ff3d",
                    "Function measurement from module UNKNOWN-ff3d with label EvaluateRequestedRegion",
                    101113.479193,
                    0.8192779999953927,
                ),
                (
                    239,
                    "Function",
                    "E9BADBB6-0228-43FB-A367-5F3677CDC9E0",
                    "UNKNOWN-ff3d",
                    "Function measurement from module UNKNOWN-ff3d with label EvaluateRequestedRegion",
                    101114.607366,
                    0.8193699999974342,
                ),
                (
                    240,
                    "Function",
                    "E9BADBB6-0228-43FB-A367-5F3677CDC9E0",
                    "UNKNOWN-ff3d",
                    "Function measurement from module UNKNOWN-ff3d with label EvaluateRequestedRegion",
                    101115.570077,
                    0.8152399999962654,
                ),
                (
                    242,
                    "LoadImage",
                    "94C210EA-3113-4563-ADEB-76FE759C2F46",
                    "UNKNOWN-b5e3",
                    "LoadImage measurement for module UNKNOWN-b5e3",
                    101117.897305,
                    0.20440899999812245,
                ),
                (
                    243,
                    "Entrypoint",
                    "94C210EA-3113-4563-ADEB-76FE759C2F46",
                    "UNKNOWN-b5e3",
                    "Entrypoint measurement for module UNKNOWN-b5e3",
                    101118.178953,
                    0.04444500000681728,
                ),
                (
                    244,
                    "LoadImage",
                    "987555D6-595D-4CFA-B895-59B89368BD4D",
                    "UNKNOWN-113d",
                    "LoadImage measurement for module UNKNOWN-113d",
                    101120.208581,
                    0.25926500000059605,
                ),
                (
                    245,
                    "Entrypoint",
                    "987555D6-595D-4CFA-B895-59B89368BD4D",
                    "UNKNOWN-113d",
                    "Entrypoint measurement for module UNKNOWN-113d",
                    101123.230778,
                    0.03915900000720285,
                ),
                (
                    246,
                    "LoadImage",
                    "3C4836AE-B24B-40E3-B24B-9448ED095BFE",
                    "UNKNOWN-2e25",
                    "LoadImage measurement for module UNKNOWN-2e25",
                    101126.0596,
                    0.2633180000120774,
                ),
                (
                    247,
                    "Entrypoint",
                    "3C4836AE-B24B-40E3-B24B-9448ED095BFE",
                    "UNKNOWN-2e25",
                    "Entrypoint measurement for module UNKNOWN-2e25",
                    101129.078709,
                    0.05201400000078138,
                ),
                (
                    248,
                    "LoadImage",
                    "AD608272-D07F-4964-801E-7BD3B7888652",
                    "UNKNOWN-38b8",
                    "LoadImage measurement for module UNKNOWN-38b8",
                    101131.999018,
                    0.24959099999978207,
                ),
                (
                    249,
                    "Entrypoint",
                    "AD608272-D07F-4964-801E-7BD3B7888652",
                    "UNKNOWN-38b8",
                    "Entrypoint measurement for module UNKNOWN-38b8",
                    101134.921708,
                    1.3199339999991935,
                ),
                (
                    250,
                    "LoadImage",
                    "378D7B65-8DA9-4773-B6E4-A47826A833E1",
                    "UNKNOWN-23c1",
                    "LoadImage measurement for module UNKNOWN-23c1",
                    101137.74776,
                    0.2888329999987036,
                ),
                (
                    251,
                    "Entrypoint",
                    "378D7B65-8DA9-4773-B6E4-A47826A833E1",
                    "UNKNOWN-23c1",
                    "Entrypoint measurement for module UNKNOWN-23c1",
                    101140.768086,
                    4.140689000007114,
                ),
                (
                    252,
                    "LoadImage",
                    "8C7DB881-DA76-4486-8654-8152EE3470A3",
                    "UNKNOWN-b280",
                    "LoadImage measurement for module UNKNOWN-b280",
                    101144.964191,
                    0.23842599999625236,
                ),
                (
                    253,
                    "Entrypoint",
                    "8C7DB881-DA76-4486-8654-8152EE3470A3",
                    "UNKNOWN-b280",
                    "Entrypoint measurement for module UNKNOWN-b280",
                    101146.613002,
                    0.5674100000032922,
                ),
                (
                    254,
                    "LoadImage",
                    "A899D6C5-9472-40B7-82AA-D1B826374502",
                    "UNKNOWN-2849",
                    "LoadImage measurement for module UNKNOWN-2849",
                    101149.446063,
                    0.25953799999842886,
                ),
                (
                    256,
                    "Entrypoint",
                    "A899D6C5-9472-40B7-82AA-D1B826374502",
                    "UNKNOWN-2849",
                    "Entrypoint measurement for module UNKNOWN-2849",
                    101152.457523,
                    0.34045299999706913,
                ),
                (
                    255,
                    "Function",
                    "A899D6C5-9472-40B7-82AA-D1B826374502",
                    "UNKNOWN-2849",
                    "Function measurement from module UNKNOWN-2849 with label SaveBootPathReasonHobsT",
                    101152.739134,
                    0.018018999995547347,
                ),
                (
                    257,
                    "LoadImage",
                    "B783ADE6-D27E-49DA-9C3A-6D91502642F4",
                    "UNKNOWN-d2cb",
                    "LoadImage measurement for module UNKNOWN-d2cb",
                    101155.287371,
                    0.26086100000247825,
                ),
                (
                    258,
                    "Entrypoint",
                    "B783ADE6-D27E-49DA-9C3A-6D91502642F4",
                    "UNKNOWN-d2cb",
                    "Entrypoint measurement for module UNKNOWN-d2cb",
                    101158.310159,
                    1.4307169999956386,
                ),
                (
                    259,
                    "LoadImage",
                    "E0ECBEC9-B193-4351-A488-36A655F22F9F",
                    "UNKNOWN-5b37",
                    "LoadImage measurement for module UNKNOWN-5b37",
                    101161.129905,
                    0.2649600000004284,
                ),
                (
                    260,
                    "Entrypoint",
                    "E0ECBEC9-B193-4351-A488-36A655F22F9F",
                    "UNKNOWN-5b37",
                    "Entrypoint measurement for module UNKNOWN-5b37",
                    101164.145239,
                    37.29956699999457,
                ),
                (
                    261,
                    "LoadImage",
                    "A88BBFFC-2964-48A2-A9AA-25FCFC9EB7DF",
                    "UNKNOWN-0e86",
                    "LoadImage measurement for module UNKNOWN-0e86",
                    101201.50121,
                    0.20833399999537505,
                ),
                (
                    262,
                    "Entrypoint",
                    "A88BBFFC-2964-48A2-A9AA-25FCFC9EB7DF",
                    "UNKNOWN-0e86",
                    "Entrypoint measurement for module UNKNOWN-0e86",
                    101202.279436,
                    0.299752000006265,
                ),
                (
                    263,
                    "LoadImage",
                    "5CD9649D-2874-4834-802B-C559C94703AE",
                    "UNKNOWN-6855",
                    "LoadImage measurement for module UNKNOWN-6855",
                    101205.114807,
                    0.272754999998142,
                ),
                (
                    264,
                    "Entrypoint",
                    "5CD9649D-2874-4834-802B-C559C94703AE",
                    "UNKNOWN-6855",
                    "Entrypoint measurement for module UNKNOWN-6855",
                    101208.13287,
                    176.0751900000032,
                ),
                (
                    265,
                    "LoadImage",
                    "CA84408A-0929-4F11-BFED-18C7D9576C6B",
                    "UNKNOWN-95ea",
                    "LoadImage measurement for module UNKNOWN-95ea",
                    101386.980567,
                    0.21026799999526702,
                ),
                (
                    266,
                    "Entrypoint",
                    "CA84408A-0929-4F11-BFED-18C7D9576C6B",
                    "UNKNOWN-95ea",
                    "Entrypoint measurement for module UNKNOWN-95ea",
                    101389.933915,
                    0.06673099999898113,
                ),
                (
                    267,
                    "LoadImage",
                    "6DB9486F-6AF6-4090-984D-238482CE3EA4",
                    "UNKNOWN-ff72",
                    "LoadImage measurement for module UNKNOWN-ff72",
                    101392.75459,
                    0.2630070000013802,
                ),
                (
                    268,
                    "Entrypoint",
                    "6DB9486F-6AF6-4090-984D-238482CE3EA4",
                    "UNKNOWN-ff72",
                    "Entrypoint measurement for module UNKNOWN-ff72",
                    101395.777319,
                    0.026243000000249594,
                ),
                (
                    269,
                    "LoadImage",
                    "1CD7E617-1566-421C-A41C-9C04497BFA75",
                    "UNKNOWN-db07",
                    "LoadImage measurement for module UNKNOWN-db07",
                    101398.604575,
                    0.2578619999985676,
                ),
                (
                    270,
                    "Entrypoint",
                    "1CD7E617-1566-421C-A41C-9C04497BFA75",
                    "UNKNOWN-db07",
                    "Entrypoint measurement for module UNKNOWN-db07",
                    101401.616591,
                    0.8935840000049211,
                ),
                (
                    271,
                    "LoadImage",
                    "5EAE05D8-2BB5-4CC3-9CAD-BBD305EA0821",
                    "UNKNOWN-ba47",
                    "LoadImage measurement for module UNKNOWN-ba47",
                    101404.448058,
                    0.26758100000733975,
                ),
                (
                    272,
                    "Entrypoint",
                    "5EAE05D8-2BB5-4CC3-9CAD-BBD305EA0821",
                    "UNKNOWN-ba47",
                    "Entrypoint measurement for module UNKNOWN-ba47",
                    101407.47009,
                    4.636727000004612,
                ),
                (
                    273,
                    "LoadImage",
                    "87BAB24A-5E58-44F3-B961-AA43E7CE5FC9",
                    "UNKNOWN-92e5",
                    "LoadImage measurement for module UNKNOWN-92e5",
                    101414.7784,
                    0.2636880000063684,
                ),
                (
                    274,
                    "Entrypoint",
                    "87BAB24A-5E58-44F3-B961-AA43E7CE5FC9",
                    "UNKNOWN-92e5",
                    "Entrypoint measurement for module UNKNOWN-92e5",
                    101417.788069,
                    0.02907000000413973,
                ),
                (
                    275,
                    "LoadImage",
                    "F9D88642-0737-49BC-81B5-6889CD57D9EA",
                    "UNKNOWN-3178",
                    "LoadImage measurement for module UNKNOWN-3178",
                    101420.621369,
                    0.26268200000049546,
                ),
                (
                    276,
                    "Entrypoint",
                    "F9D88642-0737-49BC-81B5-6889CD57D9EA",
                    "UNKNOWN-3178",
                    "Entrypoint measurement for module UNKNOWN-3178",
                    101423.642476,
                    7.242848000008962,
                ),
                (
                    277,
                    "LoadImage",
                    "FDFF263D-5F68-4591-87BA-B768F445A9AF",
                    "UNKNOWN-de3d",
                    "LoadImage measurement for module UNKNOWN-de3d",
                    101433.670545,
                    0.2703079999919282,
                ),
                (
                    278,
                    "Entrypoint",
                    "FDFF263D-5F68-4591-87BA-B768F445A9AF",
                    "UNKNOWN-de3d",
                    "Entrypoint measurement for module UNKNOWN-de3d",
                    101436.699387,
                    9.538948999994318,
                ),
                (
                    279,
                    "LoadImage",
                    "2552C00F-3CE4-4B17-915C-369A014A4CAE",
                    "UNKNOWN-8fb1",
                    "LoadImage measurement for module UNKNOWN-8fb1",
                    101446.294564,
                    0.29018700000597164,
                ),
                (
                    280,
                    "Entrypoint",
                    "2552C00F-3CE4-4B17-915C-369A014A4CAE",
                    "UNKNOWN-8fb1",
                    "Entrypoint measurement for module UNKNOWN-8fb1",
                    101446.664604,
                    7.9573269999964396,
                ),
                (
                    281,
                    "LoadImage",
                    "9569E910-79D1-45D4-BB86-A85C92AFC04F",
                    "UNKNOWN-e09f",
                    "LoadImage measurement for module UNKNOWN-e09f",
                    101457.180247,
                    0.26436699999612756,
                ),
                (
                    282,
                    "Entrypoint",
                    "9569E910-79D1-45D4-BB86-A85C92AFC04F",
                    "UNKNOWN-e09f",
                    "Entrypoint measurement for module UNKNOWN-e09f",
                    101460.204848,
                    23.193608000001404,
                ),
                (
                    283,
                    "LoadImage",
                    "C92652E3-C7DE-4C78-9577-1C897C51BFFA",
                    "UNKNOWN-03c2",
                    "LoadImage measurement for module UNKNOWN-03c2",
                    101484.430342,
                    1.9529589999874588,
                ),
                (
                    284,
                    "Entrypoint",
                    "C92652E3-C7DE-4C78-9577-1C897C51BFFA",
                    "UNKNOWN-03c2",
                    "Entrypoint measurement for module UNKNOWN-03c2",
                    101489.138032,
                    0.05709000000206288,
                ),
                (
                    285,
                    "LoadImage",
                    "65588D77-CE5A-4961-8362-8C06A3CBD0BF",
                    "UNKNOWN-e244",
                    "LoadImage measurement for module UNKNOWN-e244",
                    101491.962438,
                    1.831187999996473,
                ),
                (
                    286,
                    "Entrypoint",
                    "65588D77-CE5A-4961-8362-8C06A3CBD0BF",
                    "UNKNOWN-e244",
                    "Entrypoint measurement for module UNKNOWN-e244",
                    101496.539879,
                    0.03630199999315664,
                ),
                (
                    287,
                    "LoadImage",
                    "FF0C8745-3270-4439-B74F-3E45F8C77064",
                    "UNKNOWN-1570",
                    "LoadImage measurement for module UNKNOWN-1570",
                    101499.364827,
                    0.32717699999921024,
                ),
                (
                    288,
                    "Entrypoint",
                    "FF0C8745-3270-4439-B74F-3E45F8C77064",
                    "UNKNOWN-1570",
                    "Entrypoint measurement for module UNKNOWN-1570",
                    101502.386138,
                    0.07475699999486096,
                ),
                (
                    289,
                    "LoadImage",
                    "ACD28235-075B-48B5-98A1-DA04FCAF84F3",
                    "UNKNOWN-f491",
                    "LoadImage measurement for module UNKNOWN-f491",
                    101505.215009,
                    0.3193549999996321,
                ),
                (
                    290,
                    "Entrypoint",
                    "ACD28235-075B-48B5-98A1-DA04FCAF84F3",
                    "UNKNOWN-f491",
                    "Entrypoint measurement for module UNKNOWN-f491",
                    101508.233777,
                    1.33046800000011,
                ),
                (
                    291,
                    "LoadImage",
                    "55E76644-78A5-4A82-A900-7126A5798892",
                    "UNKNOWN-1e0e",
                    "LoadImage measurement for module UNKNOWN-1e0e",
                    101511.058718,
                    0.3007789999974193,
                ),
                (
                    292,
                    "Entrypoint",
                    "55E76644-78A5-4A82-A900-7126A5798892",
                    "UNKNOWN-1e0e",
                    "Entrypoint measurement for module UNKNOWN-1e0e",
                    101514.08275,
                    0.21618899999884889,
                ),
                (
                    293,
                    "LoadImage",
                    "D0E7EE76-3120-4241-9716-FB2657DB7130",
                    "UNKNOWN-9492",
                    "LoadImage measurement for module UNKNOWN-9492",
                    101516.900247,
                    0.31015499999921303,
                ),
                (
                    294,
                    "Entrypoint",
                    "D0E7EE76-3120-4241-9716-FB2657DB7130",
                    "UNKNOWN-9492",
                    "Entrypoint measurement for module UNKNOWN-9492",
                    101519.930263,
                    0.03879999999480788,
                ),
                (
                    295,
                    "LoadImage",
                    "F80E66A2-1A2C-415B-9B9C-066C1F04B626",
                    "UNKNOWN-4e6e",
                    "LoadImage measurement for module UNKNOWN-4e6e",
                    101522.746528,
                    0.3011160000023665,
                ),
                (
                    296,
                    "Entrypoint",
                    "F80E66A2-1A2C-415B-9B9C-066C1F04B626",
                    "UNKNOWN-4e6e",
                    "Entrypoint measurement for module UNKNOWN-4e6e",
                    101525.767619,
                    0.12561499999719672,
                ),
                (
                    297,
                    "LoadImage",
                    "E66B2A25-4759-4D56-AEA6-E164E2CD49C3",
                    "UNKNOWN-1dbc",
                    "LoadImage measurement for module UNKNOWN-1dbc",
                    101528.599588,
                    0.30240100000810344,
                ),
                (
                    298,
                    "Entrypoint",
                    "E66B2A25-4759-4D56-AEA6-E164E2CD49C3",
                    "UNKNOWN-1dbc",
                    "Entrypoint measurement for module UNKNOWN-1dbc",
                    101531.612611,
                    0.045685999997658655,
                ),
                (
                    299,
                    "LoadImage",
                    "0D4BBF18-C2CC-4C23-BD63-BFDAD4C710D0",
                    "UNKNOWN-8ef2",
                    "LoadImage measurement for module UNKNOWN-8ef2",
                    101534.447354,
                    0.3014560000010533,
                ),
                (
                    301,
                    "Entrypoint",
                    "0D4BBF18-C2CC-4C23-BD63-BFDAD4C710D0",
                    "UNKNOWN-8ef2",
                    "Entrypoint measurement for module UNKNOWN-8ef2",
                    101537.464472,
                    2.9955779999872902,
                ),
                (
                    300,
                    "Function",
                    "E9BADBB6-0228-43FB-A367-5F3677CDC9E0",
                    "UNKNOWN-ff3d",
                    "Function measurement from module UNKNOWN-ff3d with label EvaluateRequestedRegion",
                    101539.069548,
                    0.8411679999990156,
                ),
                (
                    302,
                    "LoadImage",
                    "4D9E6909-A07E-494E-939C-6A3ACC579F4C",
                    "UNKNOWN-ecbb",
                    "LoadImage measurement for module UNKNOWN-ecbb",
                    101540.515638,
                    0.315136999997776,
                ),
                (
                    303,
                    "Entrypoint",
                    "4D9E6909-A07E-494E-939C-6A3ACC579F4C",
                    "UNKNOWN-ecbb",
                    "Entrypoint measurement for module UNKNOWN-ecbb",
                    101543.310584,
                    0.04631399999198038,
                ),
                (
                    304,
                    "LoadImage",
                    "6D33944A-EC75-4855-A54D-809C75241F6C",
                    "UNKNOWN-b2b2",
                    "LoadImage measurement for module UNKNOWN-b2b2",
                    101546.135237,
                    0.42785100000037346,
                ),
                (
                    305,
                    "Entrypoint",
                    "6D33944A-EC75-4855-A54D-809C75241F6C",
                    "UNKNOWN-b2b2",
                    "Entrypoint measurement for module UNKNOWN-b2b2",
                    101549.159547,
                    0.3879099999903701,
                ),
                (
                    306,
                    "LoadImage",
                    "AD416CE3-A483-45B1-94C2-4B4E4D575562",
                    "UNKNOWN-35e1",
                    "LoadImage measurement for module UNKNOWN-35e1",
                    101551.977426,
                    0.29875699999684,
                ),
                (
                    307,
                    "Entrypoint",
                    "AD416CE3-A483-45B1-94C2-4B4E4D575562",
                    "UNKNOWN-35e1",
                    "Entrypoint measurement for module UNKNOWN-35e1",
                    101554.99926,
                    0.03563100000610575,
                ),
                (
                    308,
                    "LoadImage",
                    "5CAB08D5-AD8F-4D8B-B828-D17A8D9FE977",
                    "UNKNOWN-6ad8",
                    "LoadImage measurement for module UNKNOWN-6ad8",
                    101557.828787,
                    0.2996409999905154,
                ),
                (
                    309,
                    "Entrypoint",
                    "5CAB08D5-AD8F-4D8B-B828-D17A8D9FE977",
                    "UNKNOWN-6ad8",
                    "Entrypoint measurement for module UNKNOWN-6ad8",
                    101560.841784,
                    0.02669400000013411,
                ),
                (
                    310,
                    "LoadImage",
                    "C642C14C-0E9C-4AEF-94A5-A213BAA35DE0",
                    "UNKNOWN-5404",
                    "LoadImage measurement for module UNKNOWN-5404",
                    101563.66938,
                    0.2995479999954114,
                ),
                (
                    311,
                    "Entrypoint",
                    "C642C14C-0E9C-4AEF-94A5-A213BAA35DE0",
                    "UNKNOWN-5404",
                    "Entrypoint measurement for module UNKNOWN-5404",
                    101566.694554,
                    0.0783030000020517,
                ),
                (
                    312,
                    "LoadImage",
                    "60740CF3-D428-4500-80E6-04A5798241ED",
                    "UNKNOWN-bbe9",
                    "LoadImage measurement for module UNKNOWN-bbe9",
                    101569.515519,
                    0.35780900000827387,
                ),
                (
                    313,
                    "Entrypoint",
                    "60740CF3-D428-4500-80E6-04A5798241ED",
                    "UNKNOWN-bbe9",
                    "Entrypoint measurement for module UNKNOWN-bbe9",
                    101572.541137,
                    0.041817000004812144,
                ),
                (
                    314,
                    "LoadImage",
                    "204BF894-3B78-4F57-B051-92F8E10679CF",
                    "UNKNOWN-30e3",
                    "LoadImage measurement for module UNKNOWN-30e3",
                    101575.360159,
                    0.316781000001356,
                ),
                (
                    315,
                    "Entrypoint",
                    "204BF894-3B78-4F57-B051-92F8E10679CF",
                    "UNKNOWN-30e3",
                    "Entrypoint measurement for module UNKNOWN-30e3",
                    101578.379142,
                    0.2859199999948032,
                ),
                (
                    316,
                    "LoadImage",
                    "93B80004-9FB3-11D4-9A3A-0090273FC14D",
                    "UNKNOWN-6fea",
                    "LoadImage measurement for module UNKNOWN-6fea",
                    101581.232305,
                    0.29822100000455976,
                ),
                (
                    317,
                    "Entrypoint",
                    "93B80004-9FB3-11D4-9A3A-0090273FC14D",
                    "UNKNOWN-6fea",
                    "Entrypoint measurement for module UNKNOWN-6fea",
                    101584.227543,
                    0.1235140000062529,
                ),
                (
                    318,
                    "LoadImage",
                    "B8E62775-BB0A-43F0-A843-5BE8B14F8CCD",
                    "UNKNOWN-a6b4",
                    "LoadImage measurement for module UNKNOWN-a6b4",
                    101587.058423,
                    0.30257900001015514,
                ),
                (
                    319,
                    "Entrypoint",
                    "B8E62775-BB0A-43F0-A843-5BE8B14F8CCD",
                    "UNKNOWN-a6b4",
                    "Entrypoint measurement for module UNKNOWN-a6b4",
                    101590.072056,
                    0.10443500000110362,
                ),
                (
                    320,
                    "LoadImage",
                    "240612B7-A063-11D4-9A3A-0090273FC14D",
                    "UNKNOWN-1ada",
                    "LoadImage measurement for module UNKNOWN-1ada",
                    101592.896484,
                    0.3185820000071544,
                ),
                (
                    321,
                    "Entrypoint",
                    "240612B7-A063-11D4-9A3A-0090273FC14D",
                    "UNKNOWN-1ada",
                    "Entrypoint measurement for module UNKNOWN-1ada",
                    101595.924519,
                    0.043582000012975186,
                ),
                (
                    322,
                    "LoadImage",
                    "B7F50E91-A759-412C-ADE4-DCD03E7F7C28",
                    "UNKNOWN-38a5",
                    "LoadImage measurement for module UNKNOWN-38a5",
                    101598.745781,
                    0.32570399998803623,
                ),
                (
                    323,
                    "Entrypoint",
                    "B7F50E91-A759-412C-ADE4-DCD03E7F7C28",
                    "UNKNOWN-38a5",
                    "Entrypoint measurement for module UNKNOWN-38a5",
                    101601.763865,
                    0.05341300000145566,
                ),
                (
                    324,
                    "LoadImage",
                    "2D2E62CF-9ECF-43B7-8219-94E7FC713DFE",
                    "UNKNOWN-7535",
                    "LoadImage measurement for module UNKNOWN-7535",
                    101604.59565,
                    0.3422089999949094,
                ),
                (
                    325,
                    "Entrypoint",
                    "2D2E62CF-9ECF-43B7-8219-94E7FC713DFE",
                    "UNKNOWN-7535",
                    "Entrypoint measurement for module UNKNOWN-7535",
                    101607.612765,
                    0.045478000000002794,
                ),
                (
                    326,
                    "LoadImage",
                    "4EA43463-747C-46EB-97FB-B0E5C5F05306",
                    "UNKNOWN-a010",
                    "LoadImage measurement for module UNKNOWN-a010",
                    101610.435691,
                    0.31829799999832176,
                ),
                (
                    327,
                    "Entrypoint",
                    "4EA43463-747C-46EB-97FB-B0E5C5F05306",
                    "UNKNOWN-a010",
                    "Entrypoint measurement for module UNKNOWN-a010",
                    101613.453734,
                    0.045259999998961575,
                ),
                (
                    328,
                    "LoadImage",
                    "5BE3BDF4-53CF-46A3-A6A9-73C34A6E5EE3",
                    "UNKNOWN-729e",
                    "LoadImage measurement for module UNKNOWN-729e",
                    101616.278126,
                    0.32835399999748915,
                ),
                (
                    329,
                    "Entrypoint",
                    "5BE3BDF4-53CF-46A3-A6A9-73C34A6E5EE3",
                    "UNKNOWN-729e",
                    "Entrypoint measurement for module UNKNOWN-729e",
                    101619.305914,
                    0.060693000006722286,
                ),
                (
                    330,
                    "LoadImage",
                    "CD3BAFB6-50FB-4FE8-8E4E-AB74D2C1A600",
                    "UNKNOWN-381e",
                    "LoadImage measurement for module UNKNOWN-381e",
                    101622.125544,
                    0.3237280000030296,
                ),
                (
                    331,
                    "Entrypoint",
                    "CD3BAFB6-50FB-4FE8-8E4E-AB74D2C1A600",
                    "UNKNOWN-381e",
                    "Entrypoint measurement for module UNKNOWN-381e",
                    101625.151438,
                    0.10588000000279862,
                ),
                (
                    332,
                    "LoadImage",
                    "6B38F7B4-AD98-40E9-9093-ACA2B5A253C4",
                    "UNKNOWN-af0e",
                    "LoadImage measurement for module UNKNOWN-af0e",
                    101627.977014,
                    0.3187249999900814,
                ),
                (
                    333,
                    "Entrypoint",
                    "6B38F7B4-AD98-40E9-9093-ACA2B5A253C4",
                    "UNKNOWN-af0e",
                    "Entrypoint measurement for module UNKNOWN-af0e",
                    101630.995955,
                    0.04495399999723304,
                ),
                (
                    334,
                    "LoadImage",
                    "1FA1F39E-FEFF-4AAE-BD7B-38A070A3B609",
                    "UNKNOWN-f116",
                    "LoadImage measurement for module UNKNOWN-f116",
                    101633.81904,
                    0.3263089999963995,
                ),
                (
                    335,
                    "Entrypoint",
                    "1FA1F39E-FEFF-4AAE-BD7B-38A070A3B609",
                    "UNKNOWN-f116",
                    "Entrypoint measurement for module UNKNOWN-f116",
                    101636.845013,
                    0.04365200000756886,
                ),
                (
                    336,
                    "LoadImage",
                    "961578FE-B6B7-44C3-AF35-6BC705CD2B1F",
                    "UNKNOWN-8e9c",
                    "LoadImage measurement for module UNKNOWN-8e9c",
                    101639.666892,
                    0.3510810000007041,
                ),
                (
                    337,
                    "Entrypoint",
                    "961578FE-B6B7-44C3-AF35-6BC705CD2B1F",
                    "UNKNOWN-8e9c",
                    "Entrypoint measurement for module UNKNOWN-8e9c",
                    101642.681643,
                    0.04629199999908451,
                ),
                (
                    338,
                    "LoadImage",
                    "51CCF399-4FDF-4E55-A45B-E123F84D456A",
                    "UNKNOWN-c239",
                    "LoadImage measurement for module UNKNOWN-c239",
                    101645.505792,
                    0.325555000003078,
                ),
                (
                    339,
                    "Entrypoint",
                    "51CCF399-4FDF-4E55-A45B-E123F84D456A",
                    "UNKNOWN-c239",
                    "Entrypoint measurement for module UNKNOWN-c239",
                    101648.531769,
                    0.3935160000110045,
                ),
                (
                    340,
                    "LoadImage",
                    "408EDCEC-CF6D-477C-A5A8-B4844E3DE281",
                    "UNKNOWN-53e4",
                    "LoadImage measurement for module UNKNOWN-53e4",
                    101651.357407,
                    0.3331389999948442,
                ),
                (
                    341,
                    "Entrypoint",
                    "408EDCEC-CF6D-477C-A5A8-B4844E3DE281",
                    "UNKNOWN-53e4",
                    "Entrypoint measurement for module UNKNOWN-53e4",
                    101654.378535,
                    0.7608110000001034,
                ),
                (
                    342,
                    "LoadImage",
                    "CCCB0C28-4B24-11D5-9A5A-0090273FC14D",
                    "UNKNOWN-ae1b",
                    "LoadImage measurement for module UNKNOWN-ae1b",
                    101657.200946,
                    0.33801999999559484,
                ),
                (
                    343,
                    "Entrypoint",
                    "CCCB0C28-4B24-11D5-9A5A-0090273FC14D",
                    "UNKNOWN-ae1b",
                    "Entrypoint measurement for module UNKNOWN-ae1b",
                    101660.224689,
                    0.1359400000073947,
                ),
                (
                    423,
                    "Crossmodule",
                    "6D33944A-EC75-4855-A54D-809C75241F6C, 6D33944A-EC75-4855-A54D-809C75241F6C",
                    "UNKNOWN-b2b2, UNKNOWN-b2b2",
                    "Crossmodule measurement from UNKNOWN-b2b2 to UNKNOWN-b2b2 with label BDS",
                    101665.880138,
                    2299.918683000011,
                ),
                (
                    354,
                    "Inmodule",
                    "6D33944A-EC75-4855-A54D-809C75241F6C",
                    "UNKNOWN-b2b2",
                    "Inmodule measurement from module UNKNOWN-b2b2 with label PlatformBootManagerBefo",
                    101669.283726,
                    371.40430000000924,
                ),
                (
                    347,
                    "Function",
                    "6D33944A-EC75-4855-A54D-809C75241F6C",
                    "UNKNOWN-b2b2",
                    "Function measurement from module UNKNOWN-b2b2 with label ConnectRootBridge",
                    101669.498183,
                    46.35757300000114,
                ),
                (
                    346,
                    "BindingStart",
                    "93B80004-9FB3-11D4-9A3A-0090273FC14D",
                    "UNKNOWN-6fea",
                    "BindingStart measurement for module UNKNOWN-6fea and device PciRoot(0x0)",
                    101669.606815,
                    46.121592999988934,
                ),
                (
                    348,
                    "BindingStart",
                    "FF0C8745-3270-4439-B74F-3E45F8C77064",
                    "UNKNOWN-1570",
                    "BindingStart measurement for module UNKNOWN-1570 and device PciRoot(0x0)/Pci(0x2,0x0)",
                    101716.268368,
                    287.5453089999937,
                ),
                (
                    349,
                    "BindingStart",
                    "CCCB0C28-4B24-11D5-9A5A-0090273FC14D",
                    "UNKNOWN-ae1b",
                    "BindingStart measurement for module UNKNOWN-ae1b and device PciRoot(0x0)/Pci(0x2,0x0)/AcpiAdr(0x80011400)",
                    102003.966204,
                    0.11015300000144634,
                ),
                (
                    350,
                    "BindingStart",
                    "51CCF399-4FDF-4E55-A45B-E123F84D456A",
                    "UNKNOWN-c239",
                    "BindingStart measurement for module UNKNOWN-c239 and device PciRoot(0x0)/Pci(0x2,0x0)/AcpiAdr(0x80011400)",
                    102004.172434,
                    0.6423730000096839,
                ),
                (
                    351,
                    "BindingStart",
                    "408EDCEC-CF6D-477C-A5A8-B4844E3DE281",
                    "UNKNOWN-53e4",
                    "BindingStart measurement for module UNKNOWN-53e4 and device PciRoot(0x0)/Pci(0x2,0x0)/AcpiAdr(0x80011400)",
                    102004.914652,
                    0.16165699998964556,
                ),
                (
                    353,
                    "Function",
                    "6D33944A-EC75-4855-A54D-809C75241F6C",
                    "UNKNOWN-b2b2",
                    "Function measurement from module UNKNOWN-b2b2 with label ExitPmAuth",
                    102005.639493,
                    35.02453799999785,
                ),
                (
                    352,
                    "Callback",
                    "02CE967A-DD7E-4FFC-9EE7-810CF0470880, A88BBFFC-2964-48A2-A9AA-25FCFC9EB7DF",
                    "UNKNOWN-74ec, UNKNOWN-0e86",
                    "Callback measurement from module UNKNOWN-74ec and trigger/event UNKNOWN-0e86",
                    102021.072345,
                    10.479946000006748,
                ),
                (
                    357,
                    "Inmodule",
                    "6D33944A-EC75-4855-A54D-809C75241F6C",
                    "UNKNOWN-b2b2",
                    "Inmodule measurement from module UNKNOWN-b2b2 with label EfiBootManagerConnectAl",
                    102040.702563,
                    0.4486780000006547,
                ),
                (
                    355,
                    "BindingStart",
                    "FF0C8745-3270-4439-B74F-3E45F8C77064",
                    "UNKNOWN-1570",
                    "BindingStart measurement for module UNKNOWN-1570 and device PciRoot(0x0)/Pci(0x2,0x0)",
                    102040.827474,
                    0.0016069999983301386,
                ),
                (
                    356,
                    "BindingStart",
                    "FF0C8745-3270-4439-B74F-3E45F8C77064",
                    "UNKNOWN-1570",
                    "BindingStart measurement for module UNKNOWN-1570 and device PciRoot(0x0)/Pci(0x2,0x0)",
                    102040.923775,
                    0.017924999992828816,
                ),
                (
                    360,
                    "Inmodule",
                    "6D33944A-EC75-4855-A54D-809C75241F6C",
                    "UNKNOWN-b2b2",
                    "Inmodule measurement from module UNKNOWN-b2b2 with label PlatformBootManagerAfte",
                    102041.152132,
                    2.3371559999941383,
                ),
                (
                    359,
                    "Function",
                    "6D33944A-EC75-4855-A54D-809C75241F6C",
                    "UNKNOWN-b2b2",
                    "Function measurement from module UNKNOWN-b2b2 with label ConnectSequence",
                    102043.451875,
                    0.03651000000536442,
                ),
                (
                    358,
                    "Function",
                    "D6A2CB7F-6A18-4E2F-B43B-9920A733700A",
                    "UNKNOWN-6c05",
                    "Function measurement from module UNKNOWN-6c05 with label CoreDispatcher",
                    102043.453409,
                    0.03413100000761915,
                ),
                (
                    361,
                    "Inmodule",
                    "6D33944A-EC75-4855-A54D-809C75241F6C",
                    "UNKNOWN-b2b2",
                    "Inmodule measurement from module UNKNOWN-b2b2 with label BdsWait",
                    102043.878935,
                    0.001915999993798323,
                ),
                (
                    362,
                    "EventSignal",
                    "7B94C75C-36A4-4AA4-A1DF-14BC9A049AE4, 6D33944A-EC75-4855-A54D-809C75241F6C",
                    "UNKNOWN-e6c5, UNKNOWN-b2b2",
                    "EventSignal measurement from module UNKNOWN-e6c5 and trigger/event UNKNOWN-b2b2",
                    102044.441013,
                    0.019938999990699813,
                ),
                (
                    366,
                    "EventSignal",
                    "7CE88FB3-4BD7-4679-87A8-A8D8DEE50D2B, 6D33944A-EC75-4855-A54D-809C75241F6C",
                    "UNKNOWN-331c, UNKNOWN-b2b2",
                    "EventSignal measurement from module UNKNOWN-331c and trigger/event UNKNOWN-b2b2",
                    102044.46178,
                    92.96697599999607,
                ),
                (
                    363,
                    "Function",
                    "FDFF263D-5F68-4591-87BA-B768F445A9AF",
                    "UNKNOWN-de3d",
                    "Function measurement from module UNKNOWN-de3d with label OnReadyToBoot",
                    102067.997641,
                    16.77271400000609,
                ),
                (
                    364,
                    "Callback",
                    "7CE88FB3-4BD7-4679-87A8-A8D8DEE50D2B, A88BBFFC-2964-48A2-A9AA-25FCFC9EB7DF",
                    "UNKNOWN-331c, UNKNOWN-0e86",
                    "Callback measurement from module UNKNOWN-331c and trigger/event UNKNOWN-0e86",
                    102085.393506,
                    6.196702000001096,
                ),
                (
                    365,
                    "Inmodule",
                    "06E49122-4EF4-45FE-9766-E2EAF2F9472F",
                    "UNKNOWN-0ec7",
                    "Inmodule measurement from module UNKNOWN-0ec7 with label AdvLogger All files",
                    102135.726116,
                    0.0012889999925391749,
                ),
                (
                    367,
                    "EventSignal",
                    "A5B489B4-18FD-4425-91A4-613ADDD27405, 6D33944A-EC75-4855-A54D-809C75241F6C",
                    "UNKNOWN-6b0b, UNKNOWN-b2b2",
                    "EventSignal measurement from module UNKNOWN-6b0b and trigger/event UNKNOWN-b2b2",
                    102137.429657,
                    1.0854330000001937,
                ),
                (
                    422,
                    "Inmodule",
                    "6D33944A-EC75-4855-A54D-809C75241F6C",
                    "UNKNOWN-b2b2",
                    "Inmodule measurement from module UNKNOWN-b2b2 with label BdsAttempt",
                    102138.570144,
                    1827.2277440000034,
                ),
                (
                    368,
                    "BindingStart",
                    "FF0C8745-3270-4439-B74F-3E45F8C77064",
                    "UNKNOWN-1570",
                    "BindingStart measurement for module UNKNOWN-1570 and device PciRoot(0x0)/Pci(0x2,0x0)",
                    102138.763185,
                    0.0017989999905694276,
                ),
                (
                    369,
                    "BindingStart",
                    "FF0C8745-3270-4439-B74F-3E45F8C77064",
                    "UNKNOWN-1570",
                    "BindingStart measurement for module UNKNOWN-1570 and device PciRoot(0x0)/Pci(0x2,0x0)",
                    102138.848853,
                    0.01564299999154173,
                ),
                (
                    370,
                    "Event",
                    "6D33944A-EC75-4855-A54D-809C75241F6C",
                    "UNKNOWN-b2b2",
                    "Event measurement from module UNKNOWN-b2b2 with label ConOutReady",
                    102139.068659,
                    1e-06,
                ),
                (
                    371,
                    "BindingStart",
                    "B7F50E91-A759-412C-ADE4-DCD03E7F7C28",
                    "UNKNOWN-38a5",
                    "BindingStart measurement for module UNKNOWN-38a5 and device eXtensible Host Controller (USB 3.0 PciRoot(0x0)/Pci(0xD,0x0)",
                    102139.224422,
                    10.209631000005174,
                ),
                (
                    372,
                    "BindingStart",
                    "240612B7-A063-11D4-9A3A-0090273FC14D",
                    "UNKNOWN-1ada",
                    "BindingStart measurement for module UNKNOWN-1ada and device PciRoot(0x0)/Pci(0xD,0x0)",
                    102149.486208,
                    511.86449999999604,
                ),
                (
                    373,
                    "BindingStart",
                    "B7F50E91-A759-412C-ADE4-DCD03E7F7C28",
                    "UNKNOWN-38a5",
                    "BindingStart measurement for module UNKNOWN-38a5 and device eXtensible Host Controller (USB 3.0 PciRoot(0x0)/Pci(0x14,0x0)",
                    102661.721041,
                    10.158920000001672,
                ),
                (
                    377,
                    "BindingStart",
                    "240612B7-A063-11D4-9A3A-0090273FC14D",
                    "UNKNOWN-1ada",
                    "BindingStart measurement for module UNKNOWN-1ada and device PciRoot(0x0)/Pci(0x14,0x0)",
                    102671.943888,
                    1181.324077000012,
                ),
                (
                    374,
                    "BindingStart",
                    "2D2E62CF-9ECF-43B7-8219-94E7FC713DFE",
                    "UNKNOWN-7535",
                    "BindingStart measurement for module UNKNOWN-7535 and device Generic Usb Keyboar PciRoot(0x0)/Pci(0x14,0x0)/USB(0x5,0x0)/USB(0x0,0x0)",
                    103424.08923,
                    10.233236000000034,
                ),
                (
                    375,
                    "BindingStart",
                    "51CCF399-4FDF-4E55-A45B-E123F84D456A",
                    "UNKNOWN-c239",
                    "BindingStart measurement for module UNKNOWN-c239 and device PciRoot(0x0)/Pci(0x14,0x0)/USB(0x5,0x0)/USB(0x0,0x0)",
                    103434.431045,
                    0.35919999999168795,
                ),
                (
                    376,
                    "BindingStart",
                    "408EDCEC-CF6D-477C-A5A8-B4844E3DE281",
                    "UNKNOWN-53e4",
                    "BindingStart measurement for module UNKNOWN-53e4 and device PciRoot(0x0)/Pci(0x14,0x0)/USB(0x5,0x0)/USB(0x0,0x0)",
                    103434.900325,
                    0.9757930000050692,
                ),
                (
                    378,
                    "Event",
                    "6D33944A-EC75-4855-A54D-809C75241F6C",
                    "UNKNOWN-b2b2",
                    "Event measurement from module UNKNOWN-b2b2 with label ConInReady",
                    103853.389985,
                    1e-06,
                ),
                (
                    379,
                    "Event",
                    "6D33944A-EC75-4855-A54D-809C75241F6C",
                    "UNKNOWN-b2b2",
                    "Event measurement from module UNKNOWN-b2b2 with label ErrOutReady",
                    103853.392864,
                    1e-06,
                ),
                (
                    380,
                    "BindingStart",
                    "93B80004-9FB3-11D4-9A3A-0090273FC14D",
                    "UNKNOWN-6fea",
                    "BindingStart measurement for module UNKNOWN-6fea and device PciRoot(0x0)",
                    103862.751708,
                    0.09261100000003353,
                ),
                (
                    381,
                    "BindingStart",
                    "FF0C8745-3270-4439-B74F-3E45F8C77064",
                    "UNKNOWN-1570",
                    "BindingStart measurement for module UNKNOWN-1570 and device PciRoot(0x0)/Pci(0x2,0x0)",
                    103863.163409,
                    0.015352999995229766,
                ),
                (
                    382,
                    "BindingStart",
                    "5BE3BDF4-53CF-46A3-A6A9-73C34A6E5EE3",
                    "UNKNOWN-729e",
                    "BindingStart measurement for module UNKNOWN-729e and device NVM Express Controlle PciRoot(0x0)/Pci(0x6,0x0)/Pci(0x0,0x0)",
                    103863.760469,
                    6.965704999995069,
                ),
                (
                    383,
                    "BindingStart",
                    "6B38F7B4-AD98-40E9-9093-ACA2B5A253C4",
                    "UNKNOWN-af0e",
                    "BindingStart measurement for module UNKNOWN-af0e and device PciRoot(0x0)/Pci(0x6,0x0)/Pci(0x0,0x0)/NVMe(0x1,D5-37-1A-49-4A-44-1B-00)",
                    103870.888976,
                    0.0495939999964321,
                ),
                (
                    384,
                    "BindingStart",
                    "1FA1F39E-FEFF-4AAE-BD7B-38A070A3B609",
                    "UNKNOWN-f116",
                    "BindingStart measurement for module UNKNOWN-f116 and device PciRoot(0x0)/Pci(0x6,0x0)/Pci(0x0,0x0)/NVMe(0x1,D5-37-1A-49-4A-44-1B-00)",
                    103871.050148,
                    5.785415000005742,
                ),
                (
                    385,
                    "BindingStart",
                    "6B38F7B4-AD98-40E9-9093-ACA2B5A253C4",
                    "UNKNOWN-af0e",
                    "BindingStart measurement for module UNKNOWN-af0e and device PciRoot(0x0)/Pci(0x6,0x0)/Pci(0x0,0x0)/NVMe(0x1,D5-37-1A-49-4A-44-1B-00)/HD(1,GPT,8278E87A-6E15-40CC-9AF6-0AFAB3365E32,0x800,0x82000)",
                    103877.015142,
                    0.03648599999723956,
                ),
                (
                    386,
                    "BindingStart",
                    "1FA1F39E-FEFF-4AAE-BD7B-38A070A3B609",
                    "UNKNOWN-f116",
                    "BindingStart measurement for module UNKNOWN-f116 and device PciRoot(0x0)/Pci(0x6,0x0)/Pci(0x0,0x0)/NVMe(0x1,D5-37-1A-49-4A-44-1B-00)/HD(1,GPT,8278E87A-6E15-40CC-9AF6-0AFAB3365E32,0x800,0x82000)",
                    103877.194995,
                    2.337280000007013,
                ),
                (
                    388,
                    "BindingStart",
                    "961578FE-B6B7-44C3-AF35-6BC705CD2B1F",
                    "UNKNOWN-8e9c",
                    "BindingStart measurement for module UNKNOWN-8e9c and device FAT File Syste PciRoot(0x0)/Pci(0x6,0x0)/Pci(0x0,0x0)/NVMe(0x1,D5-37-1A-49-4A-44-1B-00)/HD(1,GPT,8278E87A-6E15-40CC-9AF6-0AFAB3365E32,0x800,0x82000)",
                    103879.664704,
                    4.901574000003166,
                ),
                (
                    387,
                    "Inmodule",
                    "06E49122-4EF4-45FE-9766-E2EAF2F9472F",
                    "UNKNOWN-0ec7",
                    "Inmodule measurement from module UNKNOWN-0ec7 with label AdvLogger All files",
                    103884.562538,
                    0.0012160000042058527,
                ),
                (
                    389,
                    "BindingStart",
                    "6B38F7B4-AD98-40E9-9093-ACA2B5A253C4",
                    "UNKNOWN-af0e",
                    "BindingStart measurement for module UNKNOWN-af0e and device PciRoot(0x0)/Pci(0x6,0x0)/Pci(0x0,0x0)/NVMe(0x1,D5-37-1A-49-4A-44-1B-00)/HD(2,GPT,78C07A1B-D442-45CB-A82A-4C43F5F5B15D,0x82800,0x8000)",
                    103884.799935,
                    0.038574999998672865,
                ),
                (
                    390,
                    "BindingStart",
                    "1FA1F39E-FEFF-4AAE-BD7B-38A070A3B609",
                    "UNKNOWN-f116",
                    "BindingStart measurement for module UNKNOWN-f116 and device PciRoot(0x0)/Pci(0x6,0x0)/Pci(0x0,0x0)/NVMe(0x1,D5-37-1A-49-4A-44-1B-00)/HD(2,GPT,78C07A1B-D442-45CB-A82A-4C43F5F5B15D,0x82800,0x8000)",
                    103884.983559,
                    2.7203600000066217,
                ),
                (
                    391,
                    "BindingStart",
                    "961578FE-B6B7-44C3-AF35-6BC705CD2B1F",
                    "UNKNOWN-8e9c",
                    "BindingStart measurement for module UNKNOWN-8e9c and device PciRoot(0x0)/Pci(0x6,0x0)/Pci(0x0,0x0)/NVMe(0x1,D5-37-1A-49-4A-44-1B-00)/HD(2,GPT,78C07A1B-D442-45CB-A82A-4C43F5F5B15D,0x82800,0x8000)",
                    103887.836274,
                    0.6398009999975329,
                ),
                (
                    392,
                    "BindingStart",
                    "6B38F7B4-AD98-40E9-9093-ACA2B5A253C4",
                    "UNKNOWN-af0e",
                    "BindingStart measurement for module UNKNOWN-af0e and device PciRoot(0x0)/Pci(0x6,0x0)/Pci(0x0,0x0)/NVMe(0x1,D5-37-1A-49-4A-44-1B-00)/HD(3,GPT,C59756F8-F924-46A3-B621-56EDC6FAA285,0x8A800,0x3B716800)",
                    103888.709024,
                    0.03813400000217371,
                ),
                (
                    393,
                    "BindingStart",
                    "1FA1F39E-FEFF-4AAE-BD7B-38A070A3B609",
                    "UNKNOWN-f116",
                    "BindingStart measurement for module UNKNOWN-f116 and device PciRoot(0x0)/Pci(0x6,0x0)/Pci(0x0,0x0)/NVMe(0x1,D5-37-1A-49-4A-44-1B-00)/HD(3,GPT,C59756F8-F924-46A3-B621-56EDC6FAA285,0x8A800,0x3B716800)",
                    103888.889739,
                    2.3282729999918956,
                ),
                (
                    394,
                    "BindingStart",
                    "961578FE-B6B7-44C3-AF35-6BC705CD2B1F",
                    "UNKNOWN-8e9c",
                    "BindingStart measurement for module UNKNOWN-8e9c and device PciRoot(0x0)/Pci(0x6,0x0)/Pci(0x0,0x0)/NVMe(0x1,D5-37-1A-49-4A-44-1B-00)/HD(3,GPT,C59756F8-F924-46A3-B621-56EDC6FAA285,0x8A800,0x3B716800)",
                    103891.349538,
                    0.6414829999994254,
                ),
                (
                    395,
                    "BindingStart",
                    "6B38F7B4-AD98-40E9-9093-ACA2B5A253C4",
                    "UNKNOWN-af0e",
                    "BindingStart measurement for module UNKNOWN-af0e and device PciRoot(0x0)/Pci(0x6,0x0)/Pci(0x0,0x0)/NVMe(0x1,D5-37-1A-49-4A-44-1B-00)/HD(4,GPT,AE634790-C9F3-451B-BAF5-9FBF14447635,0x3B7A1000,0x240000)",
                    103892.22881,
                    0.03833399999712128,
                ),
                (
                    396,
                    "BindingStart",
                    "1FA1F39E-FEFF-4AAE-BD7B-38A070A3B609",
                    "UNKNOWN-f116",
                    "BindingStart measurement for module UNKNOWN-f116 and device PciRoot(0x0)/Pci(0x6,0x0)/Pci(0x0,0x0)/NVMe(0x1,D5-37-1A-49-4A-44-1B-00)/HD(4,GPT,AE634790-C9F3-451B-BAF5-9FBF14447635,0x3B7A1000,0x240000)",
                    103892.411564,
                    2.4567690000112634,
                ),
                (
                    397,
                    "BindingStart",
                    "961578FE-B6B7-44C3-AF35-6BC705CD2B1F",
                    "UNKNOWN-8e9c",
                    "BindingStart measurement for module UNKNOWN-8e9c and device PciRoot(0x0)/Pci(0x6,0x0)/Pci(0x0,0x0)/NVMe(0x1,D5-37-1A-49-4A-44-1B-00)/HD(4,GPT,AE634790-C9F3-451B-BAF5-9FBF14447635,0x3B7A1000,0x240000)",
                    103895.002191,
                    0.6412439999985509,
                ),
                (
                    398,
                    "BindingStart",
                    "240612B7-A063-11D4-9A3A-0090273FC14D",
                    "UNKNOWN-1ada",
                    "BindingStart measurement for module UNKNOWN-1ada and device PciRoot(0x0)/Pci(0xD,0x0)",
                    103896.601088,
                    0.09072100000048522,
                ),
                (
                    401,
                    "BindingStart",
                    "240612B7-A063-11D4-9A3A-0090273FC14D",
                    "UNKNOWN-1ada",
                    "BindingStart measurement for module UNKNOWN-1ada and device PciRoot(0x0)/Pci(0x14,0x0)",
                    103897.275624,
                    11.192014999993262,
                ),
                (
                    399,
                    "BindingStart",
                    "4EA43463-747C-46EB-97FB-B0E5C5F05306",
                    "UNKNOWN-a010",
                    "BindingStart measurement for module UNKNOWN-a010 and device Generic Usb Mouse Absolute Pointe PciRoot(0x0)/Pci(0x14,0x0)/USB(0x5,0x0)/USB(0x2,0x0)",
                    103897.833454,
                    10.082835999986855,
                ),
                (
                    400,
                    "BindingStart",
                    "408EDCEC-CF6D-477C-A5A8-B4844E3DE281",
                    "UNKNOWN-53e4",
                    "BindingStart measurement for module UNKNOWN-53e4 and device PciRoot(0x0)/Pci(0x14,0x0)/USB(0x5,0x0)/USB(0x2,0x0)",
                    103908.019803,
                    0.024611999993794598,
                ),
                (
                    402,
                    "BindingStart",
                    "FF0C8745-3270-4439-B74F-3E45F8C77064",
                    "UNKNOWN-1570",
                    "BindingStart measurement for module UNKNOWN-1570 and device PciRoot(0x0)/Pci(0x2,0x0)",
                    103920.729851,
                    0.01607900000817608,
                ),
                (
                    403,
                    "BindingStart",
                    "5BE3BDF4-53CF-46A3-A6A9-73C34A6E5EE3",
                    "UNKNOWN-729e",
                    "BindingStart measurement for module UNKNOWN-729e and device NVM Express Controlle PciRoot(0x0)/Pci(0x6,0x0)/Pci(0x0,0x0)",
                    103921.305719,
                    3.6866470000095433,
                ),
                (
                    404,
                    "BindingStart",
                    "1FA1F39E-FEFF-4AAE-BD7B-38A070A3B609",
                    "UNKNOWN-f116",
                    "BindingStart measurement for module UNKNOWN-f116 and device PciRoot(0x0)/Pci(0x6,0x0)/Pci(0x0,0x0)/NVMe(0x1,D5-37-1A-49-4A-44-1B-00)",
                    103925.132099,
                    5.242326999999932,
                ),
                (
                    405,
                    "BindingStart",
                    "1FA1F39E-FEFF-4AAE-BD7B-38A070A3B609",
                    "UNKNOWN-f116",
                    "BindingStart measurement for module UNKNOWN-f116 and device PciRoot(0x0)/Pci(0x6,0x0)/Pci(0x0,0x0)/NVMe(0x1,D5-37-1A-49-4A-44-1B-00)/HD(2,GPT,78C07A1B-D442-45CB-A82A-4C43F5F5B15D,0x82800,0x8000)",
                    103930.679364,
                    2.319900000002235,
                ),
                (
                    406,
                    "BindingStart",
                    "961578FE-B6B7-44C3-AF35-6BC705CD2B1F",
                    "UNKNOWN-8e9c",
                    "BindingStart measurement for module UNKNOWN-8e9c and device PciRoot(0x0)/Pci(0x6,0x0)/Pci(0x0,0x0)/NVMe(0x1,D5-37-1A-49-4A-44-1B-00)/HD(2,GPT,78C07A1B-D442-45CB-A82A-4C43F5F5B15D,0x82800,0x8000)",
                    103933.142168,
                    0.6580169999942882,
                ),
                (
                    407,
                    "BindingStart",
                    "1FA1F39E-FEFF-4AAE-BD7B-38A070A3B609",
                    "UNKNOWN-f116",
                    "BindingStart measurement for module UNKNOWN-f116 and device PciRoot(0x0)/Pci(0x6,0x0)/Pci(0x0,0x0)/NVMe(0x1,D5-37-1A-49-4A-44-1B-00)/HD(3,GPT,C59756F8-F924-46A3-B621-56EDC6FAA285,0x8A800,0x3B716800)",
                    103934.062702,
                    2.322622000006959,
                ),
                (
                    408,
                    "BindingStart",
                    "961578FE-B6B7-44C3-AF35-6BC705CD2B1F",
                    "UNKNOWN-8e9c",
                    "BindingStart measurement for module UNKNOWN-8e9c and device PciRoot(0x0)/Pci(0x6,0x0)/Pci(0x0,0x0)/NVMe(0x1,D5-37-1A-49-4A-44-1B-00)/HD(3,GPT,C59756F8-F924-46A3-B621-56EDC6FAA285,0x8A800,0x3B716800)",
                    103936.522536,
                    0.6333069999964209,
                ),
                (
                    409,
                    "BindingStart",
                    "1FA1F39E-FEFF-4AAE-BD7B-38A070A3B609",
                    "UNKNOWN-f116",
                    "BindingStart measurement for module UNKNOWN-f116 and device PciRoot(0x0)/Pci(0x6,0x0)/Pci(0x0,0x0)/NVMe(0x1,D5-37-1A-49-4A-44-1B-00)/HD(4,GPT,AE634790-C9F3-451B-BAF5-9FBF14447635,0x3B7A1000,0x240000)",
                    103937.4232,
                    2.3260840000002645,
                ),
                (
                    410,
                    "BindingStart",
                    "961578FE-B6B7-44C3-AF35-6BC705CD2B1F",
                    "UNKNOWN-8e9c",
                    "BindingStart measurement for module UNKNOWN-8e9c and device PciRoot(0x0)/Pci(0x6,0x0)/Pci(0x0,0x0)/NVMe(0x1,D5-37-1A-49-4A-44-1B-00)/HD(4,GPT,AE634790-C9F3-451B-BAF5-9FBF14447635,0x3B7A1000,0x240000)",
                    103939.886167,
                    0.6329259999911301,
                ),
                (
                    411,
                    "BindingStart",
                    "240612B7-A063-11D4-9A3A-0090273FC14D",
                    "UNKNOWN-1ada",
                    "BindingStart measurement for module UNKNOWN-1ada and device PciRoot(0x0)/Pci(0xD,0x0)",
                    103941.452013,
                    0.08808200000203215,
                ),
                (
                    412,
                    "BindingStart",
                    "240612B7-A063-11D4-9A3A-0090273FC14D",
                    "UNKNOWN-1ada",
                    "BindingStart measurement for module UNKNOWN-1ada and device PciRoot(0x0)/Pci(0x14,0x0)",
                    103942.118067,
                    0.6287159999919822,
                ),
                (
                    413,
                    "Function",
                    "D6A2CB7F-6A18-4E2F-B43B-9920A733700A",
                    "UNKNOWN-6c05",
                    "Function measurement from module UNKNOWN-6c05 with label CoreDispatcher",
                    103946.55618,
                    0.020346000004792586,
                ),
                (
                    414,
                    "BindingStart",
                    "FF0C8745-3270-4439-B74F-3E45F8C77064",
                    "UNKNOWN-1570",
                    "BindingStart measurement for module UNKNOWN-1570 and device PciRoot(0x0)/Pci(0x2,0x0)",
                    103946.695177,
                    0.0022480000043287873,
                ),
                (
                    415,
                    "BindingStart",
                    "FF0C8745-3270-4439-B74F-3E45F8C77064",
                    "UNKNOWN-1570",
                    "BindingStart measurement for module UNKNOWN-1570 and device PciRoot(0x0)/Pci(0x2,0x0)",
                    103946.800433,
                    0.01484800000616815,
                ),
                (
                    416,
                    "Event",
                    "6D33944A-EC75-4855-A54D-809C75241F6C",
                    "UNKNOWN-b2b2",
                    "Event measurement from module UNKNOWN-b2b2 with label ConOutReady",
                    103947.052138,
                    1e-06,
                ),
                (
                    417,
                    "BindingStart",
                    "240612B7-A063-11D4-9A3A-0090273FC14D",
                    "UNKNOWN-1ada",
                    "BindingStart measurement for module UNKNOWN-1ada and device PciRoot(0x0)/Pci(0xD,0x0)",
                    103947.192942,
                    0.08665500000643078,
                ),
                (
                    418,
                    "BindingStart",
                    "240612B7-A063-11D4-9A3A-0090273FC14D",
                    "UNKNOWN-1ada",
                    "BindingStart measurement for module UNKNOWN-1ada and device PciRoot(0x0)/Pci(0x14,0x0)",
                    103947.653007,
                    0.6339650000008987,
                ),
                (
                    419,
                    "Event",
                    "6D33944A-EC75-4855-A54D-809C75241F6C",
                    "UNKNOWN-b2b2",
                    "Event measurement from module UNKNOWN-b2b2 with label ConInReady",
                    103948.396819,
                    1e-06,
                ),
                (
                    420,
                    "Event",
                    "6D33944A-EC75-4855-A54D-809C75241F6C",
                    "UNKNOWN-b2b2",
                    "Event measurement from module UNKNOWN-b2b2 with label ErrOutReady",
                    103948.399598,
                    1e-06,
                ),
                (
                    2,
                    "Event",
                    "N/A",
                    "N/A",
                    "OSLoaderLoadImageStart",
                    103959.677189,
                    1e-06,
                ),
                (
                    421,
                    "LoadImage",
                    "6C646E68-0000-0000-D81E-F75E00000000",
                    "UNKNOWN-5ed4",
                    "LoadImage measurement for module UNKNOWN-5ed4",
                    103959.739004,
                    6.036777999994229,
                ),
                (
                    3,
                    "Event",
                    "N/A",
                    "N/A",
                    "OSLoaderStartImageStart",
                    103965.800517,
                    1e-06,
                ),
                (
                    424,
                    "Inmodule",
                    "06E49122-4EF4-45FE-9766-E2EAF2F9472F",
                    "UNKNOWN-0ec7",
                    "Inmodule measurement from module UNKNOWN-0ec7 with label AdvLogger All files",
                    105084.238073,
                    0.0026630000065779313,
                ),
                (
                    4,
                    "Process",
                    "N/A",
                    "N/A",
                    "ExitBootServices",
                    105104.963359,
                    25.676374000002397,
                ),
            ],
            [
                (
                    "Error",
                    "Start record with label Function_UNKNOWN-fc49_PeiDispatcher already in dict!",
                ),
                (
                    "Error",
                    "3 start record(s) with no matching end record(s) found: {'Inmodule_UNKNOWN-17e2_DeferredFv': 100045.670302, 'Crossmodule_BDS': 103965.799664, 'Entrypoint_UNKNOWN-5ed4': 103965.854916}",
                ),
            ],
            0,
        )

        record_data = parse_fpdt_records(xml_file_path, None, {})

        for record in record_data[0]:
            self.assertIn(record, expected_data_tuple[0])

        for record in record_data[1]:
            self.assertIn(record, expected_data_tuple[1])

        self.assertEqual(record_data[2], expected_data_tuple[2])

        # Create a dictionary with GUIDs as keys and "GUIDX" as values
        guid_dict = {}
        guid_counter = 1
        for entry in expected_data_tuple[0]:
            guid = entry[2]
            if guid != "N/A":
                # Cross module GUIDs are separated by a comma
                if "," in guid:
                    for sub_guid in guid.split(", "):
                        if sub_guid not in guid_dict:
                            guid_dict[sub_guid] = f"GUID{guid_counter}"
                            guid_counter += 1
                elif guid not in guid_dict:
                    guid_dict[guid] = f"GUID{guid_counter}"
                    guid_counter += 1

        # Run again with a GUID dictionary
        record_data = parse_fpdt_records(xml_file_path, None, guid_dict)

        # Verify GUIDs decode as expected
        for record in record_data[0]:
            if record[2] != "N/A":
                if "," in record[2]:
                    for sub_guid in record[2].split(", "):
                        self.assertIn(guid_dict[sub_guid], record[3])
                else:
                    self.assertIn(guid_dict[record[2]], record[3])

    def test_parse_fpdt_records_empty_file(self) -> None:
        """Test the parse_fpdt_records function with an empty XML file.

        Ensures that parsing an empty file raises an ElementTree.ParseError.
        """
        xml_file_path = os.path.join(self.test_dir, "empty_file.xml")
        with open(xml_file_path, "w") as empty_file:
            empty_file.write("")

        with self.assertRaises(xml.etree.ElementTree.ParseError):
            parse_fpdt_records(xml_file_path, None, {})

    def test_parse_fpdt_records_invalid_file(self) -> None:
        """Test the `parse_fpdt_records` function with invalid and no-records XML files.

        Verifies the following scenarios:

        1. An invalid XML file is provided, which should raise an `xml.etree.ElementTree.ParseError`.
        2. A valid XML file with no FBPT records is provided, which should:
           - Log a critical error message.
           - Return an empty list of records, a list containing an error message, and an error code of 1.
        """
        xml_file_path = os.path.join(self.test_dir, "invalid_file.xml")
        with open(xml_file_path, "w") as invalid_file:
            invalid_file.write("<root><invalid></root>")

        with self.assertRaises(xml.etree.ElementTree.ParseError):
            parse_fpdt_records(xml_file_path, None, {})

        NO_RECORDS_XML_CONTENT = """<FpdtParserData>
            <UEFIVersion Value="Hyper-V UEFI Release v4.1" />
            <Model Value="Virtual Machine" />
            <DateCollected Value="5/1/2025" />
            <FpdtParserVersion Value="3.00" />
            <AcpiTableHeader Signature="FPDT" Length="0x34" Revision="0x1" Checksum="0x50" OEMID="b'VRTUAL'"
                             OEMTableID="b'MICROSFT'" OEMRevision="0x1" CreatorID="b'MSFT'" CreatorRevision="0x1" />
        </FpdtParserData>"""

        xml_file_path = os.path.join(self.test_dir, "no_records.xml")
        with open(xml_file_path, "w") as no_records_file:
            no_records_file.write(NO_RECORDS_XML_CONTENT)

        with self.assertLogs(level="CRITICAL") as log:
            record_data = parse_fpdt_records(xml_file_path, None, {})
            self.assertEqual(record_data[0], [])
            self.assertEqual(record_data[1], [("Error", f"No FBPT records found in {xml_file_path}")])
            self.assertEqual(record_data[2], 1)

        self.assertIn(f"CRITICAL:root:Error! No FBPT records found in {xml_file_path}", log.output)

    def test_unrecognized_record_type(self) -> None:
        """Test case for handling unrecognized record types in the FPDT XML data.

        Verifies that the `parse_fpdt_records` function correctly identifies and logs an error when encountering
        an unrecognized record type in the XML content.
        """
        UNRECOGNIZED_RECORD_XML_CONTENT = """<FpdtParserData>
            <UEFIVersion Value="Hyper-V UEFI Release v4.1" />
            <Model Value="Virtual Machine" />
            <DateCollected Value="5/1/2025" />
            <FpdtParserVersion Value="3.00" />
            <AcpiTableHeader Signature="FPDT" Length="0x34" Revision="0x1" Checksum="0x50" OEMID="b'VRTUAL'"
                             OEMTableID="b'MICROSFT'" OEMRevision="0x1" CreatorID="b'MSFT'" CreatorRevision="0x1" />
            <FwBasicBootPerformanceRecord PerformanceRecordType="0x0" RecordLength="0x10" Revision="0x1" Reserved="0x0"
                                          FBPTPointer="0x3FFC8000" />
            <Fbpt Signature="FBPT" Length="0x38">
                <FirmwareBasicBootPerformanceEvent PerformanceRecordType="0x2" RecordLength="0x30" Revision="0x2">
                    <ResetEnd RawValue="0x0" ValueInMilliseconds="0.000000" />
                    <OSLoaderLoadImageStart RawValue="0x1858C060" ValueInMilliseconds="408.469600" />
                    <OSLoaderStartImageStart RawValue="0x1ABBF908" ValueInMilliseconds="448.526600" />
                    <ExitBootServicesEntry RawValue="0x577F5100" ValueInMilliseconds="1467.961600" />
                    <ExitBootServicesExit RawValue="0x578E4AFC" ValueInMilliseconds="1468.943100" />
                </FirmwareBasicBootPerformanceEvent>
                <Record Type="UnknownType" Label="TestLabel" GUID="12345678-1234-1234-1234-123456789012"
                        ModuleName="TestModuleName" Description="TestDescription" StartTimeStamp="100000.000000"
                        DurationTimeStamp="10.000000" />
            </Fbpt>
        </FpdtParserData>"""

        xml_file_path = os.path.join(self.test_dir, "unrecognized_record.xml")
        with open(xml_file_path, "w") as unrecognized_record_file:
            unrecognized_record_file.write(UNRECOGNIZED_RECORD_XML_CONTENT)

        with self.assertLogs(level="CRITICAL"):
            record_data = parse_fpdt_records(xml_file_path, None, {})
            self.assertEqual(record_data[1], [("Error", "Unrecognized record found with tag Record")])
            self.assertEqual(record_data[2], 1)


class TestWriteHtmlReport(unittest.TestCase):
    """Unit tests for the `write_html_report` function."""

    def setUp(self) -> None:
        """Set up the test environment for performance report generator tests.

        Initializes a temporary directory for test files, sets up a path
        for an HTML report file, and defines sample timing data and log messages
        to be used in the tests.
        """
        self.test_dir = tempfile.mkdtemp()
        self.html_file_path = os.path.join(self.test_dir, "test_report.html")
        self.timing_list = [
            ("1", "Event", "N/A", "N/A", "ResetEnd", 0.000000, 0.000001),
            ("2", "Event", "N/A", "N/A", "OSLoaderLoadImageStart", 408.469600, 0.000001),
            ("3", "Event", "N/A", "N/A", "OSLoaderStartImageStart", 448.526600, 0.000001),
            ("4", "Process", "N/A", "N/A", "ExitBootServices", 1467.961600, 0.981500),
        ]
        self.messages = [
            ("INFO", "Parsing completed successfully."),
            ("WARNING", "Some records were skipped due to missing data."),
        ]

    def tearDown(self) -> None:
        """Clean up the test environment by removing the temporary test directory.

        This method is called after each test method to ensure that any resources
        created during the test are properly cleaned up.
        """
        shutil.rmtree(self.test_dir)

    def test_write_html_report_valid_data(self) -> None:
        """Test the `write_html_report` function with valid input data.

        This test verifies that key HTML elements are correctly generated when provided
        with valid XML data, timing information, and messages.
        """
        xml_file_path = os.path.join(
            os.path.dirname(os.path.abspath(__file__)),
            "testdata",
            "fpdt_complex_data.xml",
        )

        with open(self.html_file_path, "w") as html_report:
            write_html_report(xml_file_path, self.timing_list, self.messages, html_report)

        with open(self.html_file_path, "r") as html_report:
            content = html_report.read()

        self.assertIn('<html lang="en">', content)
        self.assertIn("<title>Performance Report</title>", content)
        self.assertIn("ResetEnd", content)
        self.assertIn("OSLoaderLoadImageStart", content)
        self.assertIn("OSLoaderStartImageStart", content)
        self.assertIn("ExitBootServices", content)
        self.assertIn("Parsing completed successfully.", content)
        self.assertIn("Some records were skipped due to missing data.", content)
