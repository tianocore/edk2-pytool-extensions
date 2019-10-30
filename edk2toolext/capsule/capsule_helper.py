## @file capsule_helper.py
# This module contains helper functions for building EDK2 FMP UEFI capsules from
# binary payloads, along with the functions to standardize the creation of the Windows
# driver installation files.
#
##
# Copyright (C) Microsoft Corporation
#
# SPDX-License-Identifier: BSD-2-Clause-Patent
##


import uuid
import os
# TODO: Replace this step with a new function from within
#       FmpAuthHeaderClass().
import struct

from edk2toollib.windows.capsule import inf_generator, cat_generator
from edk2toollib.uefi.uefi_capsule_header import UefiCapsuleHeaderClass
from edk2toollib.uefi.fmp_capsule_header import FmpCapsuleHeaderClass, FmpCapsuleImageHeaderClass
from edk2toollib.uefi.fmp_auth_header import FmpAuthHeaderClass
from edk2toollib.uefi.edk2.fmp_payload_header import FmpPayloadHeaderClass


def get_capsule_file_name(capsule_options):
    return f"{capsule_options['fw_name']}_{capsule_options['fw_version_string']}.bin"


def get_normalized_version_string(version_string):
    # 19H1 HLK requires a 4 digit version string, or it will fail
    while (version_string.count('.') < 3):
        version_string += '.0'
    return version_string


def get_default_arch():
    return 'amd64'


def get_default_os_string():
    return 'Win10'


def build_capsule(capsule_data, capsule_options, signer_module, signer_options):
    # Start building the capsule as we go.
    # Create the FMP Payload and set all the necessary options.
    fmp_payload_header = FmpPayloadHeaderClass()
    fmp_payload_header.FwVersion = int(capsule_options['fw_version'], 16)
    fmp_payload_header.LowestSupportedVersion = int(capsule_options['lsv_version'], 16)
    fmp_payload_header.Payload = capsule_data

    # Create the auth header and get ready to sign the data.
    fmp_auth_header = FmpAuthHeaderClass()
    # TODO: Allow caller to pass the monotonic count in capsule_options.
    fmp_auth_header.MonotonicCount = 1
    fmp_auth_header.FmpPayloadHeader = fmp_payload_header

    # TODO: Replace this step with a new function from within
    #       FmpAuthHeaderClass().
    data_to_sign = fmp_payload_header.Encode()
    data_to_sign = data_to_sign + struct.pack("<Q", fmp_auth_header.MonotonicCount)

    # Sign the data and assign it to the cert data.
    # TODO: Determine whether EKU is a signer option or a signature option.
    # TODO: Figure out whether this sign_alg is correct for capsules.
    signature_options = {
        'sign_alg': 'pkcs12',
        'hash_alg': 'sha256'
    }
    # Set or override OID.
    signer_options['oid'] = '1.2.840.113549.1.7.2'
    fmp_auth_header.AuthInfo.CertData = signer_module.sign(data_to_sign, signature_options, signer_options)

    fmp_capsule_image_header = FmpCapsuleImageHeaderClass()
    fmp_capsule_image_header.UpdateImageTypeId = uuid.UUID(capsule_options['esrt_guid'])
    fmp_capsule_image_header.UpdateImageIndex = 1
    fmp_capsule_image_header.FmpAuthHeader = fmp_auth_header

    fmp_capsule_header = FmpCapsuleHeaderClass()
    fmp_capsule_header.AddFmpCapsuleImageHeader(fmp_capsule_image_header)

    uefi_capsule_header = UefiCapsuleHeaderClass()
    uefi_capsule_header.FmpCapsuleHeader = fmp_capsule_header
    uefi_capsule_header.PersistAcrossReset = True
    uefi_capsule_header.InitiateReset = True

    return uefi_capsule_header


def save_capsule(uefi_capsule_header, capsule_options, save_path):
    # First, create the entire save path.
    os.makedirs(save_path, exist_ok=True)

    # Then save the file.
    capsule_file_path = os.path.join(save_path, get_capsule_file_name(capsule_options))
    with open(capsule_file_path, 'wb') as capsule_file:
        capsule_file.write(uefi_capsule_header.Encode())


def create_inf_file(capsule_options, save_path):
    # Expand the version string prior to creating INF file.
    capsule_options['fw_version_string'] = get_normalized_version_string(capsule_options['fw_version_string'])

    # Deal with optional parameters when creating the INF file.
    capsule_options['is_rollback'] = capsule_options.get('is_rollback', False)
    capsule_options['arch'] = capsule_options.get('arch', get_default_arch())
    capsule_options['mfg_name'] = capsule_options.get('mfg_name', capsule_options['provider_name'])

    # Create the INF.
    infgenerator = inf_generator.InfGenerator(
        capsule_options['fw_name'],
        capsule_options['provider_name'],
        capsule_options['esrt_guid'],
        capsule_options['arch'],
        capsule_options['fw_description'],
        capsule_options['fw_version_string'],
        capsule_options['fw_version']
    )
    infgenerator.Manufacturer = capsule_options['mfg_name']
    ret = infgenerator.MakeInf(
        os.path.join(save_path, f"{capsule_options['fw_name']}.inf"),
        get_capsule_file_name(capsule_options),
        capsule_options['is_rollback']
    )
    if(ret != 0):
        raise RuntimeError("MakeInf Failed with errorcode %d!" % ret)


def create_cat_file(capsule_options, save_path):
    # Deal with optional parameters when creating the CAT file.
    capsule_options['arch'] = capsule_options.get('arch', get_default_arch())
    capsule_options['os_string'] = capsule_options.get('os_string', get_default_os_string())

    # Create the CAT.
    catgenerator = cat_generator.CatGenerator(
        capsule_options['arch'],
        capsule_options['os_string']
    )
    ret = catgenerator.MakeCat(
        os.path.join(save_path, f"{capsule_options['fw_name']}.cat")
    )
    if(ret != 0):
        raise RuntimeError("MakeCat Failed with errorcode %d!" % ret)
