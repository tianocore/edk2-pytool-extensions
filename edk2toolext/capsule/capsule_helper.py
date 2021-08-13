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
import struct
import datetime

from edk2toollib.windows.capsule import inf_generator, inf_generator2, cat_generator
from edk2toollib.uefi.uefi_capsule_header import UefiCapsuleHeaderClass
from edk2toollib.uefi.fmp_capsule_header import FmpCapsuleHeaderClass, FmpCapsuleImageHeaderClass
from edk2toollib.uefi.fmp_auth_header import FmpAuthHeaderClass
from edk2toollib.uefi.edk2.fmp_payload_header import FmpPayloadHeaderClass

# https://docs.microsoft.com/en-us/dotnet/api/system.security.cryptography.pkcs.contentinfo.-ctor?view=netframework-4.8
PKCS7_SIGNED_DATA_OID = '1.2.840.113549.1.7.2'


def get_capsule_file_name(capsule_options: dict) -> str:
    '''from the shared capsule_options dictionary, returns the formatted capsule file name'''
    return f"{capsule_options['fw_name']}_{capsule_options['fw_version_string']}.bin"


def get_normalized_version_string(version_string: str) -> str:
    '''takes in a version string and returns a normalized version that is compatible with inf and cat files'''
    # 19H1 HLK requires a 4 digit version string, or it will fail
    while (version_string.count('.') < 3):
        version_string += '.0'
    return version_string


def get_default_arch() -> str:
    '''helper function to consistently return the default architecture for windows files'''
    return 'amd64'


def get_default_os_string() -> str:
    '''helper function to consistently return the default os for windows files'''
    return 'Win10'


def build_capsule(capsule_data: bytes, capsule_options: dict, signer_module: object,
                  signer_options: dict) -> UefiCapsuleHeaderClass:
    '''
    goes through all of the steps of capsule generation for a single-payload FMP capsule

    takes in capsule_data as a byte string, a signer module, and capsule and signer options,
    and produces all of the headers necessary. Will use the signer module to produce the cert data
    for the FMP Auth header.

    NOTE: Uses a fixed MonotonicCount of 1.

    capsule_data - a byte string for the innermost payload
    capsule_options - a dictionary that will be used for all the capsule payload fields. Must include
                        'fw_version', 'lsv_version', and 'esrt_guid' at a minimum. These should all be
                        strings and the two versions should be strings of hex number (e.g. 0x12345)
    signer_module - a capsule signer module that implements the sign() function (see pyopenssl_signer or
                        signtool_signer built-in modules for examples)
    signer_options - a dictionary of options that will be passed to the signer_module. The required values
                        depend on the expectations of the signer_module provided

    returns a UefiCapsuleHeaderClass object containing all of the provided data
    '''
    # Start building the capsule as we go.
    # Create the FMP Payload and set all the necessary options.
    fmp_payload_header = FmpPayloadHeaderClass()
    fmp_payload_header.FwVersion = int(capsule_options['fw_version'], 16)
    fmp_payload_header.LowestSupportedVersion = int(capsule_options['lsv_version'], 16)
    fmp_payload_header.Payload = capsule_data

    # Create the auth header and get ready to sign the data.
    fmp_auth_header = FmpAuthHeaderClass()
    fmp_auth_header.MonotonicCount = 1
    fmp_auth_header.FmpPayloadHeader = fmp_payload_header

    data_to_sign = fmp_payload_header.Encode()
    data_to_sign = data_to_sign + struct.pack("<Q", fmp_auth_header.MonotonicCount)

    # Sign the data and assign it to the cert data.
    signature_options = {
        'sign_alg': 'pkcs12',
        'hash_alg': 'sha256'
    }
    # Set or override OID.
    signer_options['oid'] = PKCS7_SIGNED_DATA_OID
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


def save_capsule(uefi_capsule_header: UefiCapsuleHeaderClass, capsule_options: dict, save_path: str) -> str:
    '''
    takes in a UefiCapsuleHeaderClass object, a dictionary of capsule_options, and a filesystem directory path
    and serializes the capsule object to the target directory

    will use get_capsule_file_name() to determine the final filename
    will create all intermediate directories if save_path does not already exist
    '''
    # Expand the version string prior to creating the payload file.
    capsule_options['fw_version_string'] = get_normalized_version_string(capsule_options['fw_version_string'])

    # First, create the entire save path.
    os.makedirs(save_path, exist_ok=True)

    # Then save the file.
    capsule_file_path = os.path.join(save_path, get_capsule_file_name(capsule_options))
    with open(capsule_file_path, 'wb') as capsule_file:
        capsule_file.write(uefi_capsule_header.Encode())

    return capsule_file_path


def save_multinode_capsule(payloads: list, payload_info: list, save_path: str) -> str:
    '''
    takes in a list of payloads, a list of payload options dictionaries, and a filesystem directory path and serializes
    the capsule object to the target directory.

    payloads        - list of bytes objects that will be written to files
    payload_info    - list of information associated with each payload. The following options are used:
        'fw_payload_file'   - filename to which to write the payload data.
        'integrity_data'    - optional. if it exists, will be written to a file in the payload directory.
        'fw_integrity_file' - required if integrity_data is present. filename to which to write the integrity data.
    save_path       - directory path to save the capsule contents into

    returns save_path
    '''
    os.makedirs(save_path, exist_ok=True)
    for (payload, payload_info) in zip(payloads, payload_info):
        payload_file_path = os.path.join(save_path, payload_info['fw_payload_file'])
        with open(payload_file_path, 'wb') as payload_file:
            payload_file.write(payload.Encode())

        if ('integrity_data' in payload_info):
            integrity_file_path = os.path.join(save_path, payload_info['fw_integrity_file'])
            with open(integrity_file_path, 'wb') as integrity_file:
                integrity_file.write(payload_info['integrity_data'])
    return save_path


def create_inf_file(capsule_options: dict, save_path: str) -> str:
    '''
    takes in a dictionary of capsule_options and creates the Windows INF file for the UEFI capsule according
    to the provided options

    will save the final file to the save_path with a name determined from the capsule_options
    '''
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
    if 'fw_integrity_file' in capsule_options:
        infgenerator.IntegrityFilename = os.path.basename(capsule_options['fw_integrity_file'])
    inf_file_path = os.path.join(save_path, f"{capsule_options['fw_name']}.inf")
    ret = infgenerator.MakeInf(inf_file_path, get_capsule_file_name(capsule_options), capsule_options['is_rollback'])
    if(ret != 0):
        raise RuntimeError("MakeInf Failed with errorcode %d!" % ret)

    return inf_file_path


def create_multinode_inf_file(capsule_options: dict, payloads: list, save_path: str) -> str:
    '''
    takes in a dictionary of capsule_options and a list of dictionaries containing payload information and creates the
    Windows INF file for the capsule according to the provided options.

    capsule_options - dictionary of capsule options:
        'fw_version_string' - the firmware version as a string e.g. 1.0.0.1
        'fw_name'           - firmware name
        'provider_name'     - specifies the provider of the capsule
        'arch'              - optional - specifies the arch for the capsule
        'mfg_name'          - optional - specifies the mfg_name for the capsule. defaults to 'provider_name'
        'date'              - optional - specifies the date for the capsule in 01/01/2021 format. defaults to today
        'fw_description     - optional - used as the default description for payloads if they don't specify one.
        'fw_version'        - optional - used as the default version strings for payloads if they don't specify one.

    payloads - list of dictionaries containing the payload info for this inf file - each element represents one targeted
               ESRT node for the capsule:
        'fw_payload_file'   - payload filename
        'esrt_guid'         - ESRT GUID for this payload
        'tag'               - optional - unique identifier for the payload. if not specified, defaults to
                              Firmware0, Firmware1, etc..
        'fw_description'    - optional - firmware description. defaults to capsule_options['fw_description']
        'is_rollback'       - optional - indicates whether this is a rollback payload or not. defaults to false.
        'fw_integrity_file' - optional - specifies integrity filename
        'fw_version'        - optional - version string. defaults to capsule_options['fw_version']

    save_path - path to directory where inf file will be created.

    returns the name of the created inf file.
    '''
    # Expand the version string prior to creating INF file.
    capsule_options['fw_version_string'] = get_normalized_version_string(capsule_options['fw_version_string'])

    # Deal with optional parameters when creating the INF file.
    capsule_options['fw_version_string'] = get_normalized_version_string(capsule_options['fw_version_string'])
    capsule_options['arch'] = capsule_options.get('arch', get_default_arch())
    capsule_options['mfg_name'] = capsule_options.get('mfg_name', capsule_options['provider_name'])
    capsule_options['date'] = capsule_options.get('date', datetime.date.today().strftime("%m/%d/%Y"))

    infFile = inf_generator2.InfFile(
        capsule_options['fw_name'],
        capsule_options['fw_version_string'],
        capsule_options['date'],
        capsule_options['provider_name'],
        capsule_options['mfg_name'],
        capsule_options['arch']
    )

    for (payload, idx) in zip(payloads, range(len(payloads))):
        payload['tag'] = payload.get('tag', f"Firmware{idx}")
        payload['fw_description'] = payload.get('fw_description', capsule_options['fw_description'])
        payload['fw_version'] = payload.get('fw_version', capsule_options['fw_version'])
        payload['is_rollback'] = payload.get('is_rollback', False)
        if 'fw_integrity_file' not in payload:
            payload['fw_integrity_file'] = None

        infFile.AddFirmware(
            payload['tag'],
            payload['fw_description'],
            payload['esrt_guid'],
            payload['fw_version'],
            payload['fw_payload_file'],
            Rollback=payload['is_rollback'],
            IntegrityFile=payload['fw_integrity_file']
        )

    inf_file_path = os.path.join(save_path, f"{capsule_options['fw_name']}.inf")
    with open(inf_file_path, "w") as fp:
        fp.write(str(infFile))

    return inf_file_path


def create_cat_file(capsule_options: dict, save_path: str) -> str:
    '''
    takes in a dictionary of capsule_options and creates the Windows CAT file for the UEFI capsule according
    to the provided options

    will save the final file to the save_path with a name determined from the capsule_options
    '''
    # Deal with optional parameters when creating the CAT file.
    capsule_options['arch'] = capsule_options.get('arch', get_default_arch())
    capsule_options['os_string'] = capsule_options.get('os_string', get_default_os_string())

    # Create the CAT.
    catgenerator = cat_generator.CatGenerator(
        capsule_options['arch'],
        capsule_options['os_string']
    )
    cat_file_path = os.path.join(save_path, f"{capsule_options['fw_name']}.cat")
    ret = catgenerator.MakeCat(cat_file_path)
    if(ret != 0):
        raise RuntimeError("MakeCat Failed with errorcode %d!" % ret)

    return cat_file_path
