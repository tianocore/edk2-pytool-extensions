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

from typing import List
from dataclasses import dataclass
from dataclasses import field

from edk2toollib.windows.capsule import inf_generator2, cat_generator
from edk2toollib.uefi.uefi_capsule_header import UefiCapsuleHeaderClass
from edk2toollib.uefi.fmp_capsule_header import FmpCapsuleHeaderClass, FmpCapsuleImageHeaderClass
from edk2toollib.uefi.fmp_auth_header import FmpAuthHeaderClass
from edk2toollib.uefi.edk2.fmp_payload_header import FmpPayloadHeaderClass

# https://docs.microsoft.com/en-us/dotnet/api/system.security.cryptography.pkcs.contentinfo.-ctor?view=netframework-4.8
PKCS7_SIGNED_DATA_OID = '1.2.840.113549.1.7.2'


@dataclass
class CapsulePayload:
    '''Stores information about a specific capsule payload.

    CapsulePayload instances have the following attributes:
    payload              - an instance of UefiCapsuleHeaderClass that represents the payload data.
    payload_filename     - the payload filename as a string
    esrt_guid            - the payload ESRT guid as a uuid.UUID instance.
    version              - the 32-bit ESRT version for the payload.
    firmware_description - the firmware payload description.
    tag                  - a string uniquely identifying the payload. optional, if not present, will be auto-generated.
    rollback             - indicates whether this is a rollback payload. optional, defaults to false.
    integrity_data       - integrity data for this payload. optional.
    integrity_filename   - integrity filename. optional if integrity_data is None, required otherwise.
    '''
    payload: UefiCapsuleHeaderClass
    payload_filename: str
    esrt_guid: uuid.UUID
    version: int
    firmware_description: str
    tag: str = None
    rollback: bool = False
    integrity_data: bytes = None
    integrity_filename: str = None


@dataclass
class Capsule:
    '''Stores information about a capsule (potentially with multiple payloads)

    Capsule instances have the following attributes:
    version_string    - the version of the entire capsule driver package as a string (e.g. 1.0.0.1)
    name              - the name of the capsule package
    provider_name     - the name of the capsule provider
    arch              - the architecture targeted by the capsule
    os                - the OS targeted by the capsule.
    manufacturer_name - name of the capsule manufacturer. optional, defaults to provider_name if None.
    date              - a datetime.date object indicating when the capsule was built. optional, defaults to
                        datetime.date.today().
    payloads          - a list of capsule payloads. optional, defaults to empty list
    '''
    version_string: str
    name: str
    provider_name: str
    arch: str = None
    os: str = None
    manufacturer_name: str = None
    date: datetime.date = datetime.date.today()
    payloads: List[CapsulePayload] = field(default_factory=list)


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


def save_multinode_capsule(capsule: Capsule, save_path: str) -> str:
    '''
    takes in a Capsule object and a filesystem directory path and generates the capsule files at that path.

    capsule     - a Capsule object containing the capsule details.
    save_path   - directory path to save the capsule contents into

    returns save_path
    '''
    os.makedirs(save_path, exist_ok=True)
    for capsule_payload in capsule.payloads:
        payload_file_path = os.path.join(save_path, capsule_payload.payload_filename)
        with open(payload_file_path, 'wb') as payload_file:
            payload_file.write(capsule_payload.payload.Encode())

        if capsule_payload.integrity_data is not None:
            if (capsule_payload.integrity_filename is None):
                raise ValueError("Integrity data specified, but no integrity filename specified.")
            integrity_file_path = os.path.join(save_path, capsule_payload.integrity_filename)
            with open(integrity_file_path, 'wb') as integrity_file:
                integrity_file.write(capsule_payload.integrity_data)
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

    inf_file = inf_generator2.InfFile(
        capsule_options['fw_name'],
        capsule_options['fw_version_string'],
        datetime.date.today().strftime("%m/%d/%Y"),
        capsule_options['provider_name'],
        capsule_options['mfg_name'],
        capsule_options['arch']
    )

    inf_file.AddFirmware(
        "Firmware",
        capsule_options['fw_description'],
        capsule_options['esrt_guid'],
        capsule_options['fw_version'],
        get_capsule_file_name(capsule_options),
        Rollback=capsule_options['is_rollback'],
        IntegrityFile=capsule_options.get('fw_integrity_file', None)
    )

    inf_file_path = os.path.join(save_path, f"{capsule_options['fw_name']}.inf")
    with open(inf_file_path, "w") as fp:
        fp.write(str(inf_file))

    return inf_file_path


def create_multinode_inf_file(capsule: Capsule, save_path: str) -> str:
    '''
    Takes in a capsule object containing payload information and creates the Windows INF file in save_path

    capsule     - capsule object containing payload information
    save_path   - path to directory where inf file will be created.

    returns the name of the created inf file.
    '''
    # Expand the version string prior to creating INF file.
    capsule.version_string = get_normalized_version_string(capsule.version_string)

    # set defaults for non-specified fields
    if (capsule.arch is None):
        capsule.arch = get_default_arch()
    if (capsule.manufacturer_name is None):
        capsule.manufacturer_name = capsule.provider_name

    inf_file = inf_generator2.InfFile(
        capsule.name,
        capsule.version_string,
        capsule.date.strftime("%m/%d/%Y"),
        capsule.provider_name,
        capsule.manufacturer_name,
        capsule.arch
    )

    idx = 0
    for payload in capsule.payloads:
        if payload.tag is None:
            payload.tag = f"Firmware{idx}"
            idx += 1
        inf_file.AddFirmware(
            payload.tag,
            payload.firmware_description,
            str(payload.esrt_guid),
            str(payload.version),
            payload.payload_filename,
            Rollback=payload.rollback,
            IntegrityFile=payload.integrity_filename
        )

    inf_file_path = os.path.join(save_path, f"{capsule.name}.inf")
    with open(inf_file_path, "w") as fp:
        fp.write(str(inf_file))

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
    if (ret != 0):
        raise RuntimeError("MakeCat Failed with errorcode %d!" % ret)

    return cat_file_path
