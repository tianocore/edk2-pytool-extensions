import uuid
import os
# TODO: Replace this step with a new function from within
#       FmpAuthHeaderClass().
import struct

from edk2toollib.uefi.uefi_capsule_header import UefiCapsuleHeaderClass
from edk2toollib.uefi.fmp_capsule_header import FmpCapsuleHeaderClass, FmpCapsuleImageHeaderClass
from edk2toollib.uefi.fmp_auth_header import FmpAuthHeaderClass
from edk2toollib.uefi.edk2.fmp_payload_header import FmpPayloadHeaderClass

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

def get_capsule_file_name(capsule_options):
    return f"{capsule_options['fw_name']}_{capsule_options['fw_version_string']}.bin"

def get_expanded_version_string(version_string):
    # TODO: This.
    return version_string

def save_capsule(uefi_capsule_header, capsule_options, save_path):
    # First, create the entire save path.
    os.makedirs(save_path, exist_ok=True)

    # Then save the file.
    capsule_file_path = os.path.join(save_path, get_capsule_file_name(capsule_options))
    with open(capsule_file_path, 'wb') as capsule_file:
        capsule_file.write(uefi_capsule_header.Encode())

# TODO: Deal with optional parameters when creating the INF file.
# OPTIONAL: is rollback, arch, os, mfg name
# TODO: Expand the version string prior to creating INF file.
