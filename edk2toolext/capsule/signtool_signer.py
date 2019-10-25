import os
import logging
import tempfile

from edk2toollib.windows import locate_tools
from edk2toollib.utility_functions import RunCmd

GLOBAL_SIGNTOOL_PATH = None

def get_signtool_path():
    global GLOBAL_SIGNTOOL_PATH

    if GLOBAL_SIGNTOOL_PATH is None:
        GLOBAL_SIGNTOOL_PATH = locate_tools.FindToolInWinSdk('signtool.exe')

    return GLOBAL_SIGNTOOL_PATH

def sign(data, signature_options, signer_options):
    # NOTE: Currently, we only support the necessary algorithms for capsules.
    if signature_options['sign_alg'] != 'pkcs12':
        raise ValueError(f"Unsupported signature algorithm: {signature_options['sign_alg']}!")
    if signature_options['hash_alg'] != 'sha256':
        raise ValueError(f"Unsupported hashing algorithm: {signature_options['hash_alg']}!")
    if 'key_file' not in signer_options:
        raise ValueError("Must supply a key_file in signer_options for Signtool!")

    # Set up a temp directory to hold input and output files.
    temp_folder = tempfile.mkdtemp()
    in_file_path = os.path.join(temp_folder, "data_to_sign.bin")

    # Create the input file for Signtool.
    in_file = open(in_file_path, 'wb')
    in_file.write(data)
    in_file.close()

    # Start building the parameters for the call.
    signtool_params = ['sign']
    signtool_params += ['/fd', 'sha256']
    signtool_params += ['/p7ce', 'DetachedSignedData']
    signtool_params += ['/p7', f'"{temp_folder}"']
    signtool_params += ['/f', f"\"{signer_options['key_file']}\""]
    if 'oid' in signer_options:
        signtool_params += ['/p7co', signer_options['oid']]
    if 'eku' in signer_options:
        signtool_params += ['/u', signer_options['eku']]
    if 'key_pass' in signer_options:
        signtool_params += ['/p', signer_options['key_pass']]
    # Add basic options.
    signtool_params += ['/debug', '/v', f'"{in_file_path}"']

    # Make the call to Signtool.
    ret = RunCmd(get_signtool_path(), " ".join(signtool_params))
    if ret != 0:
        raise RuntimeError(f"Signtool.exe returned with error: {ret}!")

    # Load the data from the output file and return it.
    out_file_path = os.path.join(temp_folder, "data_to_sign.bin.p7")
    out_file = open(out_file_path, 'rb')
    out_data = out_file.read()
    out_file.close()

    return out_data
