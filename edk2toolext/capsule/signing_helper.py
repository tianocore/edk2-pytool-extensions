import importlib

from edk2toolext.capsule import pyopenssl_signer
from edk2toolext.capsule import signtool_signer
from edk2toollib.utility_functions import import_module_by_file_name

PYOPENSSL_SIGNER = 'pyopenssl'
SIGNTOOL_SIGNER = 'signtool'
PYPATH_MODULE_SIGNER = 'pymodule'
LOCAL_MODULE_SIGNER = 'local_module'


def get_signer(type, specifier=None):
    if type == PYOPENSSL_SIGNER:
        return pyopenssl_signer
    elif type == SIGNTOOL_SIGNER:
        return signtool_signer
    elif type == PYPATH_MODULE_SIGNER:
        return importlib.import_module(specifier)
    elif type == LOCAL_MODULE_SIGNER:
        return import_module_by_file_name(specifier)
    else:
        return None
