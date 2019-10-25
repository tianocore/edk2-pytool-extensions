from edk2toolext.capsule import pyopenssl_signer
from edk2toolext.capsule import signtool_signer

PYOPENSSL_SIGNER = 'pyopenssl'
SIGNTOOL_SIGNER = 'signtool'
# TODO: pypath_module
# TODO: local_module

def get_signer(type):
  if type == PYOPENSSL_SIGNER:
    return pyopenssl_signer
  elif type == SIGNTOOL_SIGNER:
    return signtool_signer
  else:
    return None
