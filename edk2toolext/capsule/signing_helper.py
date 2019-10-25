from edk2toolext.capsule import pyopenssl_signer
from edk2toolext.capsule import signtool_signer

PYOPENSSL_SIGNER = 'pyopenssl'
SIGNTOOL_SIGNER = 'signtool'
PYPATH_MODULE_SIGNER = 'pymodule'
LOCAL_MODULE_SIGNER = 'local_module'

def get_signer(type):
  if type == PYOPENSSL_SIGNER:
    return pyopenssl_signer
  elif type == SIGNTOOL_SIGNER:
    return signtool_signer
  elif type == PYPATH_MODULE_SIGNER:
    # TODO: Import thing from the pypath.
    pass
  elif type == LOCAL_MODULE_SIGNER:
    # TODO: Import file.
    pass
  else:
    return None
