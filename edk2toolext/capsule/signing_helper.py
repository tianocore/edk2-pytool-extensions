# @file signing_helper.py
# This module contains code to help with the selection and loading of a signer module.
# These signer modules can be built-in to the edk2toolext module, loaded from other Pip
# or Python modules that are on the current pypath, or passed as a file path to a
# local Python module that should be dynamically loaded.
#
##
# Copyright (C) Microsoft Corporation
#
# SPDX-License-Identifier: BSD-2-Clause-Patent
##


import importlib

from edk2toolext.capsule import signtool_signer
from edk2toollib.utility_functions import import_module_by_file_name

# Valid types.
PYOPENSSL_SIGNER = 'pyopenssl'
SIGNTOOL_SIGNER = 'signtool'
PYPATH_MODULE_SIGNER = 'pymodule'
LOCAL_MODULE_SIGNER = 'local_module'


def get_signer(type, specifier=None):
    '''
    based on the type and optional specifier, load a signer module and return it

    if type is PYPATH_MODULE_SIGNER, the specifier should be the Python module
        package/namespace path
        example: edk2toolext.capsule.pyopenssl_signer

    if the type is LOCAL_MODULE_SIGNER, the specifier should be a filesystem
        path to a Python module that can be loaded as the signer
    '''
    if type == PYOPENSSL_SIGNER:
        try:
            from edk2toolext.capsule import pyopenssl_signer
            return pyopenssl_signer
        except ModuleNotFoundError:
            raise RuntimeError('PyOpenSsl Signer failed to load. Do you have pyopenssl installed?')
    elif type == SIGNTOOL_SIGNER:
        return signtool_signer
    elif type == PYPATH_MODULE_SIGNER:
        return importlib.import_module(specifier)
    elif type == LOCAL_MODULE_SIGNER:
        return import_module_by_file_name(specifier)
    else:
        return None
