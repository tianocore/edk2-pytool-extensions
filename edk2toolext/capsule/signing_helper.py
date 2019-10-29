# @file signing_helper.py
# This module contains code to help with the selection and loading of a signer module.
# These signer modules can be built-in to the edk2toolext module, loaded from other Pip
# or Python modules that are on the current pypath, or passed as a file path to a
# local Python module that should be dynamically loaded.
#
##
# Copyright (C) Microsoft Corporation
#
# All rights reserved.
# Redistribution and use in source and binary forms, with or without
# modification, are permitted provided that the following conditions are met:
# 1. Redistributions of source code must retain the above copyright notice,
# this list of conditions and the following disclaimer.
# 2. Redistributions in binary form must reproduce the above copyright notice,
# this list of conditions and the following disclaimer in the documentation
# and/or other materials provided with the distribution.
#
# THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS" AND
# ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED
# WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE DISCLAIMED.
# IN NO EVENT SHALL THE COPYRIGHT HOLDER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT,
# INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING,
# BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE,
# DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF
# LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE
# OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF
# ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
##


import importlib

from edk2toolext.capsule import pyopenssl_signer
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
        return pyopenssl_signer
    elif type == SIGNTOOL_SIGNER:
        return signtool_signer
    elif type == PYPATH_MODULE_SIGNER:
        return importlib.import_module(specifier)
    elif type == LOCAL_MODULE_SIGNER:
        return import_module_by_file_name(specifier)
    else:
        return None
