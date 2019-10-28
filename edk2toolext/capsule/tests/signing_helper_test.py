## @file signing_helper_test.py
# This unittest module contains test cases for the signing_helper module.
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


import os
import unittest

from edk2toolext.capsule import signing_helper


class SignerLocationTests(unittest.TestCase):
    def test_should_be_able_to_fetch_a_builtin_signer_module(self):
        pysigner = signing_helper.get_signer(signing_helper.PYOPENSSL_SIGNER)
        self.assertTrue(hasattr(pysigner, 'sign'))

        signtoolsigner = signing_helper.get_signer(signing_helper.SIGNTOOL_SIGNER)
        self.assertTrue(hasattr(signtoolsigner, 'sign'))

    def test_should_be_able_to_pass_a_signing_module(self):
        pysigner = signing_helper.get_signer(
            signing_helper.PYPATH_MODULE_SIGNER,
            'edk2toolext.capsule.pyopenssl_signer'
        )
        self.assertTrue(hasattr(pysigner, 'sign'))

    def test_should_be_able_to_fetch_a_user_provided_signer_module(self):
        test_script_path = os.path.dirname(os.path.abspath(__file__))
        pysigner_path = os.path.join(os.path.dirname(test_script_path), 'pyopenssl_signer.py')
        self.assertTrue(os.path.isfile(pysigner_path))
        pysigner = signing_helper.get_signer(signing_helper.LOCAL_MODULE_SIGNER, pysigner_path)
        self.assertTrue(hasattr(pysigner, 'sign'))

# NOTE: These tests may not run on non-Windows or without the WDK installed.
# class SigntoolSignerModuleTest(unittest.TestCase):
#     def test_module_should_be_able_to_locate_signtool(self):
#         signtoolsigner = signing_helper.get_signer(signing_helper.SIGNTOOL_SIGNER)
#         self.assertTrue(os.path.isfile(signtoolsigner.get_signtool_path()))
