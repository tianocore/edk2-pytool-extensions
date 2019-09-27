# @file test_uefi_build.py
# Unit test suite for the UefiBuilder class.
#
##
# Copyright (c) Microsoft Corporation
#
# SPDX-License-Identifier: BSD-2-Clause-Patent
##
import unittest
from edk2toolext.environment import uefi_build


class TestUefiBuild(unittest.TestCase):
    def setUp(self):
        pass

    def tearDown(self):
        pass

    @classmethod
    def setUpClass(cls):
        pass

    @classmethod
    def tearDownClass(cls):
        pass

    def test_init(self):
        builder = uefi_build.UefiBuilder()
        self.assertIsNotNone(builder)


if __name__ == '__main__':
    unittest.main()
