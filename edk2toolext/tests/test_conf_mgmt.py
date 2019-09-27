# @file test_conf_mgmt.py
# Unit test suite for the ConfMgmt class.
#
##
# Copyright (c) Microsoft Corporation
#
# SPDX-License-Identifier: BSD-2-Clause-Patent
##
import unittest
from edk2toolext.environment import conf_mgmt


class TestConfMgmt(unittest.TestCase):
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
        # we should throw an error if we haven't set our workspace
        with self.assertRaises(EnvironmentError):
            conf_mgmt.ConfMgmt(None, None)

    # TODO: finish unit test


if __name__ == '__main__':
    unittest.main()
