## @file test_capsule_signer.py
# This contains unit tests for the capsule_signer
##
# Copyright (c) Microsoft Corporation
#
# SPDX-License-Identifier: BSD-2-Clause-Patent
##
import os
import unittest
import logging
from edk2toolext.capsule import capsule_signer


class CapsuleSignerTest(unittest.TestCase):

    should be able to pass a signing module
    signature options should be passed to signing module
    signer options should be passed to signing module
    should be able to set the guid

    should be able to generate a production equivalent capsule

    enumerate all of the things that need to be passed for this signer

    def test_can_create_console_logger(self):
        console_logger = capsule_signer.setup_console_logging(False, False)
        self.assertIsNot(console_logger, None, "We created a console logger")
        capsule_signer.stop_logging(console_logger)

    def test_can_create_txt_logger(self):
        test_dir = tempfile.mkdtemp()
        location, txt_logger = capsule_signer.setup_txt_logger(test_dir, "test_txt")
        logging.info("Testing")
        self.assertTrue(os.path.isfile(location), "We should have created a file")
        self.assertIsNot(txt_logger, None, "We created a txt logger")
        capsule_signer.stop_logging(txt_logger)

    def test_can_create_md_logger(self):
        test_dir = tempfile.mkdtemp()
        location, txt_logger = capsule_signer.setup_markdown_logger(test_dir, "test_md")
        logging.info("Testing")
        self.assertTrue(os.path.isfile(location), "We should have created a file")
        self.assertIsNot(txt_logger, None, "We created a txt logger")
        capsule_signer.stop_logging(txt_logger)

    def test_none_to_close(self):
        capsule_signer.stop_logging(None)

    def test_can_close_logger(self):
        test_dir = tempfile.mkdtemp()
        location, txt_logger = capsule_signer.setup_txt_logger(test_dir, "test_close")
        logging.critical("Testing")
        self.assertTrue(os.path.isfile(location), "We should have created a file")
        file = open(location, "r")
        num_lines = len(file.readlines())
        file.close()
        self.assertEqual(num_lines, 1, "We should only have one line")
        capsule_signer.stop_logging(txt_logger)
        logging.critical("Test 2")
        file = open(location, "r")
        num_lines2 = len(file.readlines())
        file.close()
        self.assertEqual(num_lines, num_lines2, "We should only have one line")

class SigningHelperTest(unittest.TestCase):
    should be able to fetch a builtin signer module
    should be able to fetch a user provided signer module

if __name__ == '__main__':
    unittest.main()
