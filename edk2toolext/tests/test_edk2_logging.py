## @file test_edk2_logging.py
# This contains unit tests for the edk2_logging
##
# Copyright (c) Microsoft Corporation
#
# SPDX-License-Identifier: BSD-2-Clause-Patent
##
import os
import tempfile
import unittest
import logging
from edk2toolext import edk2_logging


class Test_edk2_logging(unittest.TestCase):

    def test_can_create_console_logger(self):
        console_logger = edk2_logging.setup_console_logging(False, False)
        self.assertIsNot(console_logger, None, "We created a console logger")
        edk2_logging.stop_logging(console_logger)

    def test_can_create_txt_logger(self):
        test_dir = tempfile.mkdtemp()
        location, txt_logger = edk2_logging.setup_txt_logger(test_dir, "test_txt")
        logging.info("Testing")
        self.assertTrue(os.path.isfile(location), "We should have created a file")
        self.assertIsNot(txt_logger, None, "We created a txt logger")
        edk2_logging.stop_logging(txt_logger)

    def test_can_create_md_logger(self):
        test_dir = tempfile.mkdtemp()
        location, txt_logger = edk2_logging.setup_markdown_logger(test_dir, "test_md")
        logging.info("Testing")
        self.assertTrue(os.path.isfile(location), "We should have created a file")
        self.assertIsNot(txt_logger, None, "We created a txt logger")
        edk2_logging.stop_logging(txt_logger)

    def test_none_to_close(self):
        edk2_logging.stop_logging(None)

    def test_can_close_logger(self):
        test_dir = tempfile.mkdtemp()
        location, txt_logger = edk2_logging.setup_txt_logger(test_dir, "test_close")
        logging.critical("Testing")
        self.assertTrue(os.path.isfile(location), "We should have created a file")
        file = open(location, "r")
        num_lines = len(file.readlines())
        file.close()
        self.assertEqual(num_lines, 1, "We should only have one line")
        edk2_logging.stop_logging(txt_logger)
        logging.critical("Test 2")
        file = open(location, "r")
        num_lines2 = len(file.readlines())
        file.close()
        self.assertEqual(num_lines, num_lines2, "We should only have one line")


if __name__ == '__main__':
    unittest.main()
