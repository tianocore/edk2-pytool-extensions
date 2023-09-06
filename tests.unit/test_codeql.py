# @file utility_functions_test.py
# unit test for utility_functions module.
#
#
# Copyright (c) Microsoft Corporation
#
# SPDX-License-Identifier: BSD-2-Clause-Patent
##
"""CodeQL module unit tests."""

import unittest
from argparse import ArgumentParser, Namespace
from unittest.mock import Mock, patch

import edk2toolext.codeql as codeql


class CodeQlTests(unittest.TestCase):
    """CodeQL unit tests."""

    def test_codeql_option(self):
        """Tests that common line options are added as expected."""
        parser = ArgumentParser()
        codeql.add_command_line_option(parser)

        # Test that the default value is False
        args = parser.parse_args([])
        self.assertFalse(args.codeql)

        # Test that the option sets the value to True
        args_with_option = parser.parse_args(['--codeql'])
        self.assertTrue(args_with_option.codeql)

    @patch('edk2toolext.codeql.GetHostInfo')
    def test_codeql_enabled_linux(self, mock_host_info):
        """Tests that the proper scope is returned on a Linux host."""
        mock_host_info.return_value.os = "Linux"
        result = codeql.get_scopes(codeql_enabled=True)
        expected_result = ("codeql-linux-ext-dep", "codeql-build",
                           "codeql-analyze")
        self.assertEqual(result, expected_result)

    @patch('edk2toolext.codeql.GetHostInfo')
    def test_codeql_enabled_windows(self, mock_host_info):
        """Tests that the proper scope is returned on a Windows host."""
        mock_host_info.return_value.os = "Windows"
        result = codeql.get_scopes(codeql_enabled=True)
        expected_result = ("codeql-windows-ext-dep", "codeql-build",
                           "codeql-analyze")
        self.assertEqual(result, expected_result)

    @patch('edk2toolext.codeql.GetHostInfo')
    def test_codeql_disabled(self, mock_host_info):
        """Tests that the proper scopes are returned if CodeQL is disabled."""
        result = codeql.get_scopes(codeql_enabled=False)
        expected_result = ()
        self.assertEqual(result, expected_result)

    def test_codeql_enabled(self):
        """Tests that CodeQL is recognized on the command-line properly."""
        mock_args = Namespace(codeql=True)
        result = codeql.is_codeql_enabled_on_command_line(mock_args)
        self.assertTrue(result)

    def test_codeql_not_enabled(self):
        """Tests that CodeQL is recognized on the command-line properly."""
        mock_args = Namespace(codeql=False)
        result = codeql.is_codeql_enabled_on_command_line(mock_args)
        self.assertFalse(result)

    def test_set_audit_only_mode(self):
        """Tests that CodeQL audit mode is enabled as expected."""
        mock_uefi_builder = Mock()
        codeql.set_audit_only_mode(mock_uefi_builder)
        mock_uefi_builder.env.SetValue.assert_called_once_with(
            "STUART_CODEQL_AUDIT_ONLY",
            "true",
            "Platform Defined")
