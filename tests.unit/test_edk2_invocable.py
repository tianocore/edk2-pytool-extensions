# @file test_edk2_invocable.py
# This contains unit tests for the edk2_invocable
##
# Copyright (c) Microsoft Corporation.
#
# SPDX-License-Identifier: BSD-2-Clause-Patent
##
"""Unit tests for the Edk2Invocable module."""

import unittest
from unittest.mock import MagicMock, patch

import edk2toolext.environment.version_aggregator as version_aggregator
from edk2toolext.edk2_invocable import Edk2Invocable


class TestEdk2Invocable(unittest.TestCase):
    """Tests for the Edk2Invocable module."""

    @classmethod
    def _mock_rust_tool_run_cmd_valid(cls, tool_name: str, tool_params: str, **kwargs: dict[str, any]):
        """Returns a set of expected Rust tool versions.

        Args:
            tool_name (str): The name of the tool.
            tool_params (str): Parameters to pass to the tool.
            kwargs (dict[str, any]): A dictionary of parameters to write.

        Returns:
            int: 0 for successful tool invocation. Non-zero for unsuccessful.
        """
        if tool_name == "cargo" and tool_params == "--version":
            kwargs["outstream"].write("cargo 1.10.0")
            return 0
        elif tool_name == "cargo" and tool_params == "make --version":
            kwargs["outstream"].write("cargo make 0.30.0 (abc1234)")
            return 0
        elif tool_name == "rustc":
            kwargs["outstream"].write("rustc 1.10.1")
            return 0
        return 1

    @classmethod
    def _mock_rust_tool_run_cmd_invalid(cls, tool_name: str, tool_params: str, **kwargs: dict[str, any]):
        """Returns an unexpected tool version.

        Args:
            tool_name (str): The name of the tool.
            tool_params (str): Parameters to pass to the tool.
            kwargs (dict[str, any]): A dictionary of parameters to write.

        Returns:
            int: 0 for successful tool invocation.
        """
        kwargs["outstream"].write("unknown version format")
        return 0

    @classmethod
    def _mock_rust_tool_run_cmd_missing(cls, tool_name: str, tool_params: str, **kwargs: dict[str, any]):
        """Returns an unexpected tool version.

        Args:
            tool_name (str): The name of the tool.
            tool_params (str): Parameters to pass to the tool.
            kwargs (dict[str, any]): A dictionary of parameters to write.

        Returns:
            int: 1 indicating an error.
        """
        kwargs["outstream"].write("<rust tool> is not a recognized command.")
        return 1

    @patch("edk2toolext.edk2_invocable.RunCmd")
    def test_collect_rust_info_unknown_ver(self, mock_run_cmd: MagicMock):
        """Verifies a Rust tool with an unknown format raises an exception.

        Args:
            mock_run_cmd (MagicMock): A mock RunCmd object.

        Returns:
            None
        """
        mock_run_cmd.side_effect = self._mock_rust_tool_run_cmd_invalid

        with self.assertRaises(Exception) as context:
            Edk2Invocable.collect_rust_info()

        self.assertTrue("version format is unexpected and cannot be parsed" in str(context.exception))

    @patch("edk2toolext.edk2_invocable.RunCmd")
    @patch("edk2toolext.edk2_invocable.version_aggregator.GetVersionAggregator")
    def test_collect_rust_info_missing_tool(self, mock_get_version_aggregator: MagicMock, mock_run_cmd: MagicMock):
        """Verifies a missing Rust tool returns N/A.

        Some repos may not use the Rust and the users of those repos do not
        need Rust tools installed. In that case, N/A is returned to show that
        the tools were not recognized. The tools could not be reported at all
        but N/A is meant to make the report consistent for comparison purposes.

        Args:
            mock_get_version_aggregator (MagicMock): A mock version_aggregator
            object.
            mock_run_cmd (MagicMock): A mock RunCmd object.


        Returns:
            None
        """
        mock_version_aggregator = MagicMock()
        mock_get_version_aggregator.return_value = mock_version_aggregator
        mock_run_cmd.side_effect = self._mock_rust_tool_run_cmd_missing

        Edk2Invocable.collect_rust_info()

        calls = [(("cargo", "N/A", version_aggregator.VersionTypes.TOOL),)]

        mock_version_aggregator.ReportVersion.assert_has_calls(calls, any_order=True)

    @patch("edk2toolext.edk2_invocable.RunCmd")
    @patch("edk2toolext.edk2_invocable.version_aggregator.GetVersionAggregator")
    def test_collect_rust_info_known_ver(self, mock_get_version_aggregator: MagicMock, mock_run_cmd: MagicMock):
        """Verifies Rust tools with an expected format are successful.

        Verifies the tool information is passed to the version aggregator as
        expected.

        Args:
            mock_get_version_aggregator (MagicMock): A mock version_aggregator
            object.
            mock_run_cmd (MagicMock): A mock RunCmd object.

        Returns:
            None
        """
        mock_version_aggregator = MagicMock()
        mock_get_version_aggregator.return_value = mock_version_aggregator
        mock_run_cmd.side_effect = self._mock_rust_tool_run_cmd_valid

        Edk2Invocable.collect_rust_info()

        calls = [
            (("cargo", "1.10.0", version_aggregator.VersionTypes.TOOL),),
            (("cargo make", "0.30.0", version_aggregator.VersionTypes.TOOL),),
            (("rustc", "1.10.1", version_aggregator.VersionTypes.TOOL),),
        ]

        mock_version_aggregator.ReportVersion.assert_has_calls(calls, any_order=True)
