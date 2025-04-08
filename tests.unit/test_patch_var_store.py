# @file test.patch_var_store.py
# unit test for patch_var_store.
#
# Copyright (c) Microsoft Corporation
#
# SPDX-License-Identifier: BSD-2-Clause-Patent
##
"""Patch Var Store module unit tests."""

import base64
import os
import tempfile
import unittest
import uuid
from argparse import ArgumentParser
from unittest.mock import MagicMock

import edk2toolext.uefi.patch_var_store as patch_var_store
import edk2toollib.uefi.edk2.variable_format as VF
from edk2toollib.uefi.edk2.variablestore_manulipulations import VariableStore
from edk2toollib.utility_functions import RemoveTree

test_dir = None


def prep_workspace() -> None:
    """Prepare the workspace for testing."""
    global test_dir
    # if test temp dir doesn't exist
    if test_dir is None or not os.path.isdir(test_dir):
        test_dir = tempfile.mkdtemp()
    else:
        RemoveTree(test_dir)
        test_dir = tempfile.mkdtemp()


def clean_workspace() -> None:
    """Clean up the workspace."""
    global test_dir
    if test_dir is None:
        return

    if os.path.isdir(test_dir):
        RemoveTree(test_dir)
        test_dir = None


class PatchVarStoreTests(unittest.TestCase):
    """Patch Var Store unit tests."""

    class MockVarStore(VariableStore):
        """Mock Variable Store."""

        def __init__(self) -> None:
            """Initialize the mock variable store."""
            self.variables = {}

    def setup(self) -> None:
        """Setup for the tests."""
        self.parser = ArgumentParser()
        patch_var_store.GatherArguments(self.parser)

    @classmethod
    def tearDownClass(cls) -> None:
        """TestCase Function override."""
        clean_workspace()

    def test_patch_variables(self) -> None:
        """Tests that the patch_variables function works correctly."""
        # Mock the arguments
        mock_patch_vars = [
            {
                "name": "MockVariable1",
                "guid": uuid.uuid4(),
                "attributes": "0x0000000000000001",
                "data": base64.b64encode(b"MockData1"),
            },
            {
                "name": "MockVariable2",
                "guid": uuid.uuid4(),
                "attributes": "0x0000000000000002",
                "data": base64.b64encode(b"MockData2"),
            },
        ]

        var_headers = []
        for var in mock_patch_vars:
            var_header = VF.VariableHeader()
            var_header.Name = var["name"]
            var_header.VendorGuid = var["guid"]
            var_header.Attributes = int(var["attributes"], 16)
            var_header.State = VF.VAR_ADDED
            var_header.set_data(base64.b64encode(b"OriginalData_"))
            var_headers.append(var_header)

        # Create a mock variable store with var_headers populated
        var_store = self.MockVarStore()
        var_store.rom_file = None
        var_store.rom_file_map = None
        var_store.variables = var_headers

        self.assertEqual(len(var_store.variables), 2)
        self.assertEqual(var_headers[0].Name, "MockVariable1")
        self.assertEqual(var_headers[0].VendorGuid, mock_patch_vars[0]["guid"])
        self.assertEqual(var_headers[0].Attributes, int(mock_patch_vars[0]["attributes"], 16))
        self.assertEqual(var_headers[0].State, VF.VAR_ADDED)
        self.assertEqual(var_headers[0].Data, base64.b64encode(b"OriginalData_"))

        # Call the function to test patching the data value
        patch_var_store.patch_variables(mock_patch_vars, var_store)

        self.assertEqual(len(var_store.variables), 2)
        self.assertEqual(var_headers[0].Name, "MockVariable1")
        self.assertEqual(var_headers[0].VendorGuid, mock_patch_vars[0]["guid"])
        self.assertEqual(var_headers[0].Attributes, mock_patch_vars[0]["attributes"], 16)
        self.assertEqual(var_headers[0].State, VF.VAR_ADDED)
        self.assertEqual(var_headers[0].Data, mock_patch_vars[0]["data"])

        self.assertEqual(var_headers[1].Name, "MockVariable2")
        self.assertEqual(var_headers[1].VendorGuid, mock_patch_vars[1]["guid"])
        self.assertEqual(var_headers[1].Attributes, mock_patch_vars[1]["attributes"], 16)
        self.assertEqual(var_headers[1].State, VF.VAR_ADDED)
        self.assertEqual(var_headers[1].Data, mock_patch_vars[1]["data"])

    def test_load_variable_xml(self) -> None:
        """Tests that the load_variable_xml function works correctly."""
        global test_dir

        prep_workspace()

        # Create a mock XML file
        xml_content = """<?xml version="1.0"?>
                        <Variables>
                            <Variable>
                                <Name>MockVariable1</Name>
                                <GUID>12345678-1234-5678-1234-567812345678</GUID>
                                <Attributes>0x0000000000000001</Attributes>
                                <Data type="hex">12345678</Data>
                            </Variable>
                            <Variable>
                                <Name>MockVariable2</Name>
                                <GUID>87654321-4321-6789-4321-678943216789</GUID>
                                <Attributes>0x0000000000000002</Attributes>
                                <Data type="hex">87654321</Data>
                            </Variable>
                        </Variables>
                        """
        xml_file_path = os.path.join(test_dir, "mock_variable.xml")
        with open(xml_file_path, "w") as xml_file:
            xml_file.write(xml_content)

        # Call the function to test
        variables = patch_var_store.load_variable_xml(xml_file_path)

        # Check that the variables were loaded correctly
        self.assertEqual(len(variables), 2)
        self.assertEqual(variables[0]["name"], "MockVariable1")
        self.assertEqual(
            variables[0]["guid"],
            uuid.UUID("12345678-1234-5678-1234-567812345678"),
        )
        self.assertEqual(variables[0]["attributes"], 0x0000000000000001)
        self.assertEqual(variables[0]["data"], b"\x124Vx")

        os.remove(xml_file_path)
        clean_workspace()

    def test_create_variables(self) -> None:
        """Tests that the create_variables function works correctly."""
        # Create a mock variable list
        variables = [
            {
                "name": "MockVariable1",
                "guid": str(uuid.uuid4()),
                "attributes": 0x0000000000000001,
                "data": b"MockData1",
            },
            {
                "name": "MockVariable2",
                "guid": str(uuid.uuid4()),
                "attributes": 0x0000000000000002,
                "data": b"MockData2",
            },
        ]

        var_store = self.MockVarStore()
        var_store.rom_file_map = None
        var_store.rom_file = None
        var_store.var_store_header = MagicMock()
        var_store.variables = []
        var_store.var_store_header.Type = "Var"

        # Call the function to test
        patch_var_store.create_variables(variables, var_store)

        # Check that the variables were created correctly
        self.assertEqual(len(var_store.variables), 2)
        self.assertEqual(var_store.variables[0].Name, "MockVariable1")
        self.assertEqual(
            var_store.variables[0].VendorGuid,
            variables[0]["guid"],
        )
        self.assertEqual(var_store.variables[0].Attributes, variables[0]["attributes"])
        self.assertEqual(var_store.variables[0].State, VF.VAR_ADDED)
        self.assertEqual(var_store.variables[0].Data, b"MockData1")

        self.assertEqual(var_store.variables[1].Name, "MockVariable2")
        self.assertEqual(
            var_store.variables[1].VendorGuid,
            variables[1]["guid"],
        )
        self.assertEqual(var_store.variables[1].Attributes, variables[1]["attributes"])
        self.assertEqual(var_store.variables[1].State, VF.VAR_ADDED)
        self.assertEqual(var_store.variables[1].Data, b"MockData2")
