# @file
#
# Command-line tool to patch a variable store in a ROM image.

# Copyright (c) Microsoft Corporation
#
# SPDX-License-Identifier: BSD-2-Clause-Patent
##

"""Tool for patching a variable store in a ROM image.

Patches the variable store in a ROM image based on a provided XML script file.
"""

import argparse
import base64
import binascii
import os
import uuid
import xml.etree.ElementTree as ET
from typing import Dict, List

import edk2toollib.uefi.edk2.variable_format as VF
import edk2toollib.uefi.edk2.variablestore_manulipulations as VarStore


def GatherArguments() -> argparse.Namespace:
    """Gather command-line arguments for the script.

    Returns:
        argparse.Namespace: Parsed command-line arguments.
    """
    parser = argparse.ArgumentParser(description="Process a command script to alter a ROM image varstore.")
    parser.add_argument("rom_file", type=str, help="The rom file that will be read and/or modified")
    parser.add_argument(
        "var_store_base",
        type=str,
        help="The hex offset of the var store FV within the ROM image",
    )
    parser.add_argument(
        "var_store_size",
        type=str,
        help="The hex size of the var store FV within the ROM image",
    )
    parser.add_argument(
        "-s",
        "--set",
        metavar="set_script",
        dest="set_file",
        type=str,
        help="A script file containing variables that should be updated or created in the variable store",
    )

    return parser.parse_args()


def load_variable_xml(xml_file_path: str) -> List[Dict]:
    """Load the variable XML file and return a list of variables.

    Args:
        xml_file_path (str): The XML file path to load.

    Raises:
        Exception: If an unknown data type is found in the XML file.

    Returns:
        list: A list of dictionaries containing variable information.
    """
    loaded_xml_tree = ET.parse(xml_file_path)
    loaded_xml = loaded_xml_tree.getroot()

    loaded_vars = []
    for node in loaded_xml.findall("Variable"):
        new_var = {
            "name": node.find("Name").text,
            "guid": uuid.UUID(node.find("GUID").text),
            "attributes": int(node.find("Attributes").text, 16),
        }

        # Make sure we can process the data.
        DataType = node.find("Data").get("type")
        if DataType != "hex" and DataType != "b64":
            raise Exception("Unknown data type '%s' found!" % DataType)

        # Update the node data.
        if DataType == "hex":
            new_var["data"] = binascii.unhexlify(node.find("Data").text.strip())

        if DataType == "b64":
            new_var["data"] = base64.b64decode(node.find("Data").text.strip())

        # Add the var to the list.
        loaded_vars.append(new_var)

    return loaded_vars


def patch_variables(set_vars: list[Dict], var_store: VarStore.VariableStore) -> List[str]:
    """Patch UEFI variables in the variable store based on the provided list.

    Args:
        set_vars (list[Dict]): List of dictionaries containing variable information.
        var_store (VarStore.VariableStore): The variable store to patch.

    Returns:
        List[str]: List of variables that need to be created.
    """
    create_vars = []

    # Walk through all the script variables...
    # Then walk through all existing variables in the var store...
    # If we find a match, we can update it in place.
    # Otherwise, add it to a list to create later.
    for set_var in set_vars:
        match_found = False

        for var in var_store.variables:
            if var.Name == set_var["name"] and var.VendorGuid == set_var["guid"] and var.State == VF.VAR_ADDED:
                print(f"Updating Var '{var.VendorGuid}:{var.Name}'...")

                match_found = True
                var.Attributes = set_var["attributes"]
                var.set_data(set_var["data"])

        if not match_found:
            create_vars.append(set_var)

    return create_vars


def create_variables(create_vars: list[Dict], var_store: VarStore.VariableStore) -> None:
    """Create UEFI variables from a list of variable information.

    Args:
        create_vars (list[Dict]): List of dictionaries containing variable information.
        var_store (VarStore.VariableStore): The variable store to add variables to.
    """
    for create_var in create_vars:
        print(f"Creating Var '{create_var['guid']}:{create_var['name']}'...")

        new_var = var_store.get_new_var_class()
        new_var.Attributes = create_var["attributes"]
        new_var.VendorGuid = create_var["guid"]
        new_var.set_name(create_var["name"])
        new_var.set_data(create_var["data"])

        var_store.variables.append(new_var)


def main() -> None:
    """Main function to execute the script."""
    args = GatherArguments()

    if args.set_file is not None and not os.path.isfile(args.set_file):
        raise Exception(f"Set Script path '{args.set_file}' does not point to a valid file!")

    # Load the variable store from the file.
    var_store = VarStore.VariableStore(
        args.rom_file,
        store_base=int(args.var_store_base, 16),
        store_size=int(args.var_store_size, 16),
    )

    # Print information about the current variables.
    for var in var_store.variables:
        if var.State == VF.VAR_ADDED:
            print(f"Var Found: '{var.VendorGuid}:{var.Name}'")

    # Attempt to load the set script file.
    set_vars = load_variable_xml(args.set_file)

    # Attempt to patch existing variables in the var store.
    create_vars = patch_variables(set_vars, var_store)

    # If we had variables we were unable to update, let's create them now.
    create_variables(create_vars, var_store)

    var_store.flush_to_file()


if __name__ == "__main__":
    main()
