# @file gen_api.py
#
##
# Copyright (c) Microsoft Corporation
#
# SPDX-License-Identifier: BSD-2-Clause-Patent
##
"""Python script used to automatically generate API Reference documentation.

Used in conjunction with mkdocs to generate static markdown files for each
file inside the edk2toolext package for ReadTheDocs hosting.
"""
import mkdocs_gen_files
import glob
import os


def main():
    """Entry into script that is executed."""
    files = glob.glob("**/*.py", recursive=True, root_dir="edk2toolext")

    excluded_files = ["__init__.py", "capsule_helper.py", "capsule_tool.py", "pyopenssl_signer.py",
                      "signing_helper.py", "signtool_signer.py", "sig_db_tool.py",
                      "firmware_policy_tool.py", "image_validation.py", "nuget_publishing.py",
                      "omnicache.py", "nuget.py", "versioninfo_tool.py", "versioninfo_helper.py",
                      "secureboot_audit.py"]

    for file_path in files:
        edit_path = file_path
        # __init__ file excluded as they provide no API's that needs to be generated
        # tool files excluded as they have entire readmes on how to use the tool
        if file_path.split(os.sep)[-1] in excluded_files:
            continue

        # tests are excluded as no API reference is necessary
        if file_path.startswith("tests"):
            continue

        file_path = file_path.replace(".py", ".md")

        filename = f"api{os.sep}{file_path}"
        with mkdocs_gen_files.open(filename, "w") as f:
            ff = file_path.replace(os.sep, '.').replace('.md', '')
            ff = f"edk2toolext.{ff}"
            print(f"::: {ff}", file=f)
            print("    handler: python", file=f)
            print("    options:", file=f)
            print("        show_bases: False", file=f)
            print("        show_root_heading: True", file=f)
            print("        show_root_full_path: False", file=f)
            print("        show_signature_annotations: True", file=f)
            print("        separate_signature: True", file=f)
            print("        members_order: 'source'", file=f)
            print("        show_source: False", file=f)

        # Point the "Edit on Github" button in the docs to point at the source code
        edit_path = os.path.join('..', 'edk2toolext', edit_path)
        mkdocs_gen_files.set_edit_path(filename, edit_path)
    
    with mkdocs_gen_files.open("api/.pages", "w") as f:
        print("title: API Reference", file=f)


main()
