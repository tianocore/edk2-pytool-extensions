# @file test_docgen.py
# This contains unit tests for the document generation
##
# Copyright (c) Microsoft Corporation
#
# SPDX-License-Identifier: BSD-2-Clause-Patent
##
import os
import unittest
import tempfile
from edk2toolext.docgen import generate
import sys


class Test_DocGenerator(unittest.TestCase):

    def test_can_create_generator(self):
        docgen = generate.DocGenerator()
        self.assertIsNotNone(docgen)

    def test_can_setup_generator(self):
        default_config = {
            "site_name": "edk2-pytool-extensions",
            "repo_url": "https://github.com/tianocore/edk2-pytool-extensions",
            "copyright": "SPDX-License-Identifier: BSD-2-Clause-Patent",
            "site_description": "Python tools supporting UEFI EDK2 firmware development",
            "site_url": "https://tianocore.github.io/edk2-pytool-extensions"
        }
        docgen = generate.DocGenerator()
        workspace = os.path.abspath(os.path.dirname(os.path.dirname(__file__)))
        docgen.set_workspace(workspace)
        docgen.set_config_defaults(**default_config)
        docgen.set_verbose(True)
        docgen.set_should_include_test_documentation(False)
        docgen.add_doc_folder(os.path.join(workspace, "docs"))
        docgen.set_target_module(os.path.join(workspace, "edk2toolext"))

        docgen.set_hook(docgen.Hooks.PostSetup, lambda: sys.exit(0))
        try:
            docgen.generate()
            self.fail()
        except SystemExit:
            pass

    def test_friendly_naming(self):
        test1 = generate.DocGenerator.ConvertToFriendlyName("test_one")
        self.assertEqual(test1, "Test One")
        test1 = generate.DocGenerator.ConvertToFriendlyName("test__one")
        self.assertEqual(test1, "Test One")
        test1_2 = generate.DocGenerator.ConvertToFriendlyName("TestOne")
        self.assertEqual(test1_2, "Test One")

        test_markdown_path = tempfile.mktemp(".md")
        with open(test_markdown_path, "w") as markdown_file:
            markdown_file.write(" # Test two\n This is a file\n## Test\n Bad # Times")
            markdown_file.close()
        test_markdown = generate.DocGenerator.ConvertToFriendlyName(test_markdown_path)
        self.assertEqual(test_markdown, "Test Two")
