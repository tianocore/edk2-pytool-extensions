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

default_config = {
    "site_name": "edk2-pytool-extensions",
    "repo_url": "https://github.com/tianocore/edk2-pytool-extensions",
    "copyright": "SPDX-License-Identifier: BSD-2-Clause-Patent",
    "site_description": "Python tools supporting UEFI EDK2 firmware development",
    "site_url": "https://tianocore.github.io/edk2-pytool-extensions"
}


class Test_DocGenerator(unittest.TestCase):

    def test_can_create_generator(self):
        docgen = generate.DocGenerator()
        self.assertIsNotNone(docgen)

    def test_can_setup_generator(self):
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

    def test_needs_default_config(self):
        docgen = generate.DocGenerator()
        workspace = tempfile.mkdtemp()
        docgen.set_workspace(workspace)
        docgen.set_should_include_test_documentation(False)
        docgen.set_target_module("edk2toolext")

        try:
            docgen.generate()
            self.fail()
        except ValueError:
            pass

    def test_generate_documentation(self):
        docgen = generate.DocGenerator()
        workspace = tempfile.mkdtemp()
        docgen.set_workspace(workspace)
        docgen.set_config_defaults(**default_config)
        docgen.set_target_module("edk2toolext", default_config["site_name"])
        # make sure out output docs make sense
        rel_path = os.path.relpath(docgen.get_output_docs_dir(), workspace)
        self.assertNotIn("..", rel_path)
        # make sure we don't generate html
        docgen.set_hook(docgen.Hooks.PreHtml, lambda: sys.exit(0))
        try:
            docgen.generate()
            self.fail()
        except SystemExit:
            # TODO: check that ret code is 0
            pass
        config = docgen.dump_config()
        self.assertIn("nav", config)
        print(len(config["nav"]))
        self.assertGreater(len(config["nav"]), 1)


test = Test_DocGenerator()
test.test_generate_documentation()
