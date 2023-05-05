## @file capsule_tool_test.py
# This unittest module contains test cases for the capsule_tool module and CLI routines.
#
##
# Copyright (C) Microsoft Corporation
#
# SPDX-License-Identifier: BSD-2-Clause-Patent
##


import os
import unittest
import tempfile
import json
import yaml

from edk2toolext.capsule import capsule_tool

DUMMY_OPTIONS = {
    'capsule': {
        'option1': 'value1'
    },
    'signer': {
        'option2': 'value2',
        'option_not': 'orig_value'
    }
}
DUMMY_OPTIONS_FILE_NAME = 'dummy_options_file'
DUMMY_PAYLOAD_FILE_NAME = 'dummy_payload'


class ParameterParsingTest(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        # We'll use the one-time setup to create
        # any temporary test files we'll need.
        cls.temp_dir = tempfile.mkdtemp()
        cls.dummy_json_options = os.path.join(cls.temp_dir, DUMMY_OPTIONS_FILE_NAME + ".json")
        cls.dummy_yaml_options = os.path.join(cls.temp_dir, DUMMY_OPTIONS_FILE_NAME + ".yaml")
        cls.dummy_payload = os.path.join(cls.temp_dir, DUMMY_PAYLOAD_FILE_NAME + ".bin")

        with open(cls.dummy_json_options, 'w') as dummy_file:
            json.dump(DUMMY_OPTIONS, dummy_file)
        with open(cls.dummy_yaml_options, 'w') as dummy_file:
            yaml.dump(DUMMY_OPTIONS, dummy_file)
        with open(cls.dummy_payload, 'wb') as dummy_file:
            dummy_file.write(b'DEADBEEF')

    @unittest.skip("test is incomplete")
    def test_should_require_a_signer_option(self):
        pass

    def test_capsule_options_should_be_passable(self):
        cli_params = ['--builtin_signer', 'pyopenssl']
        parsed_args = capsule_tool.get_cli_options(cli_params + [self.dummy_payload, self.temp_dir])
        self.assertEqual(len(parsed_args.capsule_options), 0)

        cli_params += ['-dc', 'option1=value1']
        cli_params += ['-dc', 'option2=value2']
        cli_params += [self.dummy_payload, self.temp_dir]
        parsed_args = capsule_tool.get_cli_options(cli_params)
        self.assertEqual(len(parsed_args.capsule_options), 2)

    def test_signer_options_should_be_passable(self):
        cli_params = ['--builtin_signer', 'pyopenssl']
        parsed_args = capsule_tool.get_cli_options(cli_params + [self.dummy_payload, self.temp_dir])
        self.assertEqual(len(parsed_args.signer_options), 0)

        cli_params += ['-ds', 'option1=value1']
        cli_params += ['-ds', 'option2=value2']
        cli_params += [self.dummy_payload, self.temp_dir]
        parsed_args = capsule_tool.get_cli_options(cli_params)
        self.assertEqual(len(parsed_args.signer_options), 2)

    def test_should_not_accept_an_invalid_path(self):
        cli_params = ['--builtin_signer', 'pyopenssl']
        cli_params += ['-o', 'not_a_path.bin']
        cli_params += [self.dummy_payload]
        with self.assertRaises(SystemExit):
            capsule_tool.get_cli_options(cli_params)

    def test_should_not_load_an_invalid_path(self):
        bad_path = 'not_a_path.bin'
        loaded_options = capsule_tool.load_options_file(bad_path)
        self.assertEqual(loaded_options, None)

    def test_options_file_should_load_json(self):
        with open(self.dummy_json_options, 'r') as options_file:
            loaded_options = capsule_tool.load_options_file(options_file)

        self.assertEqual(loaded_options['capsule']['option1'], 'value1')
        self.assertEqual(loaded_options['signer']['option2'], 'value2')

    def test_options_file_should_load_yaml(self):
        with open(self.dummy_yaml_options, 'r') as options_file:
            loaded_options = capsule_tool.load_options_file(options_file)

        self.assertEqual(loaded_options['capsule']['option1'], 'value1')
        self.assertEqual(loaded_options['signer']['option2'], 'value2')

    # @pytest.mark.skip(reason="test is incomplete")
    def test_cli_options_should_override_file_options(self):
        capsule_cli_options = ['option1=value2', 'new_option=value3']
        signer_cli_options = ['option2=value7', 'option2=value8']

        final_options = capsule_tool.update_options(DUMMY_OPTIONS, capsule_cli_options, signer_cli_options)

        self.assertEqual(final_options['capsule']['option1'], 'value2')
        self.assertEqual(final_options['capsule']['new_option'], 'value3')
        self.assertEqual(final_options['signer']['option2'], 'value8')
        self.assertEqual(final_options['signer']['option_not'], 'orig_value')

    def test_full_options_path_should_work(self):
        # Parse the command parameters.
        cli_params = ['--builtin_signer', 'pyopenssl']
        cli_params += ['-o', self.dummy_json_options]
        cli_params += ['-dc', 'option1=value2']
        cli_params += ['-dc', 'new_option=value3']
        cli_params += ['-ds', 'option2=value7']
        cli_params += ['-ds', 'option2=value8']
        cli_params += [self.dummy_payload, self.temp_dir]
        parsed_args = capsule_tool.get_cli_options(cli_params)

        loaded_options = capsule_tool.load_options_file(parsed_args.options_file)
        final_options = capsule_tool.update_options(
            loaded_options,
            parsed_args.capsule_options,
            parsed_args.signer_options
        )

        self.assertEqual(final_options['capsule']['option1'], 'value2')
        self.assertEqual(final_options['capsule']['new_option'], 'value3')
        self.assertEqual(final_options['signer']['option2'], 'value8')
        self.assertEqual(final_options['signer']['option_not'], 'orig_value')
