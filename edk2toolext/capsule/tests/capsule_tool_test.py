import os
import pytest
import unittest
import logging
import tempfile
import json
import yaml

from edk2toolext.capsule import capsule_tool

class ParameterParsingTest(unittest.TestCase):
    @pytest.mark.skip(reason="test is incomplete")
    def test_should_require_a_signer_option(self):
        pass

    def test_capsule_options_should_be_passable(self):
        cli_params = ['--builtin_signer', 'pyopenssl']
        parsed_args = capsule_tool.get_cli_options(cli_params + ['dummy_payload.bin'])
        self.assertEqual(len(parsed_args.capsule_options), 0)

        cli_params += ['-dc', 'option1=value1']
        cli_params += ['-dc', 'option2=value2']
        cli_params += ['dummy_payload.bin']
        parsed_args = capsule_tool.get_cli_options(cli_params)
        self.assertEqual(len(parsed_args.capsule_options), 2)

    def test_signer_options_should_be_passable(self):
        cli_params = ['--builtin_signer', 'pyopenssl']
        parsed_args = capsule_tool.get_cli_options(cli_params + ['dummy_payload.bin'])
        self.assertEqual(len(parsed_args.signer_options), 0)

        cli_params += ['-ds', 'option1=value1']
        cli_params += ['-ds', 'option2=value2']
        cli_params += ['dummy_payload.bin']
        parsed_args = capsule_tool.get_cli_options(cli_params)
        self.assertEqual(len(parsed_args.signer_options), 2)

    def test_should_not_accept_an_invalid_path(self):
        cli_params = ['--builtin_signer', 'pyopenssl']
        cli_params += ['-o', 'not_a_path.bin']
        cli_params += ['dummy_payload.bin']
        with self.assertRaises(SystemExit):
            parsed_args = capsule_tool.get_cli_options(cli_params)

    def test_should_not_load_an_invalid_path(self):
        bad_path = 'not_a_path.bin'
        loaded_options = capsule_tool.load_options_file(bad_path)
        self.assertEqual(loaded_options, None)

    def test_options_file_should_load_json(self):
        temp_folder = tempfile.mkdtemp()
        temp_options_path = os.path.join(temp_folder, "dummy_options.json")
        dummy_options = {
            'signer': {
                'option1': 'value1'
            },
            'capsule': {
                'option2': 'value2'
            }
        }
        with open(temp_options_path, 'w') as temp_file:
            json.dump(dummy_options, temp_file)

        with open(temp_options_path, 'r') as options_file:
            loaded_options = capsule_tool.load_options_file(options_file)

        self.assertEqual(loaded_options['signer']['option1'], 'value1')
        self.assertEqual(loaded_options['capsule']['option2'], 'value2')

    def test_options_file_should_load_yaml(self):
        temp_folder = tempfile.mkdtemp()
        temp_options_path = os.path.join(temp_folder, "dummy_options.yaml")
        dummy_options = {
            'signer': {
                'option1': 'value1'
            },
            'capsule': {
                'option2': 'value2'
            }
        }
        with open(temp_options_path, 'w') as temp_file:
            yaml.dump(dummy_options, temp_file)

        with open(temp_options_path, 'r') as options_file:
            loaded_options = capsule_tool.load_options_file(options_file)

        self.assertEqual(loaded_options['signer']['option1'], 'value1')
        self.assertEqual(loaded_options['capsule']['option2'], 'value2')

    # @pytest.mark.skip(reason="test is incomplete")
    def test_cli_options_should_override_file_options(self):
        dummy_options = {
            'capsule': {
                'option1': 'value1'
            },
            'signer': {
                'option2': 'value2',
                'option_not': 'orig_value'
            }
        }

        capsule_cli_options = ['option1=value2', 'new_option=value3']
        signer_cli_options = ['option2=value7', 'option2=value8']

        final_options = capsule_tool.update_options(dummy_options, capsule_cli_options, signer_cli_options)

        self.assertEqual(final_options['capsule']['option1'], 'value2')
        self.assertEqual(final_options['capsule']['new_option'], 'value3')
        self.assertEqual(final_options['signer']['option2'], 'value8')
        self.assertEqual(final_options['signer']['option_not'], 'orig_value')

    def test_full_options_path_should_work(self):
        # Save the options file.
        temp_folder = tempfile.mkdtemp()
        temp_options_path = os.path.join(temp_folder, "dummy_options.json")
        dummy_options = {
            'capsule': {
                'option1': 'value1'
            },
            'signer': {
                'option2': 'value2',
                'option_not': 'orig_value'
            }
        }
        with open(temp_options_path, 'w') as temp_file:
            json.dump(dummy_options, temp_file)

        # Parse the command parameters.
        cli_params = ['--builtin_signer', 'pyopenssl']
        cli_params += ['-o', temp_options_path]
        cli_params += ['-dc', 'option1=value2']
        cli_params += ['-dc', 'new_option=value3']
        cli_params += ['-ds', 'option2=value7']
        cli_params += ['-ds', 'option2=value8']
        cli_params += ['dummy_payload.bin']
        parsed_args = capsule_tool.get_cli_options(cli_params)

        loaded_options = capsule_tool.load_options_file(parsed_args.options_file)
        final_options = capsule_tool.update_options(loaded_options, parsed_args.capsule_options, parsed_args.signer_options)

        self.assertEqual(final_options['capsule']['option1'], 'value2')
        self.assertEqual(final_options['capsule']['new_option'], 'value3')
        self.assertEqual(final_options['signer']['option2'], 'value8')
        self.assertEqual(final_options['signer']['option_not'], 'orig_value')
