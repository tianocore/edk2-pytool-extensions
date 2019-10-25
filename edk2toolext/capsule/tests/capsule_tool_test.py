import os
import pytest
import unittest
import logging
import tempfile
import json
import yaml

from edk2toolext.capsule import capsule_tool

class ParameterParsingTest(unittest.TestCase):
    def test_capsule_options_should_be_passable(self):
        cli_params = ['--builtin_signer', 'pyopenssl']
        parsed_args = capsule_tool.get_cli_options(cli_params)
        self.assertEqual(len(parsed_args.capsule_options), 0)

        cli_params += ['-dc', 'option1=value1']
        cli_params += ['-dc', 'option2=value2']
        parsed_args = capsule_tool.get_cli_options(cli_params)
        self.assertEqual(len(parsed_args.capsule_options), 2)

    def test_signer_options_should_be_passable(self):
        cli_params = ['--builtin_signer', 'pyopenssl']
        parsed_args = capsule_tool.get_cli_options(cli_params)
        self.assertEqual(len(parsed_args.signer_options), 0)

        cli_params += ['-ds', 'option1=value1']
        cli_params += ['-ds', 'option2=value2']
        parsed_args = capsule_tool.get_cli_options(cli_params)
        self.assertEqual(len(parsed_args.signer_options), 2)

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

        loaded_options = capsule_tool.load_options_file(temp_options_path)

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

        loaded_options = capsule_tool.load_options_file(temp_options_path)

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

    @pytest.mark.skip(reason="test is incomplete")
    def test_full_options_path_should_work(self):
        pass
