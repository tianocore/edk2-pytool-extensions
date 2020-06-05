# this is for creating a minimal uefi tree for testing
##
# Copyright (c) Microsoft Corporation
#
# SPDX-License-Identifier: BSD-2-Clause-Patent

import os
import tempfile
import json


class uefi_tree:
    '''
    This class represents a minimal UEFI tree that you can setup
    It is configurable and offers options to modify the tree for
    '''

    def __init__(self, workspace=None, create_platform=True):
        ''' copy the minimal tree to a folder, if one is not provided we will create a new temporary folder for you '''
        if workspace is None:
            workspace = os.path.abspath(tempfile.mkdtemp())
        self.workspace = workspace
        if (create_platform):
            self._create_tree()

    @staticmethod
    def _get_src_folder():
        return os.path.dirname(os.path.abspath(__file__))

    @staticmethod
    def _get_optional_folder():
        return os.path.join(uefi_tree._get_src_folder(), "optional")

    def get_workspace(self):
        return self.workspace

    def _create_tree(self):
        ''' Creates a settings.py, test.dsc, Conf folder (with build_rule, target, and tools_def) '''
        settings_path = self.get_settings_provider_path()
        uefi_tree.write_to_file(settings_path, self._settings_file_text)
        dsc_path = os.path.join(self.workspace, "Test.dsc")
        uefi_tree.write_to_file(dsc_path, self._dsc_file_text)
        conf_path = os.path.join(self.workspace, "Conf")
        os.makedirs(conf_path, exist_ok=True)
        target_path = os.path.join(conf_path, "target.template")
        uefi_tree.write_to_file(target_path, self._target_file_text)
        build_rule_path = os.path.join(conf_path, "build_rule.template")
        uefi_tree.write_to_file(build_rule_path, "hello there")
        tools_path = os.path.join(conf_path, "tools_def.template")
        uefi_tree.write_to_file(tools_path, "hello there")

    @staticmethod
    def write_to_file(path, contents, close=True):
        f = open(path, "w")
        f.writelines(contents)
        if close:
            f.close()

    def get_settings_provider_path(self):
        ''' gets the settings provider in the workspace '''
        return os.path.join(self.workspace, "settings.py")

    def get_optional_file(self, file):
        ''' gets the path of an optional file '''
        optional_path = os.path.join(uefi_tree._get_optional_folder(), file)
        if os.path.exists(optional_path):
            return os.path.abspath(optional_path)
        raise ValueError(f"Optional file not found {file}")

    def create_path_env(self, id=None, flags=[], var_name=None, scope="global", dir_path="", extra_data=None):
        ''' creates an ext dep in your workspace '''
        data = {
            "scope": scope,
            "flags": flags,
        }
        if id is not None:
            data["id"] = id
        if var_name is not None:
            data["var_name"] = var_name
        if extra_data is not None:
            data.update(extra_data)
        text = json.dumps(data)
        file_name = f"{id}_path_env.json"
        output_dir = os.path.join(self.workspace, dir_path)
        os.makedirs(output_dir, exist_ok=True)
        output_path = os.path.join(output_dir, file_name)
        uefi_tree.write_to_file(output_path, text)

    def create_Edk2TestUpdate_ext_dep(self, version="0.0.1", extra_data=None):
        self.create_ext_dep("nuget", "Edk2TestUpdate", version, extra_data=extra_data)

    def create_ext_dep(self, dep_type, name, version, source=None, scope="global", dir_path="", extra_data=None):
        ''' creates an ext dep in your workspace '''
        dep_type = dep_type.lower()
        if source is None and dep_type == "nuget":
            source = "https://api.nuget.org/v3/index.json"
        if source is None:
            raise ValueError("Source was not provided")
        data = {
            "scope": scope,
            "type": dep_type,
            "name": name,
            "version": version,
            "source": source,
            "flags": []
        }
        if extra_data is not None:
            data.update(extra_data)
        text = json.dumps(data)
        raw_file_name = data["id"] if "id" in data else name
        ext_dep_name = raw_file_name.replace(" ", "_")
        file_name = f"{ext_dep_name}_ext_dep.json"
        output_dir = os.path.join(self.workspace, dir_path)
        os.makedirs(output_dir, exist_ok=True)
        output_path = os.path.join(output_dir, file_name)
        uefi_tree.write_to_file(output_path, text)

    _settings_file_text = '''
# @file settings.py
# This contains a settingsmanger for testing
##
# Copyright (c) Microsoft Corporation
#
# SPDX-License-Identifier: BSD-2-Clause-Patent
##
from edk2toolext.environment.uefi_build import UefiBuilder
import os
from edk2toolext.invocables.edk2_platform_build import BuildSettingsManager
from edk2toolext.invocables.edk2_setup import SetupSettingsManager
from edk2toolext.invocables.edk2_ci_setup import Edk2CiBuildSetup
from edk2toolext.invocables.edk2_ci_setup import CiSetupSettingsManager
from edk2toolext.invocables.edk2_ci_build import CiBuildSettingsManager
from edk2toolext.invocables.edk2_update import UpdateSettingsManager


class TestSettingsManager(BuildSettingsManager, SetupSettingsManager, Edk2CiBuildSetup,
                          CiSetupSettingsManager, CiBuildSettingsManager, UpdateSettingsManager):

    def GetActiveScopes(self):
        return []

    def GetWorkspaceRoot(self):
        return os.path.dirname(__file__)

    def GetPackagesPath(self):
        return []

    def GetRequiredSubmodules(self):
        return []

    def GetDependencies(self):
        return []

    def AddCommandLineOptions(self, parserObj):
        pass

    def RetrieveCommandLineOptions(self, args):
        pass

    def GetName(self):
        return "TestEdk2Invocable"

    def GetArchitecturesSupported(self):
        return []

    def GetPackagesSupported(self):
        return []

    def GetTargetsSupported(self):
        return []


class TestBuilder(UefiBuilder):
    def SetPlatformEnv(self):
        self.env.SetValue("EDK2_BASE_TOOLS_DIR", self.ws, "empty")
        return 0
    '''

    _dsc_file_text = '''
[Defines]
OUTPUT_DIRECTORY = Build
    '''

    _target_file_text = '''
ACTIVE_PLATFORM = Test.dsc
TOOL_CHAIN_TAG = test
TARGET_ARCH = X64
TARGET = DEBUG
    '''
