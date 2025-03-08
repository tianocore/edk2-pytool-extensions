# this is for creating a minimal uefi tree for testing
##
# Copyright (c) Microsoft Corporation
#
# SPDX-License-Identifier: BSD-2-Clause-Patent

"""Used for creating a minimal uefi tree for testing."""

import json
import os
import random
import tempfile
from typing import Optional

import git


class uefi_tree:
    """A minimal UEFI tree.

    This class represents a minimal UEFI tree that you can setup.
    It is configurable and offers options to modify the tree for.

    Attributes:
        workspace (str): Path to a directory for the minimal tree

    Args:
        workspace (str): Path to a directory for the minimal tree
        create_platform (bool): create the tree or use an existing
    """

    def __init__(self, workspace: Optional[str] = None, create_platform: bool = True, with_repo: bool = False) -> None:
        """Inits uefi_tree."""
        if workspace is None:
            workspace = os.path.abspath(tempfile.mkdtemp())
        self.workspace = workspace
        if create_platform:
            self._create_tree()
        if with_repo:
            self._create_repo()

    @staticmethod
    def _get_src_folder() -> str:
        return os.path.dirname(os.path.abspath(__file__))

    @staticmethod
    def _get_optional_folder() -> str:
        return os.path.join(uefi_tree._get_src_folder(), "optional")

    def get_workspace(self) -> str:
        """Returns the workspace path."""
        return self.workspace

    def _create_repo(self) -> None:
        repo = git.Repo.init(self.workspace)
        repo.create_remote("origin", "https://github.com/username/repo.git")
        repo.git.config("--global", "user.email", '"johndoe@example.com"')
        repo.git.config("--global", "user.name", '"John Doe"')
        repo.git.checkout("-b", "master")
        repo.git.add(".")
        repo.git.commit("-m", '"Initial commit"')

    def _create_tree(self) -> None:
        """Creates a settings.py, test.dsc, Conf folder (with build_rule, target, and tools_def)."""
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
    def write_to_file(path: str, contents: str, close: bool = True) -> None:
        """Writes contents to a file."""
        f = open(path, "w")
        f.writelines(contents)
        if close:
            f.close()

    def get_settings_provider_path(self) -> str:
        """Gets the settings provider in the workspace."""
        return os.path.join(self.workspace, "settings.py")

    def get_optional_file(self, file: str) -> str:
        """Gets the path of an optional file."""
        optional_path = os.path.join(uefi_tree._get_optional_folder(), file)
        if os.path.exists(optional_path):
            return os.path.abspath(optional_path)
        raise ValueError(f"Optional file not found {file}")

    def create_path_env(
        self,
        id: Optional[str] = None,
        flags: list = [],
        var_name: Optional[str] = None,
        scope: str = "global",
        dir_path: str = "",
        extra_data: Optional[str] = None,
    ) -> None:
        """Creates an ext dep in your workspace."""
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
        if id is not None:
            file_name = f"{id}_path_env.json"
        else:
            file_name = "None%s_path_env.json" % str(random.randint(1, 100000))
        output_dir = os.path.join(self.workspace, dir_path)
        os.makedirs(output_dir, exist_ok=True)
        output_path = os.path.join(output_dir, file_name)
        uefi_tree.write_to_file(output_path, text)

    def create_Edk2TestUpdate_ext_dep(self, version: str = "0.0.1", extra_data: Optional[str] = None) -> str:
        """Creates an Edk2TestUpdate ext dep in your workspace."""
        self.create_ext_dep("nuget", "Edk2TestUpdate", version, extra_data=extra_data)

    def create_ext_dep(
        self,
        dep_type: str,
        name: str,
        version: str,
        source: Optional[str] = None,
        scope: str = "global",
        dir_path: str = "",
        extra_data: Optional[str] = None,
    ) -> str:
        """Creates an ext dep in your workspace."""
        dep_type = dep_type.lower()
        if source is None and dep_type == "nuget":
            source = "https://api.nuget.org/v3/index.json"
        if source is None:
            raise ValueError("Source was not provided")
        data = {"scope": scope, "type": dep_type, "name": name, "version": version, "source": source, "flags": []}
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
        return output_path

    _settings_file_text = """
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

    def GetSkippedDirectories(self):
        return ()

class TestBuilder(UefiBuilder):
    def SetPlatformEnv(self):
        self.env.SetValue("EDK2_BASE_TOOLS_DIR", self.ws, "empty")
        return 0
    """

    _dsc_file_text = """
[Defines]
OUTPUT_DIRECTORY = Build
    """

    _target_file_text = """
ACTIVE_PLATFORM = Test.dsc
TOOL_CHAIN_TAG = test
TARGET_ARCH = X64
TARGET = DEBUG
    """
