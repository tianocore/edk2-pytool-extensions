# @file test_edk2_update.py
# This contains unit tests for the edk2_update
##
# Copyright (c) Microsoft Corporation
#
# SPDX-License-Identifier: BSD-2-Clause-Patent
##
"""Unit test suite for the Edk2Update class."""

import logging
import os
import sys
import tempfile
import unittest
from importlib import reload
from pathlib import Path

import pytest
from edk2toolext.environment import self_describing_environment, shell_environment, version_aggregator
from edk2toolext.invocables.edk2_update import Edk2Update
from uefi_tree import uefi_tree


class TestEdk2Update(unittest.TestCase):
    """Unit test suite for the Edk2Update class."""

    temp_folders: list[str] = []

    def tearDown(self) -> None:
        """Tear down the test environment."""
        shell_environment.GetEnvironment().restore_initial_checkpoint()
        for temp_folder in TestEdk2Update.temp_folders:
            logging.info(f"Cleaning up {temp_folder}")
            # shutil.rmtree(os.path.abspath(temp_folder), ignore_errors=True)
        TestEdk2Update.restart_logging()
        # we need to make sure to tear down the version aggregator and the SDE
        self_describing_environment.DestroyEnvironment()
        version_aggregator.ResetVersionAggregator()

    @classmethod
    def restart_logging(cls) -> None:
        """Restart logging."""
        logging.shutdown()
        reload(logging)

    @classmethod
    def get_temp_folder(cls) -> str:
        """Get a temporary folder."""
        temp_folder = os.path.abspath(tempfile.mkdtemp())
        TestEdk2Update.temp_folders.append(temp_folder)
        return os.path.abspath(temp_folder)

    def invoke_update(self, settings_filepath: str, args: list[str] = [], failure_expected: bool = False) -> Edk2Update:
        """Invoke the update process."""
        sys.argv = ["stuart_update", "-c", settings_filepath]
        sys.argv.extend(args)
        builder = Edk2Update()
        try:
            builder.Invoke()
        except SystemExit as e:
            if failure_expected:
                self.assertIsNot(e.code, 0, "We should have a non zero error code")
            else:
                self.assertIs(e.code, 0, "We should have a zero error code")
        return builder

    #######################################
    # Test methods
    def test_init(self) -> None:
        """Test initialization."""
        WORKSPACE = self.get_temp_folder()
        tree = uefi_tree(WORKSPACE)
        settings_filepath = tree.get_settings_provider_path()
        sys.argv = ["stuart_update", "-c", settings_filepath]
        builder = Edk2Update()
        self.assertIsNotNone(builder)

    def test_one_level_recursive(self) -> None:
        """Test one level recursive update."""
        WORKSPACE = self.get_temp_folder()
        tree = uefi_tree(WORKSPACE)
        logging.getLogger().setLevel(logging.WARNING)
        tree.create_Edk2TestUpdate_ext_dep()
        # Do the update
        updater = self.invoke_update(tree.get_settings_provider_path())
        # make sure it worked
        self.assertTrue(
            os.path.exists(
                os.path.join(WORKSPACE, "Edk2TestUpdate_extdep", "NuGet.CommandLine_extdep", "extdep_state.yaml")
            )
        )
        build_env, shell_env, failure = updater.PerformUpdate()
        # we should have no failures
        self.assertEqual(failure, 0)
        # we should have found two ext deps
        self.assertEqual(len(build_env.extdeps), 2)

    def test_multiple_extdeps(self) -> None:
        """Test multiple external dependencies."""
        WORKSPACE = self.get_temp_folder()
        tree = uefi_tree(WORKSPACE)
        num_of_ext_deps = 5
        logging.getLogger().setLevel(logging.WARNING)
        tree.create_ext_dep("nuget", "NuGet.CommandLine", "5.2.0")
        tree.create_ext_dep("nuget", "NuGet.LibraryModel", "5.6.0")
        tree.create_ext_dep("nuget", "NuGet.Versioning", "5.6.0")
        tree.create_ext_dep("nuget", "NuGet.Packaging.Core", "5.6.0")
        tree.create_ext_dep("nuget", "NuGet.RuntimeModel", "4.2.0")
        # Do the update
        updater = self.invoke_update(tree.get_settings_provider_path())
        build_env, shell_env, failure = updater.PerformUpdate()
        # we should have no failures
        self.assertEqual(failure, 0)
        # we should have found two ext deps
        self.assertEqual(len(build_env.extdeps), num_of_ext_deps)

    def test_duplicate_ext_deps(self) -> None:
        """Test redundant external dependencies fail."""
        WORKSPACE = self.get_temp_folder()
        tree = uefi_tree(WORKSPACE)

        logging.getLogger().setLevel(logging.WARNING)

        tree.create_ext_dep(
            dep_type="nuget", name="NuGet.CommandLine", version="5.2.0", dir_path="1", extra_data={"id:": "CmdLine1"}
        )
        tree.create_ext_dep(
            dep_type="nuget", name="NuGet.CommandLine", version="5.2.0", dir_path="2", extra_data={"id:": "CmdLine1"}
        )

        # Do the update. Expect a ValueError from the version aggregator.
        with self.assertRaises(ValueError):
            self.invoke_update(tree.get_settings_provider_path(), failure_expected=True)

    def test_duplicate_ext_deps_skip_dir(self) -> None:
        """Test redundant external dependencies pass if one is skipped."""
        WORKSPACE = self.get_temp_folder()
        tree = uefi_tree(WORKSPACE)
        num_of_ext_deps = 1

        logging.getLogger().setLevel(logging.WARNING)

        tree.create_ext_dep(
            dep_type="nuget", name="NuGet.CommandLine", version="5.2.0", dir_path="1", extra_data={"id:": "CmdLine1"}
        )
        tree.create_ext_dep(
            dep_type="nuget", name="NuGet.CommandLine", version="5.2.0", dir_path="2", extra_data={"id:": "CmdLine1"}
        )

        # Update GetSkippedDirectories() implementation
        with open(tree.get_settings_provider_path(), "r") as s:
            settings_text = s.read()

        settings_text = settings_text.replace(
            "def GetSkippedDirectories(self):\n        return ()",
            'def GetSkippedDirectories(self):\n        return ("2",)',
        )

        with open(tree.get_settings_provider_path(), "w") as s:
            s.write(settings_text)

        # Do the update
        updater = self.invoke_update(tree.get_settings_provider_path())
        build_env, shell_env, failure = updater.PerformUpdate()
        # we should have found one ext dep
        self.assertEqual(len(build_env.extdeps), num_of_ext_deps)
        # the one ext_dep should be valid
        self.assertEqual(failure, 0)

    def test_multiple_duplicate_ext_deps_skip_dir(self) -> None:
        """Test multiple external dependencies in subdirectories are skipped."""
        WORKSPACE = self.get_temp_folder()
        tree = uefi_tree(WORKSPACE)
        num_of_ext_deps = 1

        logging.getLogger().setLevel(logging.WARNING)

        tree.create_ext_dep(
            dep_type="nuget",
            name="NuGet.CommandLine",
            version="5.2.0",
            dir_path="first/second",
            extra_data={"id:": "CmdLine1"},
        )
        tree.create_ext_dep(
            dep_type="nuget",
            name="NuGet.CommandLine",
            version="5.2.0",
            dir_path="third/fourth/fifth",
            extra_data={"id:": "CmdLine1"},
        )
        tree.create_ext_dep(
            dep_type="nuget",
            name="NuGet.CommandLine",
            version="5.2.0",
            dir_path="sixth/seventh/eighth",
            extra_data={"id:": "CmdLine1"},
        )

        # Update GetSkippedDirectories() implementation
        with open(tree.get_settings_provider_path(), "r") as s:
            settings_text = s.read()

        settings_text = settings_text.replace(
            "def GetSkippedDirectories(self):\n        return ()",
            'def GetSkippedDirectories(self):\n        return ("third","sixth")',
        )

        with open(tree.get_settings_provider_path(), "w") as s:
            s.write(settings_text)

        # Do the update
        updater = self.invoke_update(tree.get_settings_provider_path())
        build_env, shell_env, failure = updater.PerformUpdate()
        # we should have found one ext dep
        self.assertEqual(len(build_env.extdeps), num_of_ext_deps)
        # the one ext_dep should be valid
        self.assertEqual(failure, 0)

    def test_bad_ext_dep(self) -> None:
        """Test update with a bad external dependency."""
        WORKSPACE = self.get_temp_folder()
        tree = uefi_tree(WORKSPACE)
        logging.getLogger().setLevel(logging.WARNING)
        # we know this version is bad
        tree.create_Edk2TestUpdate_ext_dep("0.0.0")
        # Do the update
        updater = self.invoke_update(tree.get_settings_provider_path(), failure_expected=True)
        build_env, shell_env, failure = updater.PerformUpdate()
        # we should have no failures
        self.assertEqual(failure, 1)


def test_log_error_on_missing_host_specific_folder(
    caplog: pytest.LogCaptureFixture, tmpdir: pytest.TempdirFactory
) -> None:
    """Test update with missing host-specific folder."""
    caplog.set_level(logging.ERROR)
    tree = uefi_tree(tmpdir)
    tree.create_ext_dep(
        dep_type="nuget",
        name="mu_nasm",
        version="20016.1.1",
        source="https://pkgs.dev.azure.com/projectmu/mu/_packaging/Basetools-Binary/nuget/v3/index.json",
        dir_path="first/",
        extra_data={"flags": ["host_specific"]},
    )
    # Should download everything fine.
    sys.argv = ["stuart_update", "-c", tree.get_settings_provider_path()]
    builder = Edk2Update()
    try:
        builder.Invoke()
    except SystemExit as e:
        assert e.code == 0

    extdep_base = Path(tmpdir, "first", "mu_nasm_extdep")
    assert 6 == len(list(extdep_base.iterdir()))

    # Delete one of the supported hosts
    if os.name == "nt":
        host = extdep_base / "Windows-x86-64"
    else:
        host = extdep_base / "Linux-x86-64"
    for file in host.iterdir():
        file.unlink()
    host.rmdir()
    assert 5 == len(list(extdep_base.iterdir()))

    # We should catch the missing host and update
    _, _, failure = builder.PerformUpdate()
    assert failure == 0
    assert len(caplog.records) > 0


if __name__ == "__main__":
    unittest.main()
