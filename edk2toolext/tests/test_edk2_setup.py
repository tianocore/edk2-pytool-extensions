# @file test_edk2_setup.py
# This contains unit tests for the edk2_ci_setup
##
# Copyright (c) Microsoft Corporation
#
# SPDX-License-Identifier: BSD-2-Clause-Patent
##
import pytest
import git
import pathlib
import sys
import logging

from edk2toolext.invocables import edk2_setup
from edk2toolext.environment import shell_environment

MIN_BUILD_FILE = r"""
from edk2toolext.invocables.edk2_setup import SetupSettingsManager, RequiredSubmodule
import pathlib

class Settings(SetupSettingsManager):
    # MIN BUILD FILE
    def GetWorkspaceRoot(self) -> str:
        return str(pathlib.Path(__file__).parent)

    def GetRequiredSubmodules(self) -> list[RequiredSubmodule]:
        return [
            RequiredSubmodule('Common/MU', True)
        ]

    def GetPackagesSupported(self) -> list[str]:
        return []

    def GetArchitecturesSupported(self) -> list[str]:
        return []

    def GetTargetsSupported(self) -> list[str]:
        return []
"""

MIN_BUILD_FILE_BACKSLASH = r"""
from edk2toolext.invocables.edk2_setup import SetupSettingsManager, RequiredSubmodule
import pathlib

class Settings(SetupSettingsManager):
    # MIN BUILD FILE with backslashes
    def GetWorkspaceRoot(self) -> str:
        return str(pathlib.Path(__file__).parent)

    def GetRequiredSubmodules(self) -> list[RequiredSubmodule]:
        return [
            RequiredSubmodule('Common\\MU', True)
        ]

    def GetPackagesSupported(self) -> list[str]:
        return []

    def GetArchitecturesSupported(self) -> list[str]:
        return []

    def GetTargetsSupported(self) -> list[str]:
        return []
"""


EMPTY_BUILD_FILE = r"""
from edk2toolext.invocables.edk2_setup import SetupSettingsManager, RequiredSubmodule
import pathlib

class Settings(SetupSettingsManager):
    # EMPTY BUILD FILE
    def GetWorkspaceRoot(self) -> str:
        return str(pathlib.Path(__file__).parent)

    def GetRequiredSubmodules(self) -> list[RequiredSubmodule]:
        return []

    def GetPackagesSupported(self) -> list[str]:
        return []

    def GetArchitecturesSupported(self) -> list[str]:
        return []

    def GetTargetsSupported(self) -> list[str]:
        return []
"""


INVALID_REPO_BUILD_FILE = r"""
from edk2toolext.invocables.edk2_setup import SetupSettingsManager, RequiredSubmodule
import pathlib

class Settings(SetupSettingsManager):
    # INVALID REPO BUILD FILE
    def GetWorkspaceRoot(self) -> str:
        return str(pathlib.Path(__file__).parent.parent)

    def GetRequiredSubmodules(self) -> list[RequiredSubmodule]:
        return []

    def GetPackagesSupported(self) -> list[str]:
        return []

    def GetArchitecturesSupported(self) -> list[str]:
        return []

    def GetTargetsSupported(self) -> list[str]:
        return []
"""


INVALID_SUBMODULE_BUILD_FILE = r"""
from edk2toolext.invocables.edk2_setup import SetupSettingsManager, RequiredSubmodule
import pathlib

class Settings(SetupSettingsManager):
    # INVALID SUBMODULE BUILD FILE
    def GetWorkspaceRoot(self) -> str:
        return str(pathlib.Path(__file__).parent)

    def GetRequiredSubmodules(self) -> list[RequiredSubmodule]:
        return [
            RequiredSubmodule('Common\BAD_REPO', True)
        ]

    def GetPackagesSupported(self) -> list[str]:
        return []

    def GetArchitecturesSupported(self) -> list[str]:
        return []

    def GetTargetsSupported(self) -> list[str]:
        return []
"""


@pytest.fixture(scope="function")
def tree(tmpdir):
    """A fixture that provides a temporary directory containing the mu_tiano_platforms repo."""
    git.Repo.clone_from("https://github.com/microsoft/mu_tiano_platforms.git", tmpdir)
    tmpdir = pathlib.Path(tmpdir)
    return pathlib.Path(tmpdir)


def write_build_file(tree, file):
    """Writes the requested build file to the base of the tree."""
    build_file = tree / "BuildFile.py"
    with open(build_file, 'x') as f:
        f.write(file)
    return build_file


def test_setup_simple_repo(tree: pathlib.Path):
    """Tests that edk2_setup can successfuly clone a submodule."""
    #############################################
    # Perform Initial Setup and verify it works #
    #############################################
    min_build_file = write_build_file(tree, MIN_BUILD_FILE)
    sys.argv = ["stuart_setup", "-c", str(min_build_file), "-v"]
    mu_submodule = tree / "Common" / "MU"

    assert len(list(mu_submodule.iterdir())) == 0  # The MU submodule should not exist
    try:
        edk2_setup.main()
    except SystemExit as e:
        assert e.code == 0
    assert len(list(mu_submodule.iterdir())) > 0  # The MU submodule should exist

    #######################################################################
    # Force mu_tiano_platforms clean (The build file we wrote dirtied it) #
    #######################################################################
    with git.Repo(tree) as repo:
        assert repo.is_dirty(untracked_files=True) is True

    sys.argv = ["stuart_setup", "-c", str(min_build_file), "-v", "--FORCE"]
    try:
        edk2_setup.main()
    except SystemExit as e:
        assert e.code == 0

    with git.Repo(tree) as repo:
        assert repo.is_dirty(untracked_files=True) is False

    #############################################################
    # Dirty a submodule file and verify we skip without --FORCE #
    #############################################################
    min_build_file = write_build_file(tree, MIN_BUILD_FILE)
    with open(mu_submodule / "License.txt", 'a') as f:
        f.write("TEST")

    with git.Repo(mu_submodule) as repo:
        assert repo.is_dirty(untracked_files=True) is True

    sys.argv = ["stuart_setup", "-c", str(min_build_file), "-v"]
    try:
        edk2_setup.main()
    except SystemExit as e:
        assert e.code == 0

    with git.Repo(mu_submodule) as repo:
        assert repo.is_dirty(untracked_files=True) is True

    #############################################################
    # Verify we can clean the dirty submodule with --FORCE      #
    #############################################################
    with git.Repo(mu_submodule) as repo:
        assert repo.is_dirty(untracked_files=True) is True

    sys.argv = ["stuart_setup", "-c", str(min_build_file), "-v", "--FORCE"]
    try:
        edk2_setup.main()
    except SystemExit as e:
        assert e.code == 0

    with git.Repo(mu_submodule) as repo:
        assert repo.is_dirty(untracked_files=True) is False


def test_setup_bad_omnicache(caplog, tree: pathlib.Path):
    """Tests that edk2_setup catches a bad omnicache path."""
    caplog.at_level(logging.WARNING)  # Capture only warnings
    empty_build_file = write_build_file(tree, EMPTY_BUILD_FILE)
    sys.argv = ["stuart_setup", "-c", str(empty_build_file), "-v", "--omnicache", "does_not_exist"]

    try:
        edk2_setup.main()
    except SystemExit as e:
        assert e.code == 0

    # Verify we output a warning about the omnicache path being invalid
    for record in caplog.records:
        if "Omnicache path set to invalid path" in record.msg:
            break
    else:
        pytest.fail("Did not find a warning about the omnicache path being invalid.")


def test_setup_invalid_repo(tree: pathlib.Path):
    """Tests that edk2_setup catches a bad omnicache path."""
    invalid_build_file = write_build_file(tree, INVALID_REPO_BUILD_FILE)
    sys.argv = ["stuart_setup", "-c", str(invalid_build_file), "-v", "--FORCE"]
    try:
        edk2_setup.main()
    except SystemExit as e:
        assert e.code == -1


def test_setup_invalid_submodule(tree: pathlib.Path):
    """Tests that edk2_setup catches a bad submodule path."""
    invalid_build_file = write_build_file(tree, INVALID_SUBMODULE_BUILD_FILE)
    sys.argv = ["stuart_setup", "-c", str(invalid_build_file), "-v"]
    try:
        edk2_setup.main()
    except SystemExit as e:
        assert e.code == -1

    sys.argv = ["stuart_setup", "-c", str(invalid_build_file), "-v", "--FORCE"]
    try:
        edk2_setup.main()
    except SystemExit as e:
        assert e.code == -1


def test_parse_command_line_options(tree: pathlib.Path):
    """Tests that the command line parser works correctly."""
    # Test valid command line options
    empty_build_file = write_build_file(tree, EMPTY_BUILD_FILE)
    sys.argv = [
        "stuart_setup", "-c", str(empty_build_file),
        "BLD_*_VAR",
        "VAR",
        "BLD_DEBUG_VAR2",
        "BLD_RELEASE_VAR2",
        "TEST_VAR=TEST",
        "BLD_*_TEST_VAR2=TEST"
    ]
    try:
        edk2_setup.main()
    except SystemExit as e:
        assert e.code == 0

    env = shell_environment.GetBuildVars()
    assert env.GetValue("BLD_*_VAR") is not None
    assert env.GetValue("VAR") is not None
    assert env.GetValue("BLD_DEBUG_VAR2") is not None
    assert env.GetValue("BLD_RELEASE_VAR2") is not None
    assert env.GetValue("TEST_VAR") == "TEST"
    assert env.GetValue("BLD_*_TEST_VAR2") == "TEST"

    # Test invalid command line options
    for arg in ["BLD_*_VAR=5=10", "BLD_DEBUG_VAR2=5=5", "BLD_RELEASE_VAR3=5=5", "VAR=10=10"]:
        sys.argv = [
            "stuart_setup",
            "-c", str(empty_build_file),
            arg
        ]
        try:
            edk2_setup.main()
        except RuntimeError as e:
            assert str(e).startswith(f"Unknown variable passed in via CLI: {arg}")


def test_conf_file(tree: pathlib.Path):
    """Tests that the config file parser works correctly."""
    empty_build_file = write_build_file(tree, EMPTY_BUILD_FILE)
    build_conf = tree / 'BuildConfig.conf'
    with open(build_conf, 'x') as f:
        f.writelines([
            "BLD_*_VAR",
            "\nVAR",
            "\nBLD_DEBUG_VAR2",
            "\nBLD_RELEASE_VAR2",
            "\nTEST_VAR=TEST",
            "\nBLD_*_TEST_VAR2=TEST"
        ])
    sys.argv = ["stuart_setup", "-c", str(empty_build_file)]

    try:
        edk2_setup.main()
    except SystemExit as e:
        assert e.code == 0

    env = shell_environment.GetBuildVars()
    assert env.GetValue("BLD_*_VAR") is not None
    assert env.GetValue("VAR") is not None
    assert env.GetValue("BLD_DEBUG_VAR2") is not None
    assert env.GetValue("BLD_RELEASE_VAR2") is not None
    assert env.GetValue("TEST_VAR") == "TEST"
    assert env.GetValue("BLD_*_TEST_VAR2") == "TEST"

    # Test invalid build config
    for arg in ["BLD_*_VAR=5=10", "BLD_DEBUG_VAR2=5=5", "BLD_RELEASE_VAR3=5=5", "VAR=10=10"]:
        build_conf.unlink()
        with open(build_conf, 'x') as f:
            f.writelines([arg])

        sys.argv = [
            "stuart_setup",
            "-c", str(empty_build_file),
            arg
        ]
        try:
            edk2_setup.main()
        except RuntimeError as e:
            assert str(e).startswith(f"Unknown variable passed in via CLI: {arg}")


def test_backslash(tree: pathlib.Path):
    """Test setup with force flag before submodules are initialized."""
    build_file = write_build_file(tree, MIN_BUILD_FILE_BACKSLASH)
    sys.argv = [
        "stuart_setup", "-c", str(build_file), "--FORCE",
    ]
    mu_submodule = tree / "Common" / "MU"

    assert len(list(mu_submodule.iterdir())) == 0  # The MU submodule should not exist
    try:
        edk2_setup.main()
    except SystemExit as e:
        assert e.code == 0
    assert len(list(mu_submodule.iterdir())) > 0  # The MU submodule should exist
