# @file rust.py
#
# Functions to help check that a build environment is ready to build Rust code.
#
# Copyright (c) Microsoft Corporation.
# SPDX-License-Identifier: BSD-2-Clause-Patent
##
"""Rust Environment Helper Functions.

Helpers to check that Rust tools are present needed to compile Rust code
during firmare build.

This functionality can be used to provide faster, direct feedback to a
developer about the changes they may need to make to successfully build Rust
code. Otherwise, the build will fail much later during firmware code
compilation when Rust tools are invoked with messages that are ambiguous or
difficult to find.

Note:
  - Individual tools can be opted out by setting the environment variable
    `RUST_ENV_CHECK_TOOL_EXCLUSIONS` with a comma separated list of the tools
    to exclude. For example, "rustup, cargo tarpaulin" would not require that
    those tools be installed.
"""

import logging
import re
from io import StringIO
from typing import Callable, Dict, List, NamedTuple

from edk2toollib.utility_functions import RunCmd

from edk2toolext.environment import shell_environment

WORKSPACE_TOOLCHAIN_FILE = "rust-toolchain.toml"


class RustToolInfo(NamedTuple):
    """Represents information about a Rust tool.

    Attributes:
        presence_cmd (tuple[str]): A tuple of command-line arguments to check
            for the presence of the tool.
        install_help (str): Help text for installing the tool.
        required_version (str): The required version of the tool.
        regex (str): Regular expression pattern to match the tool's version.
    """

    presence_cmd: tuple[str]
    install_help: str
    required_version: str
    regex: str


class RustToolChainInfo(NamedTuple):
    """Represents information about a Rust toolchain.

    Attributes:
        error (bool): Indicates whether an error occurred while retrieving the
            toolchain information.
        toolchain (str): The name of the Rust toolchain.
    """

    error: bool
    toolchain: str


class CustomToolFilter(NamedTuple):
    """Represents a custom tool filter.

    Attributes:
        filter_fn (Callable[[RustToolInfo, str], bool]): A callable function
            that takes a `RustToolInfo` object and a string as input and
            returns a boolean value indicating whether the tool should be
            filtered or not.
        error_msg (str): The error message to be displayed if the tool is
            filtered.
        error_only (bool): A boolean value indicating whether the error message
            should be displayed only when the tool is filtered.
    """

    filter_fn: Callable[[RustToolInfo, str], bool]
    error_msg: str
    error_only: bool


def _is_corrupted_component(tool: RustToolInfo, cmd_output: str) -> bool:
    """Checks if a component should be removed and reinstalled.

    Args:
        tool (RustToolInfo): Tool information.
        cmd_output (str): The output from a command that will be
        inspected by this function.

    Returns:
        bool: True if the component should be removed and added back to
        correct its installation.
    """
    return (
        f"error: the '{tool.presence_cmd[0]}' binary, normally "
        f"provided by the '{tool.presence_cmd[0]}' component, is "
        f"not applicable to the "
    ) in cmd_output


def _verify_cmd(tool: RustToolInfo, custom_filters: List[CustomToolFilter]) -> int:
    """Indicates if a command can successfully be executed.

    Args:
        tool (RustToolInfo): Tool information
        custom_filters (List[CustomToolFilter]): Custom filters to apply

    Returns:
        int: 0 for success, 1 for missing tool, 2 for version mismatch,
        3 if a component is present but broken
        4 if a custom tool filter detected an error
    """
    cmd_output = StringIO()
    params = "--version"
    name = tool.presence_cmd[0]
    if len(tool.presence_cmd) == 2:
        params = tool.presence_cmd[1]
    ret = RunCmd(name, params, outstream=cmd_output, logging_level=logging.DEBUG)

    # Give precedence to custom filters as they may be more specialized
    for custom_filter in custom_filters:
        if ((custom_filter.error_only and ret != 0) or not custom_filter.error_only) and custom_filter.filter_fn(
            tool, cmd_output.getvalue()
        ):
            logging.error(custom_filter.error_msg)
            return 4

    if ret != 0:
        if _is_corrupted_component(tool, cmd_output.getvalue()):
            return 3
        return 1

    # If a specific version is required, check the version, returning
    # false if there is a version mismatch
    if tool.required_version:
        match = re.search(tool.regex, cmd_output.getvalue())
        if match is None:
            logging.warning(f"Failed to verify version: {tool.required_version}")
            return 0
        if match.group(0) != tool.required_version:
            return 2

    return 0


def _get_required_tool_versions() -> Dict[str, str]:
    """Returns any tools and their required versions from the workspace toolchain file.

    Returns:
        Dict[str,str]: dict where the key is the tool name and the
        value is the version
    """
    tool_ver = {}
    try:
        with open(WORKSPACE_TOOLCHAIN_FILE, "r") as toml_file:
            content = toml_file.read()
            match = re.search(r"\[tool(?:s)?\]\n((?:.+\s*=\s*.+\n?)*)", content)
            if match:
                for line in match.group(1).splitlines():
                    (tool, version) = line.split("=", maxsplit=1)
                    tool_ver[tool.strip()] = version.strip(" \"'")
        return tool_ver
    except FileNotFoundError:
        # If a file is not found. Do not check any further.
        return tool_ver


def _verify_rust_src_component_is_installed() -> bool:
    """Verifies the rust-src component is installed.

    Returns:
        bool: True if the rust-src component is installed for the default
        toolchain or the status could not be determined, otherwise, False.
    """
    toolchain_version = get_workspace_toolchain_version()
    if toolchain_version.error or not toolchain_version:
        # If the file is not in an expected format, let that be handled
        # elsewhere and do not look further.
        return True

    toolchain_version = toolchain_version.toolchain

    rustc_output = StringIO()
    ret = RunCmd(
        "rustc",
        "--version --verbose",
        outstream=rustc_output,
        logging_level=logging.DEBUG,
    )
    if ret != 0:
        # rustc installation is checked elsewhere. Exit here on failure.
        return True

    for line in rustc_output.getvalue().splitlines():
        start_index = line.lower().strip().find("host: ")
        if start_index != -1:
            target_triple = line[start_index + len("host: ") :]
            break
    else:
        logging.error("Failed to get host target triple information.")
        return False

    rustup_output = StringIO()
    ret = RunCmd(
        "rustup",
        f"component list --toolchain {toolchain_version}",
        outstream=rustup_output,
        logging_level=logging.DEBUG,
    )
    if ret != 0:
        # rustup installation and the toolchain are checked elsewhere.
        # Exit here on failure.
        return True

    for component in rustup_output.getvalue().splitlines():
        if "rust-src (installed)" in component:
            return True

    logging.error(
        "The Rust toolchain is installed but the rust-src component "
        "needs to be installed:\n\n"
        f"  rustup component add --toolchain {toolchain_version}-"
        f"{target_triple} rust-src"
    )

    return False


def verify_workspace_rust_toolchain_is_installed() -> RustToolChainInfo:
    """Verifies the rust toolchain used in the workspace is available.

    !!! note
        This function does not use the toml library to parse the toml
        file since the file is very simple and its not desirable to add the
        toml module as a dependency.

    Returns:
        RustToolChainInfo: A tuple that indicates if the toolchain is
            available and includes the toolchain version if found.
    """
    toolchain_version = get_workspace_toolchain_version()
    if toolchain_version.error or not toolchain_version:
        # If the file is not in an expected format, let that be handled
        # elsewhere and do not look further.
        return RustToolChainInfo(error=False, toolchain=None)

    toolchain_version = toolchain_version.toolchain

    installed_toolchains = StringIO()
    ret = RunCmd(
        "rustup",
        "toolchain list",
        outstream=installed_toolchains,
        logging_level=logging.DEBUG,
    )

    # The ability to call "rustup" is checked separately. Here do not
    # continue if the command is not successful.
    if ret != 0:
        return RustToolChainInfo(error=False, toolchain=None)

    installed_toolchains = installed_toolchains.getvalue().splitlines()
    return RustToolChainInfo(
        error=not any(toolchain_version in toolchain for toolchain in installed_toolchains),
        toolchain=toolchain_version,
    )


def get_workspace_toolchain_version() -> RustToolChainInfo:
    """Returns the rust toolchain version specified in the workspace toolchain file.

    Returns:
        RustToolChainInfo: The rust toolchain information. If an error
            occurs, the error field will be True with no toolchain info.
    """
    toolchain_version = None
    try:
        with open(WORKSPACE_TOOLCHAIN_FILE, "r") as toml_file:
            content = toml_file.read()
            match = re.search(r'channel\s*=\s*"([^"]+)"', content)
            if match:
                toolchain_version = match.group(1)
        return RustToolChainInfo(error=False, toolchain=toolchain_version)
    except FileNotFoundError:
        # If a file is not found. Do not check any further.
        return RustToolChainInfo(error=True, toolchain=None)


def run(
    custom_tool_checks: Dict[str, RustToolInfo] = {},
    custom_tool_filters: List[CustomToolFilter] = [],
) -> int:
    """Checks the current environment for Rust build support.

    Args:
        custom_tool_checks (Dict[str, RustToolInfo], optional): A dictionary
            of custom tools to check. The key is the tool name and the value
            is a `RustToolInfo` object. Defaults to {}.
        custom_tool_filters (List[CustomToolFilter], optional): A list of
            custom tool filters. Defaults to [].

    Returns:
        int: Then number of errors discovered. 0 indicates success.
    """
    generic_rust_install_instructions = "Visit https://rustup.rs/ to install Rust and cargo."
    tool_ver = _get_required_tool_versions()

    tools = {
        "rustup": RustToolInfo(
            presence_cmd=("rustup",),
            install_help=generic_rust_install_instructions,
            required_version=None,
            regex=None,
        ),
        "rustc": RustToolInfo(
            presence_cmd=("rustc",),
            install_help=generic_rust_install_instructions,
            required_version=None,
            regex=None,
        ),
        "cargo": RustToolInfo(
            presence_cmd=("cargo",),
            install_help=generic_rust_install_instructions,
            required_version=None,
            regex=None,
        ),
        "cargo build": RustToolInfo(
            presence_cmd=("cargo", "build --help"),
            install_help=generic_rust_install_instructions,
            required_version=None,
            regex=None,
        ),
        "cargo check": RustToolInfo(
            presence_cmd=("cargo", "check --help"),
            install_help=generic_rust_install_instructions,
            required_version=None,
            regex=None,
        ),
        "cargo fmt": RustToolInfo(
            presence_cmd=("cargo", "fmt --help"),
            install_help=generic_rust_install_instructions,
            required_version=None,
            regex=None,
        ),
        "cargo test": RustToolInfo(
            presence_cmd=("cargo", "test --help"),
            install_help=generic_rust_install_instructions,
            required_version=None,
            regex=None,
        ),
        "cargo make": RustToolInfo(
            presence_cmd=("cargo", "make --version"),
            install_help=(
                "  cargo binstall cargo-make "
                f"{('--version ' + tool_ver.get('cargo-make', '')) if 'cargo-make' in tool_ver else ''}"
                "\n\n"
                "  Need to install cargo-binstall? Visit: https://github.com/cargo-bins/cargo-binstall?tab=readme-ov-file#installation\n"
            ),
            required_version=tool_ver.get("cargo-make"),
            regex=r"\d+\.\d+\.\d+",
        ),
        "cargo tarpaulin": RustToolInfo(
            presence_cmd=("cargo", "tarpaulin --version"),
            install_help=(
                "  cargo binstall cargo-tarpaulin "
                f"{('--version ' + tool_ver.get('cargo-tarpaulin', '')) if 'cargo-tarpaulin' in tool_ver else ''}"
                "\n\n"
                "  Need to install cargo-binstall? Visit: https://github.com/cargo-bins/cargo-binstall?tab=readme-ov-file#installation\n"
            ),
            required_version=tool_ver.get("cargo-tarpaulin"),
            regex=r"\d+\.\d+\.\d+",
        ),
    }
    tools.update(custom_tool_checks)

    excluded_tools_in_shell = shell_environment.GetEnvironment().get_shell_var("RUST_ENV_CHECK_TOOL_EXCLUSIONS")
    excluded_tools = [t.strip() for t in excluded_tools_in_shell.split(",")] if excluded_tools_in_shell else []

    errors = 0
    for tool_name, tool_info in tools.items():
        if tool_name not in excluded_tools:
            ret = _verify_cmd(tool_info, custom_tool_filters)
            if ret == 1:
                logging.error(
                    f"Rust Environment Failure: {tool_name} is not installed "
                    "or not on the system path.\n\n"
                    f"Instructions:\n{tool_info.install_help}\n\n"
                    f'Ensure "{" ".join(tool_info.presence_cmd)}" can '
                    "successfully be run from a terminal before trying again."
                )
                errors += 1
            if ret == 2:
                logging.error(
                    f"Rust Environment Failure: {tool_name} version mismatch.\n\n"
                    f"Expected version: {tool_info.required_version}\n\n"
                    f"Instructions:\n{tool_info.install_help}"
                )
                errors += 1
            if ret == 3:
                logging.error(
                    f"Rust Environment Failure: {tool_name} is installed "
                    "but does not run correctly.\n\n"
                    f'Run "rustc component remove {tool_name}"\n'
                    f'    "rustc component add {tool_name}"\n\n'
                    f"Then try again."
                )
                errors += 1
            if ret == 4:
                errors += 1
                break

    rust_toolchain_info = verify_workspace_rust_toolchain_is_installed()
    if rust_toolchain_info.error:
        # The "rustc -Vv" command could be run in the script with the
        # output given to the user. This is approach is also meant to show
        # the user how to use the tools since getting the target triple is
        # important.
        logging.error(
            f"This workspace requires the {rust_toolchain_info.toolchain} "
            "toolchain.\n\n"
            'Run "rustc -Vv" and use the "host" value to install the '
            "toolchain needed:\n"
            f'  "rustup toolchain install {rust_toolchain_info.toolchain}-'
            '<host>"\n\n'
            '  "rustup component add rust-src '
            f'{rust_toolchain_info.toolchain}-<host>"'
        )
        errors += 1

    if not _verify_rust_src_component_is_installed():
        errors += 1

    return errors
