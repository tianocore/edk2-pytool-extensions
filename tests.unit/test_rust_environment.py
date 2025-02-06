##
"""Rust Environment module unit tests."""

import unittest
from unittest.mock import mock_open, patch, MagicMock

from edk2toolext.environment.rust import (
    RustToolChainInfo,
    RustToolInfo,
    CustomToolFilter,
    _is_corrupted_component,
    _verify_cmd,
    _get_required_tool_versions,
    _verify_rust_src_component_is_installed,
    run,
    verify_workspace_rust_toolchain_is_installed,
)


class RustEnvironmentTests(unittest.TestCase):
    """Rust Environment unit tests."""

    @classmethod
    def _mock_run_cmd(cls, tool_name: str, tool_params: str, **kwargs: dict[str, any]):
        if tool_name == "rustc":
            if any(p in tool_params for p in ["--version", "-V"]):
                if any(p in tool_params for p in ["--verbose", "-v"]):
                    kwargs["outstream"].write(
                        "rustc 1.76.0 (c560aa0e2e 2024-04-12)\n"
                        "binary: rustc\n"
                        "commit-hash: c560aa0e2e2ae245cf41c934a259a7bbe87ff96f\n"
                        "commit-date: 2024-04-12\n"
                        "host: x86_64-pc-windows-msvc\n"
                        "release: 1.76.0\n"
                        "LLVM version: 17.0.6\n"
                    )
                else:
                    kwargs["outstream"].write("rustc 1.76.0 (c560aa0e2e 2024-04-12)")
            return 0
        elif tool_name == "corruptedtool":
            kwargs["outstream"].write(
                (
                    "error: the 'corruptedtool' "
                    "binary, normally provided by the "
                    "'corruptedtool' component, "
                    "is not applicable to the ..."
                )
            )
            return 100
        elif tool_name == "filternoerrortesttool":
            kwargs["outstream"].write(("filter match string"))
            return 0
        elif tool_name == "rustup":
            if all(p in tool_params for p in ["component", "list", "--toolchain"]):
                kwargs["outstream"].write(
                    "cargo-x86_64-pc-windows-msvc (installed)\n"
                    "clippy-x86_64-pc-windows-msvc (installed)\n"
                    "llvm-tools-x86_64-pc-windows-msvc\n"
                    "rls-x86_64-pc-windows-msvc\n"
                    "rust-analysis-x86_64-pc-windows-msvc\n"
                    "rust-analyzer-x86_64-pc-windows-msvc\n"
                    "rust-docs-x86_64-pc-windows-msvc (installed)\n"
                    "rust-src (installed)\n"
                    "rust-std-aarch64-apple-darwin\n"
                    "rust-std-aarch64-apple-ios\n"
                    "rust-std-aarch64-apple-ios-sim\n"
                    "rust-std-aarch64-linux-android\n"
                    "rust-std-aarch64-pc-windows-msvc\n"
                    "rust-std-aarch64-unknown-fuchsia\n"
                    "rust-std-aarch64-unknown-linux-gnu\n"
                    "rust-std-aarch64-unknown-linux-musl\n"
                    "rust-std-aarch64-unknown-none\n"
                    "rust-std-aarch64-unknown-none-softfloat\n"
                    "rust-std-aarch64-unknown-uefi\n"
                    "rust-std-arm-linux-androideabi\n"
                    "rust-std-arm-unknown-linux-gnueabi\n"
                    "rust-std-arm-unknown-linux-gnueabihf\n"
                    "rust-std-arm-unknown-linux-musleabi\n"
                    "rust-std-arm-unknown-linux-musleabihf\n"
                    "rust-std-armebv7r-none-eabi\n"
                    "rust-std-armebv7r-none-eabihf\n"
                    "rust-std-armv5te-unknown-linux-gnueabi\n"
                    "rust-std-armv5te-unknown-linux-musleabi\n"
                    "rust-std-armv7-linux-androideabi\n"
                    "rust-std-armv7-unknown-linux-gnueabi\n"
                    "rust-std-armv7-unknown-linux-gnueabihf\n"
                    "rust-std-armv7-unknown-linux-musleabi\n"
                    "rust-std-armv7-unknown-linux-musleabihf\n"
                    "rust-std-armv7a-none-eabi\n"
                    "rust-std-armv7r-none-eabi\n"
                    "rust-std-armv7r-none-eabihf\n"
                    "rust-std-i586-pc-windows-msvc\n"
                    "rust-std-i586-unknown-linux-gnu\n"
                    "rust-std-i586-unknown-linux-musl\n"
                    "rust-std-i686-linux-android\n"
                    "rust-std-i686-pc-windows-gnu\n"
                    "rust-std-i686-pc-windows-msvc\n"
                    "rust-std-i686-unknown-freebsd\n"
                    "rust-std-i686-unknown-linux-gnu\n"
                    "rust-std-i686-unknown-linux-musl\n"
                    "rust-std-i686-unknown-uefi\n"
                    "rust-std-loongarch64-unknown-linux-gnu\n"
                    "rust-std-loongarch64-unknown-none\n"
                    "rust-std-loongarch64-unknown-none-softfloat\n"
                    "rust-std-nvptx64-nvidia-cuda\n"
                    "rust-std-powerpc-unknown-linux-gnu\n"
                    "rust-std-powerpc64-unknown-linux-gnu\n"
                    "rust-std-powerpc64le-unknown-linux-gnu\n"
                    "rust-std-riscv32i-unknown-none-elf\n"
                    "rust-std-riscv32imac-unknown-none-elf\n"
                    "rust-std-riscv32imafc-unknown-none-elf\n"
                    "rust-std-riscv32imc-unknown-none-elf\n"
                    "rust-std-riscv64gc-unknown-linux-gnu\n"
                    "rust-std-riscv64gc-unknown-none-elf\n"
                    "rust-std-riscv64imac-unknown-none-elf\n"
                    "rust-std-s390x-unknown-linux-gnu\n"
                    "rust-std-sparc64-unknown-linux-gnu\n"
                    "rust-std-sparcv9-sun-solaris\n"
                    "rust-std-thumbv6m-none-eabi\n"
                    "rust-std-thumbv7em-none-eabi\n"
                    "rust-std-thumbv7em-none-eabihf\n"
                    "rust-std-thumbv7m-none-eabi\n"
                    "rust-std-thumbv7neon-linux-androideabi\n"
                    "rust-std-thumbv7neon-unknown-linux-gnueabihf\n"
                    "rust-std-thumbv8m.base-none-eabi\n"
                    "rust-std-thumbv8m.main-none-eabi\n"
                    "rust-std-thumbv8m.main-none-eabihf\n"
                    "rust-std-wasm32-unknown-emscripten\n"
                    "rust-std-wasm32-unknown-unknown\n"
                    "rust-std-wasm32-wasi\n"
                    "rust-std-wasm32-wasi-preview1-threads\n"
                    "rust-std-x86_64-apple-darwin\n"
                    "rust-std-x86_64-apple-ios\n"
                    "rust-std-x86_64-fortanix-unknown-sgx\n"
                    "rust-std-x86_64-linux-android\n"
                    "rust-std-x86_64-pc-solaris\n"
                    "rust-std-x86_64-pc-windows-gnu\n"
                    "rust-std-x86_64-pc-windows-msvc (installed)\n"
                    "rust-std-x86_64-unknown-freebsd\n"
                    "rust-std-x86_64-unknown-fuchsia\n"
                    "rust-std-x86_64-unknown-illumos\n"
                    "rust-std-x86_64-unknown-linux-gnu\n"
                    "rust-std-x86_64-unknown-linux-gnux32\n"
                    "rust-std-x86_64-unknown-linux-musl\n"
                    "rust-std-x86_64-unknown-netbsd\n"
                    "rust-std-x86_64-unknown-none\n"
                    "rust-std-x86_64-unknown-redox\n"
                    "rust-std-x86_64-unknown-uefi\n"
                    "rustc-x86_64-pc-windows-msvc (installed)\n"
                    "rustc-dev-aarch64-apple-darwin\n"
                    "rustc-dev-aarch64-pc-windows-msvc\n"
                    "rustc-dev-aarch64-unknown-linux-gnu\n"
                    "rustc-dev-aarch64-unknown-linux-musl\n"
                    "rustc-dev-arm-unknown-linux-gnueabi\n"
                    "rustc-dev-arm-unknown-linux-gnueabihf\n"
                    "rustc-dev-armv7-unknown-linux-gnueabihf\n"
                    "rustc-dev-i686-pc-windows-gnu\n"
                    "rustc-dev-i686-pc-windows-msvc\n"
                    "rustc-dev-i686-unknown-linux-gnu\n"
                    "rustc-dev-loongarch64-unknown-linux-gnu\n"
                    "rustc-dev-powerpc-unknown-linux-gnu\n"
                    "rustc-dev-powerpc64-unknown-linux-gnu\n"
                    "rustc-dev-powerpc64le-unknown-linux-gnu\n"
                    "rustc-dev-riscv64gc-unknown-linux-gnu\n"
                    "rustc-dev-s390x-unknown-linux-gnu\n"
                    "rustc-dev-x86_64-apple-darwin\n"
                    "rustc-dev-x86_64-pc-windows-gnu\n"
                    "rustc-dev-x86_64-pc-windows-msvc\n"
                    "rustc-dev-x86_64-unknown-freebsd\n"
                    "rustc-dev-x86_64-unknown-illumos\n"
                    "rustc-dev-x86_64-unknown-linux-gnu\n"
                    "rustc-dev-x86_64-unknown-linux-musl\n"
                    "rustc-dev-x86_64-unknown-netbsd\n"
                    "rustc-docs-x86_64-unknown-linux-gnu\n"
                    "rustfmt-x86_64-pc-windows-msvc (installed)\n"
                )
            elif all(p in tool_params for p in ["toolchain", "list"]):
                kwargs["outstream"].write(
                    "stable-x86_64-pc-windows-msvc"
                    "nightly-x86_64-pc-windows-msvc"
                    "1.71.1-x86_64-pc-windows-msvc"
                    "1.73.0-x86_64-pc-windows-msvc"
                    "1.74.0-x86_64-pc-windows-msvc"
                    "1.76.0-x86_64-pc-windows-msvc"
                    "1.77.1-x86_64-pc-windows-msvc"
                    "1.77.2-x86_64-pc-windows-msvc"
                    "ms-1.76 (default)"
                    "ms-1.76-x86_64-pc-windows-msvc"
                    "ms-stable (default)"
                )
            return 0

        return 1

    @classmethod
    def _mock_get_workspace_toolchain_version(cls) -> RustToolChainInfo:
        return RustToolChainInfo(error=False, toolchain="1.76.0")

    def test_is_corrupted_component(self):
        tool = RustToolInfo(
            presence_cmd=("rustc", "--version"),
            install_help="Install Rust compiler using rustup",
            required_version="1.76.0",
            regex=r"rustc (\d+\.\d+\.\d+)",
        )
        cmd_output = (
            f"error: the '{tool.presence_cmd[0]}' binary, normally "
            f"provided by the '{tool.presence_cmd[0]}' component, is "
            "not applicable to the ..."
        )
        self.assertTrue(_is_corrupted_component(tool, cmd_output))

        cmd_output = "rustc 1.76.0 (c560aa0e2e 2024-04-12) "
        self.assertFalse(_is_corrupted_component(tool, cmd_output))

    @patch("edk2toolext.environment.rust.RunCmd")
    def test_verify_cmd(self, mock_run_cmd: MagicMock):
        working_tool = RustToolInfo(
            presence_cmd=("rustc", "--version"),
            install_help="Install Rust compiler using rustup",
            required_version="1.76.0",
            regex=r"\d+\.\d+\.\d+",
        )
        bad_version_tool = RustToolInfo(
            presence_cmd=("rustc", "--version"),
            install_help="Install Rust compiler using rustup",
            required_version="1.77.0",
            regex=r"\d+\.\d+\.\d+",
        )
        corrupted_test_tool = RustToolInfo(
            presence_cmd=("corruptedtool", "--version"),
            install_help="Install Corrupted Tool",
            required_version="2.5.10",
            regex=r"\d+\.\d+\.\d+",
        )
        unknown_tool = RustToolInfo(
            presence_cmd=("unknowntool",),
            install_help="Install the Unknown Tool",
            required_version=None,
            regex=None,
        )
        filter_no_error_test_tool = RustToolInfo(
            presence_cmd=("filternoerrortesttool",),
            install_help="Install the Filter No Error Test Tool",
            required_version=None,
            regex=None,
        )

        custom_filters = [
            CustomToolFilter(
                filter_fn=lambda _, o: "error" in o.lower(),
                error_msg="Error occurred while verifying tool",
                error_only=True,
            ),
            CustomToolFilter(
                filter_fn=lambda _, o: "warning" in o.lower(),
                error_msg="Warning occurred while verifying tool",
                error_only=False,
            ),
            CustomToolFilter(
                filter_fn=lambda _, o: "filter match" in o.lower(),
                error_msg="A filter matched!",
                error_only=True,
            ),
        ]

        mock_run_cmd.side_effect = self._mock_run_cmd

        # Normal, working case, no custom filters
        result = _verify_cmd(working_tool, [])
        self.assertEqual(result, 0)

        # Normal, working case, custom filters
        result = _verify_cmd(working_tool, custom_filters)
        self.assertEqual(result, 0)

        # Tool not found
        result = _verify_cmd(unknown_tool, [])
        self.assertEqual(result, 1)

        # Version required and does not match
        result = _verify_cmd(bad_version_tool, custom_filters)
        self.assertEqual(result, 2)

        # Corrupted component, but custom filter takes precedence (on error)
        result = _verify_cmd(corrupted_test_tool, custom_filters)
        self.assertEqual(result, 4)

        # Corrupted component, no applicable custom filter
        result = _verify_cmd(corrupted_test_tool, [])
        self.assertEqual(result, 3)

        # Custom filter, but custom filter does not apply (no error)
        result = _verify_cmd(filter_no_error_test_tool, custom_filters)
        self.assertEqual(result, 0)

    def test_get_required_tool_versions_empty(self):
        versions = _get_required_tool_versions()
        self.assertIsInstance(versions, dict)
        self.assertEqual(len(versions), 0)

    @patch("edk2toolext.environment.rust.RunCmd")
    @patch("edk2toolext.environment.rust.get_workspace_toolchain_version")
    def test_verify_rust_src_component_is_installed(
        self,
        mock_get_workspace_toolchain_version: MagicMock,
        mock_run_cmd: MagicMock,
    ):
        mock_run_cmd.side_effect = self._mock_run_cmd
        mock_get_workspace_toolchain_version.side_effect = self._mock_get_workspace_toolchain_version
        result = _verify_rust_src_component_is_installed()
        self.assertTrue(result)

    def test_get_required_tool_versions(self):
        test_data = [
            '[toolchain]\nchannel = "1.76.0"\n\n[tool]\ncargo-make = "0.37.9"\ncargo-tarpaulin = "0.27.3"',
            '[toolchain]\nchannel = "1.76.0"\n\n[tools]\ncargo-make = "0.37.9"\ncargo-tarpaulin = "0.27.3"',
        ]

        for data in test_data:
            with patch("builtins.open", mock_open(read_data=data)):
                tool_versions = _get_required_tool_versions()
                assert tool_versions == {
                    "cargo-make": "0.37.9",
                    "cargo-tarpaulin": "0.27.3",
                }

        # Test when the workspace toolchain file does not exist
        with patch("builtins.open", side_effect=FileNotFoundError):
            tool_versions = _get_required_tool_versions()
            assert tool_versions == {}

    @patch("edk2toolext.environment.rust.RunCmd")
    def test_verify_workspace_rust_toolchain_is_installed(self, mock_run_cmd: MagicMock):
        mock_run_cmd.side_effect = self._mock_run_cmd

        # Test when the toolchain is not found
        toolchain_info = verify_workspace_rust_toolchain_is_installed()
        assert not toolchain_info.error
        assert toolchain_info.toolchain is None

        # Test when the toolchain is found and stable
        with patch("builtins.open", mock_open(read_data='[toolchain]\nchannel = "stable"')):
            toolchain_info = verify_workspace_rust_toolchain_is_installed()
            assert not toolchain_info.error
            assert toolchain_info.toolchain == "stable"

        # Test when the toolchain file is not found
        # Note: A file not found is not considered an error
        with patch("builtins.open", side_effect=FileNotFoundError):
            toolchain_info = verify_workspace_rust_toolchain_is_installed()
            assert not toolchain_info.error
            assert toolchain_info.toolchain is None

    @patch("edk2toolext.environment.rust.logging")
    @patch("edk2toolext.environment.rust.RunCmd")
    def test_run_success(self, mock_run_cmd, mock_logging):
        mock_run_cmd.return_value = 0
        custom_tool_checks = {
            "custom_tool": RustToolInfo(
                presence_cmd=("custom_tool",),
                install_help="Install custom_tool",
                required_version=None,
                regex=None,
            )
        }
        custom_tool_filters = [
            CustomToolFilter(
                filter_fn=lambda tool, output: "error" in output,
                error_msg="Custom tool error",
                error_only=False,
            )
        ]
        result = run(custom_tool_checks, custom_tool_filters)
        self.assertEqual(result, 0)
        mock_logging.error.assert_not_called()

    @patch("edk2toolext.environment.rust.logging")
    @patch("edk2toolext.environment.rust.RunCmd")
    def test_run_missing_tool(self, mock_run_cmd, mock_logging):
        mock_run_cmd.return_value = 1
        custom_tool_checks = {
            "custom_tool": RustToolInfo(
                presence_cmd=("custom_tool",),
                install_help="Install custom_tool",
                required_version=None,
                regex=None,
            )
        }
        custom_tool_filters = []
        result = run(custom_tool_checks, custom_tool_filters)
        self.assertGreaterEqual(result, 1)
        mock_logging.error.assert_called_with(
            "Rust Environment Failure: custom_tool is not installed or not on the system path.\n\n"
            "Instructions:\nInstall custom_tool\n\n"
            'Ensure "custom_tool" can successfully be run from a terminal before trying again.'
        )


if __name__ == "__main__":
    unittest.main()
