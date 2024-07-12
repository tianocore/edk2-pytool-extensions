# Rust Environment Helpers

## About Rust Environment Helpers

Firmware developer's machines are often not setup for Rust. As more Rust code is proliferating across the repos, this
code can be used to provide early and direct feedback about the developer's environment so it can successfully build
Rust code using the tools commonly used in the firmware build process.

## Usage

The primary purpose of this functionality is to be used in a build plugin wrapper. However, the public functions may be
used in other contexts as well. The following functions are available:

- `run()` - Checks the current environment for Rust build support.
  - The checks can be customized with the `custom_tool_checks` and `custom_tool_filters` parameters.
- `get_workspace_toolchain_version()` - Returns the rust toolchain version specified in the workspace toolchain file.
- `verify_workspace_rust_toolchain_is_installed()` - Verifies the rust toolchain used in the workspace is available.

### Integration Examples

This section provides examples of how to use the functions available in `edk2toolext.environment.rust`.

#### `run()`

Call to check the environment for Rust build support:

```python
    import edk2toolext.environment.rust as rust_env

    def Run(self):
        error_count = rust_env.run()
        print(f"{error_count} errors found.")
```

#### `get_workspace_toolchain_version()`

Call to get Rust toolchain info:

```python
    import edk2toolext.environment.rust as rust_env

    def GetWorkspaceToolchainVersion(self):
        toolchain = rust_env.get_workspace_toolchain_version()
        print(f"Workspace toolchain version: {toolchain_version.toolchain}")
```

#### `verify_workspace_rust_toolchain_is_installed()`

Call to verify the workspace specified toolchain is installed:

```python
    import edk2toolext.environment.rust as rust_env

    def VerifyWorkspaceRustToolchainIsInstalled(self):
        rust_toolchain_info = verify_workspace_rust_toolchain_is_installed()
        if rust_toolchain_info.error:
            print(f"Error: {rust_toolchain_info.error}")
        else:
            print(f"Rust toolchain is installed: {rust_toolchain_info.toolchain}")
```
