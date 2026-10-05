# Creating Plugins in a Platform Repository

Stuart discovers plugins in the workspace, loads the plugins whose scopes are
active, and makes them available to the invocable being run. A platform
repository can provide three commonly used plugin types:

| Plugin type | Interface | How it is used |
| --- | --- | --- |
| CI build plugin | `ICiBuildPlugin` | `stuart_ci_build` runs it for each selected package and target that the plugin supports. |
| Build plugin | `IUefiBuildPlugin` | `stuart_build` calls its pre-build and post-build callbacks. |
| Helper plugin | `IUefiHelperPlugin` | Stuart registers its functions on the helper object for build code and other plugins to call. |

## Make a plugin discoverable

### Add the plugin files

Keep each plugin's descriptor and Python module in the same directory.
Conventionally, repository-wide CI plugins are placed under `.pytool/Plugin`,
while build and helper plugins are placed inside the EDK II package that owns
their functionality. For example:

```text
.pytool/
`-- Plugin/
    `-- RequiredFileCheck/
        |-- RequiredFileCheck.py
        `-- RequiredFileCheck_plug_in.yaml

MyPlatformPkg/
`-- Plugins/
    |-- BuildSummary/
    |   |-- BuildSummary.py
    |   `-- BuildSummary_plug_in.yaml
    `-- PlatformPathHelpers/
        |-- PlatformPathHelpers.py
        `-- PlatformPathHelpers_plug_in.yaml
```

The exact plugin directory name within a package can follow the repository's
conventions. Stuart discovers descriptors anywhere under the workspace root
unless the settings file excludes the directory with
`GetSkippedDirectories()`.

The descriptor filename must end in `_plug_in.json` or `_plug_in.yaml`.

### Add a descriptor

Every plugin needs a descriptor with these fields:

```yaml
scope: my-platform
name: My Plugin
module: MyPlugin
```

- `scope` selects when the plugin is available. The settings file used by the
  Stuart command must return this value from `GetActiveScopes()`.
- `name` is the human-readable name shown in logs and reports.
- `module` identifies both the Python module and the class to instantiate.
  For `module: MyPlugin`, Stuart loads `MyPlugin.py`, finds
  `class MyPlugin`, and constructs it without arguments.

The descriptor and module must be in the same directory. The descriptor can
contain other fields for a plugin to read, but `scope`, `name`, and `module`
are required.

### Activate the descriptor's scope

Include the descriptor's scope in the settings used by every command that
should load the plugin:

```python
def GetActiveScopes(self):
    return ("my-platform", "cibuild")
```

In this example, descriptors in either the `my-platform` or `cibuild` scope
are active. Scopes are case-insensitive, but using the same spelling in the
descriptor and settings makes the relationship easier to see.

## CI build plugins

A CI build plugin subclasses
[`ICiBuildPlugin`](/api/environment/plugintypes/ci_build_plugin.md#edk2toolext.environment.plugintypes.ci_build_plugin.ICiBuildPlugin).
`stuart_ci_build` runs each active CI build plugin for every selected package
and for each target returned by `RunsOnTargetList()`. The inherited default is
`["NO-TARGET"]`, which makes a target-independent plugin run once per package
when `NO-TARGET` is selected.

### Descriptor

Create
`.pytool/Plugin/RequiredFileCheck/RequiredFileCheck_plug_in.yaml`:

```yaml
scope: cibuild
name: Required File Check
module: RequiredFileCheck
```

Make sure `cibuild` is one of the active scopes in the CI settings file.

### Python module

Create `.pytool/Plugin/RequiredFileCheck/RequiredFileCheck.py` next to the
descriptor:

```python
from pathlib import Path

from edk2toolext.environment.plugintypes.ci_build_plugin import ICiBuildPlugin


class RequiredFileCheck(ICiBuildPlugin):
    def GetTestName(self, package_class_name, environment):
        return (
            "Required file check",
            f"{package_class_name}.RequiredFileCheck",
        )

    def RunBuildPlugin(
        self,
        packagename,
        Edk2pathObj,
        pkgconfig,
        environment,
        PLM,
        PLMHelper,
        tc,
        output_stream,
    ):
        package_path = Edk2pathObj.GetAbsolutePathOnThisSystemFromEdk2RelativePath(
            packagename
        )
        if package_path is None:
            tc.SetFailed(
                f"Could not locate package {packagename}",
                "PACKAGE_NOT_FOUND",
            )
            return 1

        required_file = pkgconfig.get("RequiredFile", "README.md")
        required_path = Path(package_path, required_file)
        if not required_path.is_file():
            tc.SetFailed(
                f"Required file does not exist: {required_path}",
                "REQUIRED_FILE_MISSING",
            )
            return 1

        tc.SetSuccess()
        return 0
```

The plugin must set the JUnit test case state and return an integer:

- Return `0` after calling `tc.SetSuccess()` when the check passes.
- Return a positive value after calling `tc.SetFailed()` when the check fails.
- Return `-1` after calling `tc.SetSkipped()` when a prerequisite is
  unavailable and the check cannot run.

CI plugins are not guaranteed to run in a particular order. A plugin must not
depend on another CI plugin having run first.

### Package configuration

For a package named `MyPkg`, put its CI configuration in
`MyPkg/MyPkg.ci.yaml`. The configuration key defaults to the descriptor's
`module` value:

```yaml
RequiredFileCheck:
  RequiredFile: Docs/Contributing.md
```

Stuart passes the `RequiredFileCheck` mapping to `RunBuildPlugin()` as
`pkgconfig`. Package settings override the repository-wide defaults returned
by the CI settings manager:

```python
def GetPluginSettings(self):
    return {
        "RequiredFileCheck": {
            "RequiredFile": "README.md",
        },
    }
```

Set `skip: true` in the package configuration to skip the plugin for that
package:

```yaml
RequiredFileCheck:
  skip: true
```

Run `stuart_ci_build -c path/to/CISettings.py --plugin-list` to confirm that
the plugin was discovered. Then run the CI build normally:

```cmd
stuart_ci_build -c path/to/CISettings.py
```

## Build plugins

A build plugin subclasses
[`IUefiBuildPlugin`](/api/environment/plugintypes/uefi_build_plugin.md#edk2toolext.environment.plugintypes.uefi_build_plugin.IUefiBuildPlugin).
`stuart_build` passes the active
[`UefiBuilder`](/api/environment/uefi_build.md#edk2toolext.environment.uefi_build.UefiBuilder)
object to both callbacks. This object gives the plugin access to the build
environment through `thebuilder.env`, path utilities through
`thebuilder.edk2path`, registered helpers through `thebuilder.Helper`, and the
other attributes and methods documented in the `UefiBuilder` API.

### Descriptor

Create
`MyPlatformPkg/Plugins/BuildSummary/BuildSummary_plug_in.yaml`:

```yaml
scope: my-platform
name: Build Summary
module: BuildSummary
```

### Python module

Create `MyPlatformPkg/Plugins/BuildSummary/BuildSummary.py` next to the
descriptor:

```python
import logging
from pathlib import Path

from edk2toolext.environment.plugintypes.uefi_build_plugin import (
    IUefiBuildPlugin,
)


class BuildSummary(IUefiBuildPlugin):
    def do_pre_build(self, thebuilder):
        active_platform = thebuilder.env.GetValue("ACTIVE_PLATFORM")
        if active_platform is None:
            logging.error("ACTIVE_PLATFORM is not set")
            return 1

        logging.info("Starting build for %s", active_platform)
        return 0

    def do_post_build(self, thebuilder):
        output_directory = thebuilder.env.GetValue("BUILD_OUTPUT_BASE")
        if output_directory is None:
            logging.error("BUILD_OUTPUT_BASE is not set")
            return 1

        Path(output_directory, "build-summary.txt").write_text(
            "Build completed successfully.\n",
            encoding="utf-8",
        )
        return 0
```

The relevant `stuart_build` order is:

1. `PlatformPreBuild()`
2. Every active build plugin's `do_pre_build()`
3. The firmware build
4. `PlatformPostBuild()`
5. Every active build plugin's `do_post_build()`

A nonzero callback return stops the build at that point. Post-build callbacks
do not run if an earlier build step fails. Ordering among multiple plugins is
not guaranteed, so plugins must be independent.

Run the platform build to load and execute the plugin:

```cmd
stuart_build -c path/to/PlatformBuild.py
```

## Helper plugins

A helper plugin subclasses
[`IUefiHelperPlugin`](/api/environment/plugintypes/uefi_helper_plugin.md#edk2toolext.environment.plugintypes.uefi_helper_plugin.IUefiHelperPlugin)
and registers one or more callables. Stuart loads active helper plugins while
initializing an invocable.

### Descriptor

Create
`MyPlatformPkg/Plugins/PlatformPathHelpers/PlatformPathHelpers_plug_in.yaml`:

```yaml
scope: my-platform
name: Platform Path Helpers
module: PlatformPathHelpers
```

### Python module

Create `MyPlatformPkg/Plugins/PlatformPathHelpers/PlatformPathHelpers.py` next
to the descriptor:

```python
import os
from pathlib import Path

from edk2toolext.environment.plugintypes.uefi_helper_plugin import (
    IUefiHelperPlugin,
)


class PlatformPathHelpers(IUefiHelperPlugin):
    def RegisterHelpers(self, helper):
        helper.Register(
            "BuildOutputPath",
            PlatformPathHelpers.build_output_path,
            os.path.abspath(__file__),
        )

    @staticmethod
    def build_output_path(environment, *relative_parts):
        output_directory = environment.GetValue("BUILD_OUTPUT_BASE")
        if output_directory is None:
            raise RuntimeError("BUILD_OUTPUT_BASE is not set")

        return Path(output_directory, *relative_parts)
```

The registered name becomes a method on the helper object. Platform build code
can use it through `self.Helper`. Use
[`HelperFunctions.HasFunction()`](/api/environment/plugintypes/uefi_helper_plugin.md#edk2toolext.environment.plugintypes.uefi_helper_plugin.HelperFunctions.HasFunction)
to check whether a helper was registered before calling it:

```python
def PlatformPostBuild(self):
    if not self.Helper.HasFunction("BuildOutputPath"):
        logging.warning("BuildOutputPath helper is not available")
        return 0

    firmware = self.Helper.BuildOutputPath(
        self.env,
        "FV",
        "MY_PLATFORM.fd",
    )
    logging.info("Firmware image: %s", firmware)
    return 0
```

A CI build plugin can call the same helper through the `PLMHelper` argument:

```python
if not PLMHelper.HasFunction("BuildOutputPath"):
    tc.SetSkipped()
    tc.LogStdError("BuildOutputPath helper is not available")
    return -1

firmware = PLMHelper.BuildOutputPath(environment, "FV", "MY_PLATFORM.fd")
```

`HasFunction()` accepts the registered name and returns `True` only when that
name is available on the helper object. This is useful when a helper is
optional or its descriptor is active only in some scopes. If the helper is a
required platform dependency, report or raise an explicit error instead of
silently continuing.

Helper functions are attached to the helper object; they are not injected as
global Python functions. Register each name only once. A duplicate helper name
causes registration to fail.

## Troubleshooting discovery

If a plugin is not loaded, check the following:

1. The descriptor filename ends in `_plug_in.json` or `_plug_in.yaml`.
2. The descriptor is under the workspace root and not in a skipped directory.
3. The descriptor's scope is returned by `GetActiveScopes()`.
4. The descriptor's `module`, the `.py` filename, and the class name match
   exactly.
5. The plugin class can be constructed without arguments.
6. The plugin and all of its imports are available in the Python environment.
7. The module has not been disabled with `<ModuleName>=skip`.

Plugin import or construction failures are reported while Stuart is loading
plugins and stop the invocable. CI plugins can also be enumerated with
`stuart_ci_build -c path/to/CISettings.py --plugin-list`.
