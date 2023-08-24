# Stuart Parse Tool

The stuart parse tool (`stuart_parse`) is the first half of a two part tool used for generating a database and running
reports for an Edk2 UEFI codebase. The stuart parse tool will run against a codebase, executing multiple workspace
parsers and creating a database with tables for each parser that can then be consumed by any tool (though specifically
by the [edk2 report](/tools/using_edk2_report) tool) to be used as needed. In addition to parsing generic workspace
information, the parse tool is also able to parse instanced information about a package, utilizing environment
variables described by either the `stuart_build` (for platform packages) or `stuart_ci_build` (for non-platform
packages).

## Setting Up The Tool

Like all other stuart invocables, it has a [SettingsManager](/features/settings_manager) that must be implemented. This
tool has been designed to be easily implemented into the existing infrastructure and can be implemented one of two
two separate ways:

1. Subclass the [ParseSettingsManager](/api/invocables/edk2_parse/#edk2toolext.invocables.edk2_parse.ParseSettingsManager)
   to the same python object as the [UefiBuilder](/api/environment/uefi_build/#edk2toolext.environment.uefi_build.UefiBuilder)
   is subclassed to. This scenario is used to parse the workspace in terms of platform packages.

2. Associate the [ParseSettingsManager](/api/invocables/edk2_parse/#edk2toolext.invocables.edk2_parse.ParseSettingsManager)
   to the same python object as the [CiBuildSettingsManager](/api/invocables/edk2_ci_build/#edk2toolext.invocables.edk2_ci_build.CiBuildSettingsManager)
   is subclassed to. This scenario is used to parse the workspace in terms of non-platform packages.

```python
# Before implementation (platform package)
class PlatformSettingsManager(BuildSettingsManager, UefiBuilder):
    ...

# After implementation (platform package)
class PlatformSettingsManager(BuildSettingsManager, UefiBuilder, ParseSettingsManager):
    ...

# Before implementation (non-platform package)
class CiSettingsManager(CiBuildSettingsManager):
    ...

# After implementation (non-platform package)
class CiSettingsManger(CiBuildSettingsManager, ParseSettingsManager):
    ...
```

**WARNING**: ParseSettingsManager does add additional command line arguments that are used when attached to the same
object as the `CIBuildSettingsManager`, but also exist when attached to the `UefiBuilder` This may create argument
parser conflicts between platform added arguments and default arguments, that will need to be resolved.

## Command Line Interface

Similar to all other invocables, the user can use the `-h` flag review a detailed description of the CLI interface,
however for convenience, here are the options available:

``` cmd
Optional Arguments:
  --append, --Append, --APPEND    Run only environment aware parsers and append them to the database.
  -p, --pkg, --pkg-dir            Packages to parse (CI builder only)
  -a, --arch                      Architectures to use when parsing (CI builder only)
```

## Example usage

``` cmd
:: parse the workspace for mu_tiano_platform's QemuQ35Pkg in debug mode
stuart_parse -c Platforms/QemuQ35Pkg/PlatformBuild.py TARGET=DEBUG

:: parse the workspace for mu_tiano_platform's QemuQ35Pkg in release mode, appending the results to the existing database
stuart_parse -c Platforms/QemuQ35Pkg/PlatformBuild.py --append TARGET=RELEASE

:: parse the workspace for all packages supported in mu_basecore
stuart_parse -c .pytool/CISettings.py

:: parse the workspace for all packages supported in mu_basecore, filtering the packages
stuart_parse -c .pytool/CISettings.py -p MdePkg -p MdeModulePkg
```
