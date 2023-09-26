# Reporting on a EDK2 workspace

Stuart provides both a library implementation and an invocable for parsing an EDK2 workspace, creating a database, and
running generic reports against the database. Reporting is supported both on regular packages (built with
`stuart_ci_build`) and platform packages (built with `stuart_build`).

There are three [stuart commands](/#what-can-i-ask-stuart-to-do) to create a database, then a forth command to run
reports against the database: `stuart_setup`/`stuart_ci_setup`, `stuart_update`, and `stuart_parse`. From there, a
developer can directly query the sqlite3 database or call `stuart_report <report>` to run a pre-build report.

## Getting Started

Similar to [building with stuart](/integrate/build/), it needs a settings file to configure itself. This settings file
must provide a settings manager subclass for each of the commands mentioned above. Please review the steps provided in
[building with stuart](/integrate/build/) on the steps necessary for integrate the above mentioned commands.

The only additional integration is to integrate `stuart_parse`, which needs the [`ParseSettingsManager`](/api/invocables/edk2_parse/#edk2toolext.invocables.edk2_parse.ParseSettingsManager)
to work. No additional methods need to be implemented, `ParseSettingsManager` just needs to be present.

## Stuart Parse

`Stuart_parse` is responsible for actually parsing the workspace and creating the database. `stuart_parse` is smart in
that it can determine if you are attempting to parse a specific platform package, or normal packages by the presence of
the `UefiBuilder` object or not. If the `UefiBuilder` object is detected, it knows that a platform package is being
parsed, and it uses the `UefiBuilder` configure the environment before parsing.

If the `UefiBuilder` object is not present, it assumes you are parsing the workspace in regards to one or multiple
regular packages. Similar to when running `stuart_ci_build`, you can filter on packages (`-p <pkg>`) amd architectures
(`-a <arch>`). When `stuart_parse` executes in this method, it parses the environment once per package, and all reports
allow you to generatea report given a specific environment.

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

Attaching directly to the same object as the `UefiBuilder` or `CiBuildSettingsManager` is for convenience; as long
as the `UefiBuilder` or `CiBuildSettingsManager` is in the file (or is a parent of a class in the file), the parser
will work as expected.

**WARNING**: ParseSettingsManager does add additional command line arguments that are used when attached to the same
object as the `CIBuildSettingsManager`, but also exist when attached to the `UefiBuilder` This may create argument
parser conflicts between platform added arguments and default arguments, that will need to be resolved.

## Stuart Report

`Stuart_report` is a standalone command line tool that is not need to be associated with a python settings file. It
only needs access to the database. Out of convenience, it assumes the database exists where `stuart_report` generates
it in the workspace, however you can override that with the `-db` command line argument. Simply run `stuart_report -h`
to view all reports, or review [TODO] TODO.
