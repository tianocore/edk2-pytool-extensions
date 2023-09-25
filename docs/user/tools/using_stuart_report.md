# Report Generator Tool

The report generator tool `stuart_report` is a tool that allows you to run
reports on database that was generated via `stuart_parse`. The tool is designed
to be portable, such that it can be ran on a database and the repository the
database was generated from does not have to be present. This is so that
databases can be archived, or passed around, and reports can be generated after
the fact, or used to compare different versions of the firmware.

## Command line arguments

``` cmd
usage: A tool to generate reports on a edk2 workspace. [-h] [--verbose] [-db DATABASE] {coverage,component-libs,usage} ...

positional arguments:
  {coverage,component-libs,usage}

options:
  -h, --help            show this help message and exit
  --verbose, --VERBOSE, -v
                        verbose
  -db DATABASE, --database DATABASE, --DATABASE DATABASE
                        The database to use when generating reports. Can be a comma separated list of db's to merge. Globbing is supported.
```

Review the command line arguments with `stuart_report -h`. As you can tell, the
command line interface for the tool itself is simple, only truly needing a path
to the database to use. Out of convenience, the default path for the database
is Reports/DATABASE.db, as that is where the database is generated when running
`stuart_parse`. If the database is moved or renamed, you will need to manually
link it with the `-db, --database`.

Each available report (positional argument) has it's own subset of command line
arguments so before running a report, it is important to review it's interface
also `stuart_report <Report> -h` to see the customizations / necessary
arguments for the report.

### Coverage Report

`stuart_report coverage` converts coverage xml results into a similar coverage
xml that re-organizes the data to be based off the library INF rather than the
executed binary used for testing. It provides a more accurate representation of
the current code coverage as most UEFI developers will care about code coverage
of a specific library. Additionally, some files are used in multiple INFs,
which this report will more accurately depict.

Due to the complex nature involved in building a UEFI package, code coverage
results can also contain code coverage results for INFs outside of the package
the developer cares about. This tool allows for the filtering of results to
specific packages.

``` cmd
usage: A tool to generate reports on a edk2 workspace. coverage [-h] [-o OUTPUT] [-s {inf}] [-p PACKAGE_LIST] [-ws WORKSPACE] [--library] xml

Reorganizes an xml coverage report by INF rather than executable.

positional arguments:
  xml                   The path to the XML file parse.

options:
  -h, --help            show this help message and exit
  -o OUTPUT, --output OUTPUT, --Output OUTPUT, --OUTPUT OUTPUT
                        The path to the output XML file.
  -s {inf}, --scope {inf}, --Scope {inf}, --SCOPE {inf}
                        The scope to associate coverage data
  -p PACKAGE_LIST, --package PACKAGE_LIST, --Package PACKAGE_LIST, --PACKAGE PACKAGE_LIST
                        The package to include in the report. Can be specified multiple times.
  -ws WORKSPACE, --workspace WORKSPACE, --Workspace WORKSPACE, --WORKSPACE WORKSPACE
                        The Workspace root associated with the xml argument.
  --library             To only show results for library INFs
```

### Usage Report

`stuart_report usage` generates a standalone html document (requires internat)
that contains pie charts showing the different library and component INFs that
are used to build the specific package parsed, and which submodules (or BASE)
they come from. It also contains a table of all INFs used, and a table of all
environment variables used when building the package.

``` cmd
usage: A tool to generate reports on a edk2 workspace. usage [-h] [-e ENV_ID] [-o OUTPUT]

Generates a report of INF usage for a specific build.

options:
  -h, --help            show this help message and exit
  -e ENV_ID, -env ENV_ID
                        The environment id to generate the report for. Defaults to the latest environment.
  -o OUTPUT, -output OUTPUT
                        The output file to write the report to. Defaults to 'usage_report.html'.
```

### Component Library Report

`stuart_report component-libs` prints to the terminal (or writes to a file) the
actual list of library instances (and their associated library classes) used to
create the component. This is based off the package dsc that was parsed. The
report will print a flat version, providing each library compiled into the
component, or a recursive list of dependencies for each library.

``` cmd
usage: A tool to generate reports on a edk2 workspace. component-libs [-h] [-o FILE] [-d DEPTH] [-f] [-s] [-e ENV_ID] component

Dumps the library instances used by component.

positional arguments:
  component             The component to query.

options:
  -h, --help            show this help message and exit
  -o FILE, --out FILE   The file, to write the report to. Defaults to stdout.
  -d DEPTH, --depth DEPTH
                        The depth to recurse when printing libraries used.
  -f, --flatten         Flatten the list of libraries used in the component.
  -s, --sort            Sort the libraries listed in alphabetical order.
  -e ENV_ID, --env ENV_ID
                        The environment id to generate the report for.
```
