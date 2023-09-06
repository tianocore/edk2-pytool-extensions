# CodeQL

## About CodeQL

CodeQL is open source and free for open-source projects. It is maintained by GitHub and naturally has excellent
integration with GitHub projects. CodeQL generates a "database" during the firmware build process that enables queries
to run against that database. Many open-source queries are officially supported and comprise the vulnerability analysis
performed against the database. These queries are maintained here - [github/codeql](https://github.com/github/codeql).

Queries are written in an object-oriented query language called QL. CodeQL provides:

1. A [command-line (CLI) interface](https://codeql.github.com/docs/codeql-cli/#codeql-cli)
2. A [VS Code extension](https://codeql.github.com/docs/codeql-for-visual-studio-code/#codeql-for-visual-studio-code)
   to help write queries and run queries
3. [GitHub action](https://github.com/github/codeql-action) support for repo integration via
   [code scanning](https://docs.github.com/en/code-security/code-scanning/automatically-scanning-your-code-for-vulnerabilities-and-errors/configuring-code-scanning)
4. In addition to other features described in the [CodeQL overview](https://codeql.github.com/docs/codeql-overview/)

## CodeQL Usage

CodeQL provides the capability to debug the actual queries and for our (Tianocore) community to write our own queries
and even contribute back to the upstream repo when appropriate. In other cases, we might choose to keep our own queries
in a separate TianoCore repo or within a directory in the edk2 code tree.

This is all part of CodeQL Scanning. [This page](https://docs.github.com/en/code-security/code-scanning/automatically-scanning-your-code-for-vulnerabilities-and-errors/configuring-code-scanning)
has information concerning how to configure CodeQL scanning within a GitHub project such as edk2. Information on the
topic of running additional custom queries is documented [here](https://docs.github.com/en/code-security/code-scanning/automatically-scanning-your-code-for-vulnerabilities-and-errors/configuring-code-scanning#running-additional-queries)
in that page.

In addition, CodeQL offers the flexibility to:

- Build databases locally
- Retrieve databases from server builds
- Relatively quickly test queries locally against a database for a fast feedback loop
- Suppress false positives
- Customize the files and queries used in the edk2 project and quickly keep this list in sync between the server and
  local execution

## EDK2 PyTool Extensions CodeQL Module

A Python module located in `edk2toolext/codeql.py` provides helper functions that platform and CI build files can use
to support CodeQL enabled builds with minimal effort.

The following functions are available. The expected actions to be taken per scope are included as well.

- `add_command_line_option()` - Adds the CodeQL command (`--codeql`) to the platform command line options.
- `get_scopes()` - Returns the active CodeQL scopes for this build.
  - Host OS neutral scopes:
    - `codeql-build` - Build the CodeQL database during firmware build.
    - `codeql-analyze` - Analyze the CodeQL database after firmware build (post-build).
  - Linux scope:
    - `codeql-linux-ext-dep` - Download the Linux CodeQL CLI external dependency.
  - Windows scope:
    - `codeql-windows-ext-dep` - Download the Windows CodeQL CLI external dependency.
- `is_codeql_enabled_on_command_line` - Returns whether CodeQL was enabled (via `--codeql`) on the command line.
- `set_audit_only_mode` - Configures the CodeQL plugin to run in audit only mode.

These functions are intended to ease repo integration with CodeQL, ensure consistent command-line usage across repos,
and define standard scopes that other plugins and tools can depend on for CodeQL operations.

### Integration Examples

This section provides examples of how to use the functions available in `edk2toolext/codeql.py`.

#### add_common_line_option()

Call when the command-line options are registered for the build:

```python
    import edk2toolext.codeql as codeql_helpers

    def AddCommandLineOptions(self, parserObj):
        codeql_helpers.add_command_line_option(parserObj)
```

#### get_scopes()

Call when scopes are returned for the build file:

```python
    import edk2toolext.codeql as codeql_helpers

    def GetActiveScopes(self):
        scopes = ("cibuild", "edk2-build", "host-based-test")

        scopes += codeql_helpers.get_scopes(self.codeql)
        return scopes
```

#### is_codeql_enabled_on_command_line()

Call when code needs to know if the CodeQL argument was given on the command line:

```python
    import edk2toolext.codeql as codeql_helpers

    def RetrieveCommandLineOptions(self, args):
        super().RetrieveCommandLineOptions(args)

        try:
        self.codeql = codeql_helpers.is_codeql_enabled_on_command_line(args)
```

In the above example, a `Settings` class is creating an instance variable that can be referred to later based on the
value returned from the function.

#### set_audit_only_mode()

Call when a CI or platform build would like to enable audit mode for the current build invocation.

```python
    import edk2toolext.codeql as codeql_helpers

    def GetActiveScopes(self):
        codeql_helpers.set_audit_only_mode()
```
