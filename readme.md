# Tianocore Edk2 PyTool Extensions (edk2toolext)

This is a Tianocore maintained project consisting of command line and other python tools and extensions for building and maintaining an Edk2 based UEFI firmware code tree.  This package's intent is to provide tools, scripts, and a plugin based environment for use within the tools and scripts.  This environment has command line interfaces to support building a product, building CI, running tests, and downloading dependencies.  This environment also provides the building blocks for developers to write their own tools to launch in the environment and leverage the capabilities provided by the environment.  The unique capabilities provided help support building products with multiple repositories and having each repository contribute/plugin to the build process in a scalable way.  The environment will scan the files in the code tree (multiple repos) and discover plugins, dependencies, path adjustments, environment variable settings, etc.  This provides easy methods for common repositories to share build tools/steps.

Inclusion of this package is best managed using Pip/Pypi.  This package makes use of edk2-pytool-library.

This is a supplemental package and is not required to be used for edk2 builds.

## Content

The package contains cli tools and a basic common environment for running tools.  This common environment supports extensions, sub-classing, and plugin to allow great flexibility for building and maintaining a code tree.

Examples:

* CI build support with plugin
* Binary dependency resolution (nuget, urls, git repos)
* Loggers (markdown, file, memory, and colored console)
* Plugins (pre/post build, function injection)
* Wrapper around edk2 build
* VarDict and ShellEnvrionment to manage key/value pairs consistently across entire process
* Nuget Publishing tool to push new packages
* Omnicache - Support a super cache of git repos to speed up creating and updating multiple work spaces and minimizing filesystem impact

## License

All content in this repository is licensed under [BSD-2-Clause Plus Patent License](license.txt).

[![PyPI - License](https://img.shields.io/pypi/l/edk2_pytool_extensions.svg)](https://pypi.org/project/edk2-pytool-extensions/)

## Usage

NOTE: It is strongly recommended that you use python virtual environments.  Virtual environments avoid changing the global python workspace and causing conflicting dependencies.  Virtual environments are lightweight and easy to use.  [Learn more](https://docs.python.org/3/library/venv.html)

* To install run `pip install --upgrade edk2-pytool-extensions`
* To use in your python code

    ```python
    from edk2toolext.<module> import <class>
    ```

## Release Version History

## Version 0.12.1

* Features:
  * Updated nuget to 5.3
  * Add tags to nuget packages on external dependencies and nuget publishing
* Bug:
  * #102: Fixed version aggregator so it doesn't emit warnings

## Version 0.12.0

* Features:
  * BREAKING CHANGE - PR 92 - remove special pytool toolchain processing in conf_mgmt

## Version 0.11.3

* Bug:
  * Issue 90 - edk2_pr_eval policy 3 is not first checking that change is in public file

## Version 0.11.2

* Features:
  * Add tool to evaluate which packages should be tested for a given PR
  * Improved logging and visibility

## Version 0.11.1

* Bugs
  * Issue 80 - Omnicache path check causes failure when not set

### Version 0.11.0

* Features:
  * BREAKING CHANGE - PR 77 - Refactor BuildSettingsManager.GetModulePkgsPath to GetPackagesPath
  * BREAKING CHANGE - PR 74 - Refactor SetupSettingsManager.GetRequiredRepos to GetRequiredSubmodules and return list of RequiredSubmodule objects
* Bugs
  * Issue 65 - web dependency sha256 value is case sensitive
  * Issue 72 - Nuget dependencies hang when credentials are needed
  * Issue 59 - Missing information from version report

### Version 0.10.0

* Features:
  * BREAKING CHANGE - PR 48 - Refactor for consistent multi-pkg support in invocables.
* Bugs
  * Issue 49 - Build.Conf not parsed correctly
  * Issue 47 - Setup, Update, and Build SettingsManager can't optimize based on user supplied CLI options because there is no sharing of that back to settings manager
  * Issue 40 - web dependency doesn't work on single files
  * Issue 31 - stuart_ci_build should not put all dependency in the PackagesPath
  * Issue 23 - Stuart doesn't give a good error when trying to use the wrong invocable
  * Issue 15 - Stuart_ci_build -p parameter eats all positional parameters following it


### Version 0.9.5

* Features:
  * Issue 27 - Add Api to allow override of var_dict entry
  * Change CIBuild plugins to allow detection of skipping using newly defined return code
* Bugs
  * Issue 27 - When a build variable is updated with same value but different attributes those attributes are not set.

### Version 0.9.4

* Bugs
  * Issue 14 - XML log created by Stuart_ci_build has incorrect fields

### Version 0.9.3

* Bugs
  * Issue 14 - XML log created by Stuart_ci_build has incorrect fields

### Version 0.9.2

* Bugs
  * Issue 11 - MAX_CONCURRENT_THREAD_NUMBER is not required in Target.txt
  * Issue 9  - ConfMgmt incorrect usage of shell environment leading to exception

### Version 0.9.1

* Features
  * Add documentation
* Bugs
  * Incorrect import statement in module uefi_build
  * clean up EOL and use gitattributes
  * Add nuget_publish cli (missing from initial port)

### Version 0.9.00

Initial release ported from Project Mu.
For history and documentation prior to this see the original Project Mu project
<https://github.com/microsoft/mu_pip_environment> and <https://github.com/microsoft/mu_pip_build>

## Current Status

[![PyPI](https://img.shields.io/pypi/v/edk2_pytool_extensions.svg)](https://pypi.org/project/edk2-pytool-extensions/)

| Host Type | Toolchain | Branch | Build Status | Test Status | Code Coverage |
| :-------- | :-------- | :---- | :----- | :---- | :--- |
| Windows VS 2017 | Python 3.7.x | master | [![Build Status](https://dev.azure.com/tianocore/edk2-pytool-extensions/_apis/build/status/Master%20CI%20Build%20-%20Win%20VS2017?branchName=master)](https://dev.azure.com/tianocore/edk2-pytool-extensions/_build/latest?definitionId=8&branchName=master) | ![Azure DevOps tests](https://img.shields.io/azure-devops/tests/tianocore/edk2-pytool-extensions/8.svg) | ![Azure DevOps coverage](https://img.shields.io/azure-devops/coverage/tianocore/edk2-pytool-extensions/8.svg) |
| Linux Ubuntu 1604 | Python 3.7.x | master | [![Build Status](https://dev.azure.com/tianocore/edk2-pytool-extensions/_apis/build/status/Master%20CI%20Build%20-%20Linux?branchName=master)](https://dev.azure.com/tianocore/edk2-pytool-extensions/_build/latest?definitionId=7&branchName=master) | ![Azure DevOps tests](https://img.shields.io/azure-devops/tests/tianocore/edk2-pytool-extensions/7.svg) | ![Azure DevOps coverage](https://img.shields.io/azure-devops/coverage/tianocore/edk2-pytool-extensions/7.svg) |

## Contribution Process

This project welcomes all types of contributions.
For issues, bugs, and questions it is best to open a [github issue](https://github.com/tianocore/edk2-pytool-extensions/issues).

### Code Contributions

For code contributions this project leverages github pull requests.  See github tutorials, help, and documentation for complete descriptions.
For best success please follow the below process.

1. Contributor opens an issue describing problem or new desired functionality
2. Contributor forks repository in github
3. Contributor creates branch for work in their fork
4. Contributor makes code changes, writes relevant unit tests, authors documentation and release notes as necessary.
5. Contributor runs tests locally
6. Contributor submits PR to master branch of tianocore/edk2-pytool-extensions
    1. PR reviewers will provide feedback on change.  If any modifications are required, contributor will make changes and push updates.
    2. PR automation will run and validate tests pass
    3. If all comments resolved, maintainers approved, and tests pass the PR will be squash merged and closed by the maintainers.

## Maintainers

See the [github team](https://github.com/orgs/tianocore/teams/edk-ii-tool-maintainers) for more details.

## Documentation

See the github repo __docs__ folder
