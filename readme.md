# Tianocore Edk2 PyTool Extensions (edk2toolext)

This is a Tianocore maintained project consisting of command line and other
python tools and extensions for building and maintaining an Edk2 based UEFI
firmware code tree. Part of these tools include "invocables" that can be used to
build EDK2 Platforms and these tools are known as "stuart". This package's
intent is to provide tools, scripts, and a plugin based environment for use
within the tools and scripts. This environment has command line interfaces to
support building a product, building CI, running tests, and downloading
dependencies. This environment also provides the building blocks for developers
to write their own tools to launch in the environment and leverage the
capabilities provided by the environment. The unique capabilities provided help
support building products with multiple repositories and having each repository
contribute/plugin to the build process in a scalable way. The environment will
scan the files in the code tree (multiple repos) and discover plugins,
dependencies, path adjustments, environment variable settings, etc. This
provides easy methods for common repositories to share build tools/steps.

Inclusion of this package is best managed using Pip/Pypi.  This package makes
use of edk2-pytool-library.

This is a supplemental package and is not required to be used for edk2 builds.

![stuart himself](stuart_logo.png "Stuart")

## Current Status

| Host Type | Toolchain | Branch | Build Status | Test Status | Code Coverage |
| :-------- | :-------- | :---- | :----- | :---- | :--- |
| Windows Server 2019 | Python 3.8.x | master | [![Build Status](https://dev.azure.com/tianocore/edk2-pytool-extensions/_apis/build/status/Master%20CI%20Build%20-%20Win%20VS2017?branchName=master)](https://dev.azure.com/tianocore/edk2-pytool-extensions/_build/latest?definitionId=8&branchName=master) | ![Azure DevOps tests](https://img.shields.io/azure-devops/tests/tianocore/edk2-pytool-extensions/8.svg) | ![Azure DevOps coverage](https://img.shields.io/azure-devops/coverage/tianocore/edk2-pytool-extensions/8.svg) |
| Linux Ubuntu 1804 | Python 3.8.x | master | [![Build Status](https://dev.azure.com/tianocore/edk2-pytool-extensions/_apis/build/status/Master%20CI%20Build%20-%20Linux?branchName=master)](https://dev.azure.com/tianocore/edk2-pytool-extensions/_build/latest?definitionId=7&branchName=master) | ![Azure DevOps tests](https://img.shields.io/azure-devops/tests/tianocore/edk2-pytool-extensions/7.svg) | ![Azure DevOps coverage](https://img.shields.io/azure-devops/coverage/tianocore/edk2-pytool-extensions/7.svg) |

### Current Release

[![PyPI](https://img.shields.io/pypi/v/edk2_pytool_extensions.svg)](https://pypi.org/project/edk2-pytool-extensions/)

All release information is now tracked with Github
 [tags](https://github.com/tianocore/edk2-pytool-extensions/tags),
 [releases](https://github.com/tianocore/edk2-pytool-extensions/releases) and
 [milestones](https://github.com/tianocore/edk2-pytool-extensions/milestones).

## Content

The package contains cli tools and a basic common environment for running tools.
This common environment supports extensions, sub-classing, and plugin to allow
great flexibility for building and maintaining a code tree.

Examples:

* CI build support with plugin
* Binary dependency resolution (nuget, urls, git repos)
* Loggers (markdown, file, memory, and colored console)
* Plugins (pre/post build, function injection)
* Wrapper around edk2 build
* VarDict and ShellEnvrionment to manage key/value pairs consistently across
  entire process
* Nuget Publishing tool to push new packages
* Omnicache - Support a super cache of git repos to speed up creating and
  updating multiple work spaces and minimizing filesystem impact

## License

All content in this repository is licensed under [BSD-2-Clause Plus Patent
License](license.txt).

[![PyPI -
License](https://img.shields.io/pypi/l/edk2_pytool_extensions.svg)](https://pypi.org/project/edk2-pytool-extensions/)

## Usage

NOTE: It is strongly recommended that you use python virtual environments.
Virtual environments avoid changing the global python workspace and causing
conflicting dependencies.  Virtual environments are lightweight and easy to use.
[Learn more](https://docs.python.org/3/library/venv.html)

* To install run `pip install --upgrade edk2-pytool-extensions`
* To use in your python code

    ```python
    from edk2toolext.<module> import <class>
    ```

## History

This project and functionality was ported from Project Mu. For history and
documentation prior to this see the original Project Mu projects
<https://github.com/microsoft/mu_pip_environment> and
<https://github.com/microsoft/mu_pip_build>

## Contribution Process

This project welcomes all types of contributions. For issues, bugs, and
questions it is best to open a [github
issue](https://github.com/tianocore/edk2-pytool-extensions/issues).

### Code Contributions

For code contributions this project leverages github pull requests.  See github
tutorials, help, and documentation for complete descriptions. For best success
please follow the below process.

1. Contributor opens an issue describing problem or new desired functionality
2. Contributor forks repository in github
3. Contributor creates branch for work in their fork
4. Contributor makes code changes, writes relevant unit tests, authors
   documentation and release notes as necessary.
5. Contributor runs tests locally
6. Contributor submits PR to master branch of tianocore/edk2-pytool-extensions
    1. PR reviewers will provide feedback on change.  If any modifications are
       required, contributor will make changes and push updates.
    2. PR automation will run and validate tests pass
    3. If all comments resolved, maintainers approved, and tests pass the PR
       will be squash merged and closed by the maintainers.

## Maintainers

See the [github
team](https://github.com/orgs/tianocore/teams/edk-ii-tool-maintainers) for more
details.

## Documentation

See the github repo __docs__ folder
