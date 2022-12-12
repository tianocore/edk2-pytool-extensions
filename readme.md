# Tianocore Edk2 PyTool Extensions (edk2toolext)

[![pypi]][_pypi]
[![codecov]][_codecov]
[![ci]][_ci]

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

[![codecov]][_codecov]
[![ci]][_ci]

The code coverage and CI badges represent unit test status and the code
coverage of those unit tests. We require 100% unit test success
(Hence the pass / fail) and that code coverage percentage does not lower.

| Host Type           | Toolchain   | Project    | Integration Tests |
| :------------------ | :---------  | :--------- | :---------------- |
| Windows Server 2019 | Python 3.9  | Edk2       | [![ewt1]][_it]    |
| Windows Server 2019 | Python 3.10 | Edk2       | [![ewt2]][_it]    |
| Windows Server 2019 | Python 3.11 | Edk2       | [![ewt3]][_it]    |
| Linux Ubuntu 18.04  | Python 3.9  | Edk2       | [![eut1]][_it]    |
| Linux Ubuntu 18.04  | Python 3.10 | Edk2       | [![eut2]][_it]    |
| Linux Ubuntu 18.04  | Python 3.11 | Edk2       | [![eut3]][_it]    |
| Windows Server 2022 | Python 3.9  | Project Mu | [![mwt1]][_it]    |
| Windows Server 2022 | Python 3.10 | Project Mu | [![mwt2]][_it]    |
| Windows Server 2022 | Python 3.11 | Project Mu | [![mwt3]][_it]    |
| Linux Ubuntu 20.04  | Python 3.9  | Project Mu | [![mut1]][_it]    |
| Linux Ubuntu 20.04  | Python 3.10 | Project Mu | [![mut2]][_it]    |
| Linux Ubuntu 20.04  | Python 3.11 | Project Mu | [![mut3]][_it]    |

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
License](https://github.com/tianocore/edk2-pytool-extensions/blob/master/LICENSE).

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

Documentation is located in the ```docs/``` folder and is split into two
separate categories. The first is located at ```docs/user/``` and is
documentation and API references for those that are using this package in their
own project. Users can generate a local copy of the
[ReadTheDocs](https://readthedocs.org/) documentation by executing the
following command from the root of the project:

```cmd
pip install --upgrade -r .\docs\user\requirements.txt
mkdocs serve
```

The second is located at ```docs/contributor/``` and is documentation for
contributing to the edk2-pytool-extensions repository.

[codecov]: https://codecov.io/gh/tianocore/edk2-pytool-extensions/branch/master/graph/badge.svg?token=vVJxZexcTI
[_codecov]: https://codecov.io/gh/tianocore/edk2-pytool-extensions
[pypi]: https://img.shields.io/pypi/v/edk2_pytool_extensions.svg
[_pypi]: https://pypi.org/project/edk2-pytool-extensions/
[ci]: https://github.com/tianocore/edk2-pytool-extensions/actions/workflows/ci.yml/badge.svg?branch=master&event=push
[_ci]: https://github.com/tianocore/edk2-pytool-extensions/actions/workflows/ci.yml

[_it]: https://dev.azure.com/tianocore/edk2-pytool-extensions/_build?definitionId=52&_a=summary&repositoryFilter=2&branchFilter=14
[ewt1]: https://dev.azure.com/tianocore/edk2-pytool-extensions/_apis/build/status/Integration%20Tests?branchName=master&configuration=Edk2_Windows_Python39
[ewt2]: https://dev.azure.com/tianocore/edk2-pytool-extensions/_apis/build/status/Integration%20Tests?branchName=master&configuration=Edk2_Windows_Python310
[ewt3]: https://dev.azure.com/tianocore/edk2-pytool-extensions/_apis/build/status/Integration%20Tests?branchName=master&configuration=Edk2_Windows_Python311

[eut1]: https://img.shields.io/github/issues/detail/label/tianocore/edk2-pytool-extensions/359?color=orange&label=issue%20359
[eut2]: https://dev.azure.com/tianocore/edk2-pytool-extensions/_apis/build/status/Integration%20Tests?branchName=master&configuration=Edk2_Ubuntu_Python310
[eut3]: https://dev.azure.com/tianocore/edk2-pytool-extensions/_apis/build/status/Integration%20Tests?branchName=master&configuration=Edk2_Ubuntu_Python311

[mwt1]: https://dev.azure.com/tianocore/edk2-pytool-extensions/_apis/build/status/Integration%20Tests?branchName=master&configuration=ProjectMu_Windows_Python39
[mwt2]: https://dev.azure.com/tianocore/edk2-pytool-extensions/_apis/build/status/Integration%20Tests?branchName=master&configuration=ProjectMu_Windows_Python310
[mwt3]: https://dev.azure.com/tianocore/edk2-pytool-extensions/_apis/build/status/Integration%20Tests?branchName=master&configuration=ProjectMu_Windows_Python311

[mut1]: https://img.shields.io/github/issues/detail/label/tianocore/edk2-pytool-extensions/359?color=orange&label=issue%20359
[mut2]: https://dev.azure.com/tianocore/edk2-pytool-extensions/_apis/build/status/Integration%20Tests?branchName=master&configuration=ProjectMu_Ubuntu_Python310
[mut3]: https://dev.azure.com/tianocore/edk2-pytool-extensions/_apis/build/status/Integration%20Tests?branchName=master&configuration=ProjectMu_Ubuntu_Python311
