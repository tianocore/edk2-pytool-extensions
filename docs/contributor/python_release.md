# Python Releases and edk2toolext

This document provides information on the necessary steps to update the
edk2-pytool-extensions repository when a new minor version of python has been
release (3.12, 3.13, etc).

## Steps

Each individual step will be a different section below and be associated with a
specific file that must be updated.

### pyproject.toml

We must update the classifiers section to show the new supported python version:

```cmd
classifiers=[
        ...
        "Programming Language :: Python :: 3.10",
        "Programming Language :: Python :: 3.11",
        "Programming Language :: Python :: 3.12",
        "Programming Language :: Python :: 3.13"
    ]
```

### bug_report.yml

Update the supported python versions in the entry with `id: py_version`

### VariableProducer.yml

Update `pythonversions` to the support versions

### tests.integration/azure-pipelines/windows-robot-integration-test.yml

Since we support the last three minor versions of python, we want to ensure
that we run integration tests against all three supported versions.

Within the `parameters:` section, we must update the PythonVersionList
parameter to the last three versions. Barring any special exceptions, if the
newest minor version is 3.11, then overall we will support 3.9, 3.10, and 3.11
as seen below:

```yaml
parameters:
- name: PythonVersionList
  type: object
  default: ['3.9', '3.10', '3.11']
```

### readme.md

This file is what is visible to a user reviewing the package on pypi or on
github. It provides status information and shields for each supported minor
version of python. When there is a new minor version of python, we need to make
sure we keep this front page information up to date.

Due to this, we must update the table under `Current Status`. Within the table,
you must update the `Toolchain` column to the correct python version and the
`Integration Tests` section links to point towards the correct pipeline job.
Whenever the python version is updated, it changes the job title, so the
associated entry in this table must be updated. These entries are links that
can be found at the bottom of the readme.

Links are abbreviated to represent the particular test. In the example below,
the test link is abbreviated `ewt1` standing for Edk2-Windows-Test #1. When
updating to a new Python version, we simply need to bump the python version
in the link as seen below

#### Current Python Version 3.11

```md
[ewt1]: https://dev.azure.com/tianocore/edk2-pytool-extensions/_apis/build/status/Integration%20Tests?branchName=master&configuration=Edk2_Windows_Python39
[ewt2]: https://dev.azure.com/tianocore/edk2-pytool-extensions/_apis/build/status/Integration%20Tests?branchName=master&configuration=Edk2_Windows_Python310
[ewt3]: https://dev.azure.com/tianocore/edk2-pytool-extensions/_apis/build/status/Integration%20Tests?branchName=master&configuration=Edk2_Windows_Python311
```

#### Upgrading to Python Version 3.12

```md
[ewt1]: https://dev.azure.com/tianocore/edk2-pytool-extensions/_apis/build/status/Integration%20Tests?branchName=master&configuration=Edk2_Windows_Python310
[ewt2]: https://dev.azure.com/tianocore/edk2-pytool-extensions/_apis/build/status/Integration%20Tests?branchName=master&configuration=Edk2_Windows_Python311
[ewt3]: https://dev.azure.com/tianocore/edk2-pytool-extensions/_apis/build/status/Integration%20Tests?branchName=master&configuration=Edk2_Windows_Python312
```

### azure-pipelines/templates/basic-setup-steps.yml

This file is responsible for setting the python version when pushing the
release to pypi, which is why we want to keep it on the most up to date
python version.

Within the `task: UsePythonVersion@0:` section, we must update the
`versionSpec` parameter to the latest version. Barring any special
exceptions, if the latest minor version is 3.11, then overall we will run
this pipeline for 3.11

```yaml
parameters
- task: UsePythonVerion@0
  inputs:
    versionSpec: '3.11'
    architecture: 'x64'
```
