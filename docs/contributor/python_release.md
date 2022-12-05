# Python Releases and edk2toolext

This document provides information on the necessary steps to update the
edk2-pytool-extensions repository when a new minor version of python has been
release (3.9, 3.10, etc).

## Steps

Each individual step will be a different section below and be associated with a
specific file that must be updated.

### setup.py

This file is responsible for the release process to pypi. We want to make sure
we keep the required python version for our pypi releases up to date.
Within `setuptools.setup()` locate the line `python_requires = "XXX" and
update it to the next version.

We typically support the last three minor versions; barring any special
exceptions, if the newest minor version is 3.11, then overall, we will
support 3.9, 3.10, and 3.11. Therefore you should update the line to
`python_requires = ">=3.9.0".

### integration_test/azure-pipelines/windows-robot-integration-test.yml

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
  default:
    '3_9': '3.9'
    '3_10': '3.10'
    '3_11': '3.11'
```

### readme.md

This file is what is visible to a user reviewing the package on pypi or on
github. It provides status information and shields for each supported minor
version of python. When there is a new minor version of python, we need to make
sure we keep this front page information up to date.

Due to this, we must update the table under `Current Status`. Within the table,
you must update the `Toolchain` column to the correct python version and the
`Test Status` sections to point towards the correct pipeline job. Whenever the
python version is updated, it changes the job title, so the associated entry in
this table must be updated.

Below is an example of an update due to the job title changing:

`![Azure DevOps tests](https://img.shields.io/azure-devops/tests/tianocore/edk2-pytool-extensions/8/master?Job=Build_and_Test_windows_Python_3_9.svg)`

`![Azure DevOps tests](https://img.shields.io/azure-devops/tests/tianocore/edk2-pytool-extensions/8/master?Job=Build_and_Test_windows_Python_3_10.svg)`

### azure-pipelines/ubuntu-test-pr-ci.yml

Since we support the last three minor versions of python, we want to ensure
that we run all unit tests against all three minor versions of python.

Within the `parameters:` section, we must update the python_versions parameter
to the last three versions. Barring any special exceptions, if the newest minor
version is 3.11, then overall we will support 3.9, 3.10 and 3.11 as seen below:

```yaml
parameters
...
  python_versions:
    '3_9': 3.9
    '3_10': 3.10
    '3_11': 3.11
```

### azure-pipelines/windows-test-pr-ci.yml

Since we support the last three minor versions of python, we want to ensure
that we run all unit tests against all three minor versions of python.

Within the `parameters:` section, we must update the python_versions parameter
to the last three versions. Barring any special exceptions, if the newest minor
version is 3.11, then overall we will support 3.9, 3.10 and 3.11 as seen below:

```yaml
parameters
...
  python_versions:
    '3_9': 3.9
    '3_10': 3.10
    '3_11': 3.11
```

### azure-pipelines/azure-pipelines-release.yml

This file is responsible for pushing the release to pypi, therefore we only
want to run it once, not per supported release. Due to this, we only run it for
the latest python minor version.

Within the `parameters:` section, we must update the python_versions parameter
to the latest version. Barring any special exceptions, if the latest minor
version is 3.11, then overall we will run this pipeline for 3.11

```yaml
parameters
...
  python_versions:
    '3_11': 3.11
```
