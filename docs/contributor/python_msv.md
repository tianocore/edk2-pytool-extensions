# Python Minimum Supported Version

In addition to the N-2 versions of python being actively maintained and
supported, this repository also has a minimum supported version (MSV) of
python. Any version of python between the MSV and N-2 version of python is not
actively maintained or monitored, however it is supported (e.g. the repository
does not use any features past this version of python).

The MSV for this project is subject to change at any time based on project
needs and features introduced by python. At a minimum, this repository will
never use a feature newer than N-2, providing a two year lookback period for
consumers to increase their supported version of python while receiving new
feature updates of this project.

## Updating the MSV

If the need arises to increase the minimum supported version of python, below
are the necessary files and steps to update the repository.

### pyproject.toml

This file is responsible for the release process to pypi. We want to make sure
we keep the required version for our pypi releases up to date. Update
`requires-python` to the new msv.

Additionally, we must update the classifiers section to remove the now
unsupported versions of python.

```python
classifiers=[
    "Programming Language :: Python :: 3.10",
    "Programming Language :: Python :: 3.11",
    "Programming Language :: Python :: 3.12",
    "Programming Language :: Python :: 3.13"
]
```

### bug_report.yml

Remove the now unsupported version of python in the following
section: `id: py_version`.

### VariableProducer.yml

Update `python-msv:` to the new msv

### readme.md

Update the `Toolchain` section of the `Minimum Supported Version` table.
