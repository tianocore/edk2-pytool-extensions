# Continuous Integration with Stuart

The idea of Continuous Integration (CI) with Stuart is that you have code and
you have a to-do list of tasks that verify this code meets the requirements
defined by you or your team. Stuart provides an easy to use interface that
automates this process.

To take your firmware code tree from freshly cloned to fully tested, you only
need to execute three commands. If you've properly [installed](/using/install)
edk2-pytool-extensions, then these commands will be available to execute as
seen below:

```cmd
stuart_init -c path/to/CISettingsFile.py
stuart_update -c path/to/CISettingsFile.py
stuart_ci_build -c path/to/CISettingsFile.py
```

!!! tip
    Review your platform's instructions as it is common to install any
    additional python requirements via the command
    `pip install --upgrade -r pip-requirements.txt`, where pip-requirements.txt
    contains the necessary python requirements.

Stuart provides platforms the ability to customize it's CI via command
flags. Due to this **Your platform's build instructions is the single
source of truth.**

As you can see, Each of these commands has a single required flag `-c` that
points towards a CI settings file. There is no set place for this file, so
**refer to your platform's build instructions for the exact name and location
of this file.**

Curious about what each command does? Check out the below sections.

## stuart_init

Stuart_init is responsible for downloading all git submodule and repository
dependencies required to perform all CI tasks.

```cmd
stuart_init -c path/to/CISettingsFile.py
```

## stuart_update

Stuart_update is responsible for downloading all other required external
dependencies (including, but not limited to nuget, azure, etc) required to
perform all CI tasks.

```cmd
stuart_update -c path/to/CISettingsFile.py
```

## stuart_ci_build

Stuart_ci_build is responsible for executing all CI tasks and placing any
artifacts in the /Build/ directory.

```cmd
stuart_ci_build -c path/to/CISettingsFile.py
```

## FAQ

N/A
