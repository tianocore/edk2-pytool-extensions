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
stuart_ci_setup -c path/to/CISettingsFile.py
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

## stuart_ci_setup

Stuart_ci_setup is responsible for downloading all git submodule dependencies
required to perform all CI tasks.

```cmd
stuart_ci_setup -c path/to/CISettingsFile.py
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
artifacts in the /Build/ directory. By default, stuart_ci_build will run
all tests on all packages as specified by the configuration file passed
to it with the `-c` command.

```cmd
stuart_ci_build -c path/to/CISettingsFile.py
```

You can filter the package's you want to test with the `-p` command and the
type of test to execute with the `-t` command. To determine available packages
and test targets available, use the help command (note you'll only see the
available options if you provide the configuration file):

```cmd
stuart_ci_build -c path/to/CISettingsFile.py --h`
```

## FAQ

Q: Is there a way for me to skip a CI test?
A: Yes! You have two ways to skip a CI tests. You can permanently skip a
   specific CI test for a package by adding the configuration `{"skip": true}`
   in the package's ci.yaml file. If you just need to skip a specific CI test
   once, you can add `<TestName>=skip` to the command line.

Q: Is there a way for me to only run a single test?
A: Yes! You can turn off all tests with the `-d, --disable-all` command line
   argument, then turn the test(s) back on with `<TestName>=run`
