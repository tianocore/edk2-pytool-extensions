# Integration testing for Edk2 Pytool Extensions

This describes what is needed to run integration testing on pytool extensions.  This testing will use known compatible
and public open source repositories for validation.  This set of automated tests will run common user level operations
and validate that pytools works as expected. Some basic examples are:

* Build Edk2 OvmfPkg Platform CI
* Run Core Ci on Edk2 MdeModulePkg
* After committing a change in the repo use pr_eval to confirm the correct packages need testing.

## Prerequisites

* Standard Edk2 Prerequisites
  * git cli
  * Python 3.8.x with support for Pip and virtual environment
  * VS 2019 (Windows Only)
  * GCC (Linux Only)
* Additional requirements
  * robot framework
  * QEMU (on your path)

## Process

1. Create new virtual environment
2. Activate virtual environment
3. Clone edk2-pytool-extension
4. Check out desired version/branch and cd to root (folder where *setup.py* is located)
5. Pip Install the local version by running `pip install -e .` in the root directory
6. Pip install remaining dependencies by running `pip install --upgrade -r integration_test/pip-requirements.txt`
7. cd to *integration_test* directory (folder where *this* document is located)
8. Run robot `python -m robot.run -v TEST_OUTPUT_BASE:test -d report <additional flags here> <robot file to run or directory>`
   1. use `.` to run all test cases in all robot files in the current directory
   2. use `edk2_stuart_pr_eval.robot` robot file for testing stuart pr eval using edk2 repo
   3. use `edk2_core_ci.robot` robot file for running parts of the core ci tests on edk2
   4. use `edk2_platform_ci.robot` robot file for running parts of the platform ci tests on edk2

## Additional useful CLI flags

1. Only run test cases with a given tag
   1. `--include CoreCI` to run only the CoreCI tests
   2. `--include PlatformCI` to run only the Platform CI tests
   3. `--include PrEval` to run only the pr_eval tests
   4. `--include Edk2` to run only on edk2 repo
   5. `--include ProjectMu` to run only on Project Mu basecore repo
2. More Debug info in log
   1. `-L TRACE` to run with most detailed info
   2. `-L DEBUG` to turn on debug level.  This is less than trace
   3. `-L INFO` this is the default level.
3. Set more variables
   1. `-v <var name>:<var value>` set a variable for your robot file

## Lessons learned/Tips

### Robot hangs for seemingly unknown reason

It is well known that robot will hang if you "log too much" from Run Process.  For example running git clone can sometimes
create a large log.  So for those commands which can create a large log redirect stdout and stderr to a file.  To do this
add additional parameters to your "Run Process" cmd like so `stdout=stdout.txt  stderr=stderr.txt`.  For an example in action
look at the keywords for all stuart commands.

### Run a single test so you can collect the logs from the file system

Robot framework supports running a single test by providing the test name.  The robot.run command should
add `-t "the test case name here"`.  This has been useful to run a single failing test on your filesystem and then
collect the stuart log to debug problems.

## Helpful Robot Links

<https://robotframework.org> is the main site.  Lots of good info here.  My most commonly used pages are:

* UserGuide: <https://robotframework.org/robotframework/latest/RobotFrameworkUserGuide.html>
* Operating System Library: <https://robotframework.org/robotframework/latest/libraries/OperatingSystem.html>
* BuiltIn Library: <https://robotframework.org/robotframework/latest/libraries/BuiltIn.html>
* String Library: <https://robotframework.org/robotframework/latest/libraries/String.html>

## Copyright

Copyright (c) Microsoft Corporation.  
SPDX-License-Identifier: BSD-2-Clause-Patent
