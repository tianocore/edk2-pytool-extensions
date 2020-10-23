# The Self Describing Environment and You

## The Genesis

Previous to stuart, a simple wrapper around the EDK2 build system was developed.
As it grew, the centralized systems that have been in place to this point have gotten more and more brittle.
Previously, the paths to critical files and build tools have been hard-coded into the primary build scripts (such as
PlatformBuild.py). If code was to be added or moved, all build scripts for all projects had to be updated to find
the new code and consume it.

Furthermore, the old build system required that all binaries, executables, artifacts, and other miscellaneous files
be carried in the source tree somewhere. Since moving to Git, this cost has become increasingly burdensome to the
point where some of the larger repositories are almost unwieldy.

The new Self Describing Environment system, along with the new Plugin behavior, aims to remedy some of these problems,
while preserving flexibility and agility for further project growth.

## What is it

The Self-Describing Environment is assembled by a combination of scripts and descriptor files. The scripts locate the
descriptor files and configure the environment in a number of different ways (eg. PATH, PYTHONPATH, Shell Variables,
Build Variables, external dependencies, etc.). Currently, there are two kinds of descriptor files that can be found in
the Core UEFI tree: Path Environment descriptors (path_env) and External Dependency descriptors (ext_dep). Both of these
files are simple JSON files containing fields that are used to configure the SDE. They have some overlapping features,
but are used for very different purposes.

Many of these features have their own documentation, and you are encouraged to go check them out.

## path_env Descriptors

The path_env descriptor is used, primarily, to update the path. This way the build system can locate required tools and
scripts. It can also update build vars that can be referenced from the Settings Manager or Uefi Builder to locate
things like binary artifacts that will be included in certain build steps (eg. OPROM binaries).

The path_env descriptor works by taking the path containing the descriptor and applying it to the environment as
specified by the fields of the descriptor. For example, if there were a path_env file located at
"\MyBuild\SubDir\Tools\my_sample_path_env.json" and the descriptor flags included "set_path", "\MyBuild\SubDir\Tools"
would be added to the environment path. path_env descriptors are located by the environment configuration scripts by
searching the Workspace for files ending in "*_path_env.json". It does not matter what the first part of the file is
called, so long as the end is correct. By convention, the first part of the file name should be descriptive enough to
differentiate a given descriptor from another descriptor, should it show up in a "find in files" list or something.

The following path_env fields are required:

- scope

  - Identifies which build environments this descriptor contributes to, and what level of precedence it should take
    within that environment.

- flags

  - We'll see that flags are common to both path_env and ext_dep descriptors, but they are required for path_env (and
    only optional for ext_dep). This is because it doesn't make any sense to create a path_env descriptor without
    specifying what part of the environment should be updated.

Currently supported flags are:

- host_specific

  - Allows a nuget package to specify that the contents of the package are organized by host OS or architecture. The SDE
    will determine what folder is relevant for the host OS and product being built and add that to the path.

- set_path

  - Adds the NuGet unpacked folder to the front of PATH

- set_pypath

  - Adds the NuGet unpacked folder to the front of PYTHONPATH. Also adds it to sys.path.

- set_build_var

  - Sets a build variable with the key being the name of the ext_dep and the value being the path of the nuget unpacked folder
  - If you include this attribute you must include a var_name
  - (a var that exists internally to the build system that is retrieved with with env.GetValue())

- set_shell_var

  - Sets a shell variable with the key being the name of the ext_dep and the value being the path of the nuget unpacked folder
  - If you include this attribute you must include a var_name
  - (a var that exists in the command-line environment via "set" or "os.environ" or "env")

- include_separator

  - Includes a path separated at the end of the path we set in variables

The following path_env fields are optional or conditional:

- var_name

  - If either the "set_shell_var" or "set_build_var" are in the flags, this field will be required. It defines the name
    of the var being set.

- id

  - Part of the Override System, this field defines the name that this file will be referred to as by any override_id fields.
  It is an error for there to be multiple files with the same id in the same set of scopes.
  The SDE will throw an exception in this case.
  You are welcome to have the same id if they're on separate scopes that won't overlap.

- override_id

  - This file will override any descriptor files.
  Override can apply to any type of descriptor (a path env can override an ext_dep for example).
  If two descriptors override the same file, this is considered an error and the SDE will throw an exception.

## The Belly of the Beast

### self_describing_environment.py

This is the proverbial "heart of the beast". It contains most of the business logic for locating, compiling, sorting,
filtering, and assembling the SDE files and the environment itself. There are class methods and helper functions to do
things like:

- Locate all the relevant files in the workspace.
- Sort the files lexically and by scope.
- Filter the files based on overrides.
- Assemble the environment (eg. PATH, PYTHONPATH, vars, etc.).
- Validate all dependencies.
- Update all dependencies.

Many of these routines will leverage logic specific to individual sub-modules (Python, not Git), but the collective
logic is located here.

### EnvironmentDescriptorFiles.py

This module contains business logic and validation code for dealing with the descriptor files as JSON objects. It
contains code (and error checking) for loading the files, reading their contents into a standard internal
representation, and running a limited set of sanitization and validation functions to identify any mistakes as early
as possible and provide as much information as possible. For convenience, this module also contains the class code for
PathEnv descriptor objects, but that's because the class code is so small felt silly to create another file.

### ExternalDependencies.py

This module contains code for managing external dependencies. ExternalDependency objects are created with the data from
ext_dep descriptors and are subclassed according to the "type" field in the descriptor. Currently, the only valid
subclass is "nuget". These objects contain the code for fetching, validating, updating, and cleaning dependency objects
and metadata. When referenced from the SDE itself, they can also update paths and other build/shell vars in the build
environment.

## Taming the SDE

### Understanding Scope

A critical concept in the SDE system is that of "scope". Each project can define its own scope, and scope is integral to
the distributed and shared nature of the SDE. Project scopes are linearly hierarchical and can have an arbitrary number
of entries. Only descriptors matching one or more of the scope entries will be included in the SDE during
initialization. Furthermore, higher scopes will take precedence when setting paths and assigning values to vars. An
example project scope might be: `("my_platform", "tablet_family", "silicon_reference")`

In this example, "my_platform" is the highest priority in the scope. Any descriptor files found in the entire workspace
that have this scope will not only be included in the SDE, they will take precedence over any of the lesser scopes.
"tablet_family" and "silicon_reference" scopes will also be used, in that order. Additionally, all projects inherit the
"global" scope, but it takes the lowest precedence.

### Setting Up for Platform Builds

Since the SDE knows how to fetch its own dependencies, and since all these dependencies are described by the code tree
itself, stuart can now perform the minimal steps to enable building any given platform, including:

- Synchronizing all required submodules.
- Downloading all source (and only the source actually used by the platform).
- Configuring all paths.
- Downloading all binaries.

NOTE:

- `stuart_setup` should only be required once per build machine, per platform being built. It is not necessary to run
   it regularly. Only when setting up a new personal workstation or starting to work with a platform that you haven't
   used yet.
- The `stuart_setup` feature does not actually build the platform.
- The `stuart_setup` feature will NOT change branches in any submodule that already exists locally, or that has local
  changes. This is to prevent accidental loss of work. If you would like the script to try making changes even in
  these cases, use the "--FORCE" argument.
- The `stuart_setup` feature does not yet install dev singing certs. Those steps must still be performed manually.

### Updating

Prior to any build, the SDE will attempt to validate the external dependencies that currently exist on the local
machine against the versions that are specified in the code. If the code is updated (perhaps by a pull request to
the branch you're working on), it is possible that the dependencies will have to be refreshed. If this is the case,
you will see a message prompting you to do so when you run `stuart_build` to build your platform. To perform this
update, simply run the `stuart_update`. Any dependencies that match their current versions will be skipped and only
out-of-date dependencies will be refreshed.

### Setting Up for CI Build

Stuart CI Build works on a similar mechanism to `stuart_build` and expects to be have things setup and updated.
Git Modules are monitored and handled via the repo_resolver framework, which has more logic to it, and doesn't
handle submodules. `stuart_ci_setup` handles python defined git modules to clone into the code tree.

### Building

Building can be done with `stuart_build` or `stuart_ci_build`.
Note that the current state of the SDE is always printed in the DEBUG level of the build log.
