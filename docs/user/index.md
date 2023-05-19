# Our Philosophy

Edk2 Pytool Extensions (edk2toolext) is a Tianocore maintained project
consisting of command line and other python tools and extensions to simplify
and automate the process of building and maintaining an Edk2 based UEFI
Firmware code tree.

!!! note
    If stuart is already integrated into your platform and you're looking for a
    tutorial on how to install and use stuart, please see
    [Installation](/using/install), [Building](/using/build), and
    [Core CI](/using/ci) Instructions.

As UEFI developers, we found the process of building firmware to be extremely
rigid and hard to customize without the use of disjointed scripts that would
only work under extremely specific circumstances. Due to this, we sought to
develop a build system to manage our environment and it's dependencies in a
easily configurable, yet extremely reliable and fashion - even across operating
systems.

As we developed this system, we found ourselves referring to it as
'the environment' because it is just a complex series of system states... But
it's more fun to imagine that your code and enviornment is being managed by a
helpful pet. This is how Stuart came to be; he is a mouse that lives inside
your computer. He takes care of your code and even manages your environment for
you. Executing commands such as building a platform is as simple as asking
Stuart to do it for you. You can ask him to do many things... see some of them
[here!](#what-can-i-ask-stuart-to-do).

## What does Stuart Manage for us

Stuart is responsible for many things, so lets take a look at them, and see how
you can use it to simplify your building experience!

### The Environment

Stuart uses a self describing environment to read and understand workspaces.
The Environment is a collection of path, pypath, build vars, and plugin
configurations needed for a build to execute successfully.

### Settings Manager

Stuart's invocables are very smart but they don't know everything. The paradigm
we've come up with is to have each invocable provide an abstract Settings
Manager class with a 'get' function for each piece of information required
invocation. Invoking an edk2 invocable requires that an instance of this class
be passed in. This way, the invocable script gets all the information it needs
without needing to carry the overhead of command line parsing and loading the
class.

[Settings Manager documentation](features/settings_manager)

### Scopes

Stuart allows many different workflows in the same tree, but needs a way to
organize the environment in a way that identifies which component are used by
which workflows. Stuart manages this via scopes! Each component can have only
one scope, and a workflow designates a combination of scopes, known as
**ActiveScopes** to specify which components to use in a workflow.

### Plugins

Stuart manages many plugins that are executed in specific workflows according
to their scope. There are three different types of plugins that exist and can
be implemented.

1. `UefiBuildPlugin` - Used for platform builds, this interface has two hooks: pre-build and post-build.
2. `CiBuildPlugin` - Our CI process is to run all
   CiBuildPlugins for each package. Each plugin is essentially a test that will
   be executed on the given code tree.
3. `UefiHelperPlugin` - Registers one or
   more functions that can called by any part of the build system.

[Plugin Manager Documentation](features/plugin_manager)

### External Dependencies

External dependencies (ext_deps) are a great way to manage tools and resources
for a codebase. You provide a `_ext_dep.json` file that indicates the source,
type (git, web download, NuGet, etc.), scope, and version. Stuart will manage
the rest! When you call stuart_update, Stuart will collect, download, and store
the ext_deps pertaining to your scope. Stuart will make sure these ext_deps are
available to the rest of the environment.

[External Dependency Documentation](features/extdep)

### Environment Variables

Different then your operating system environment variables, Stuart will also
manage variables defined across your FDF, DSC, DEC, ext_deps, build scripts
and ensures a variable defined in one is available to all others. This means
if a variable is set in the build script, it can then be used in your FDF, DSC,
etc (and vise versa).

[Environment Variable Documentation](features/environment_variables)

## What can I ask Stuart to do

I'm glad you asked! Stuart has a variety of invocable tasks that he hopes will
be helpful for a wide variety workflows.

### stuart_init

Initializes the repo based on the configuration file. Can initialize submodules or
other repositories using `get_required_submodules()` or `get_required_repositories()`.

### stuart_update

Reads ext_dep files in the environment and downloads the appropriate files for the
active scopes currently defined. These scopes come from the settings manager.

### stuart_build

Builds a platform. Requires an instance of `UefiBuilder` to be provided in
addition to the settings manager.

### stuart_ci_build

Given a list of packages, runs all plugins (for active scope) on each package.
This includes compiler plugin, which builds each package for the required
targets. Stuart will checkpoint the original environment and restore that
checkpoint between each test.

## Living with Stuart

### .gitignore

We have a couple `.gitignore` items that are important for keeping git from
getting its hands on Stuart!

```.gitignore
*.pyc
*_LOG.*
*_extdep/
```
