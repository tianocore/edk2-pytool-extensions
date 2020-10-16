# Using Tianocore Edk2 Pytool Extensions (edk2toolext)

## Installing

Have [Python3](https://www.python.org/downloads/) installed on your system.
NOTE: It is suggested to use python virtual environments to avoid dependency
pollution and conflicts. [Read
More](https://docs.python.org/3/library/venv.html) Install from pip

```cmd
pip install --upgrade edk2-pytool-extensions
```

## Why am I here

I assume you are here because you have an EDK2 implementation and you aren't
sure what to do with it. There are three categories of things you can do with
these utilities.

### 1) I want to build a platform

You have an EDK2 implementation, a platform DSC, and a platform FDF? Great! You
are one settings file away from a great platform building experience.

If you use submodules, you will find stuart_setup helpful for submodule sync and
update.

stuart_update walks through the environment and downloads all the tools that the
environment says it needs.

To build the platform and assemble a ROM according to your FDF, invoke
stuart_build. Your UefiBuilder instance will provide the opportunity to tweak or
override at every step of the process.

### 2) I want to manage a codebase

The idea here is that you have code and you have a to-do list of tasks to do.
Maybe you want to make sure all the drivers compile, maybe you want to check all
the images in your file tree and make sure they are encoded correctly.

These use cases will fit into our 'CI' tools category.

stuart_ci_setup can be called to clone whatever code repositories would be
required for this operation. stuart_update can be called to download all the
tools the environment says it needs. From there, stuart_ci_build takes a list of
packages to look at and runs all plugins on each package.

### 3) I want to do something new

You want to do something new that has never been done before? You want to tailor
the process specifically to your use case? You need something to do on the
weekend?

Great! We have built out invocables to be as robust and extensible as possible.
We have base_abstract_invocable, which asks for the bare minimum required for
environment initialization in the form of abstract functions that you can fill
out. We have also built edk2_invocable, on top of base_abstract_invocable, which
handles getting setup and providing settings in a manner we hope will work well
for most everyone.

## What does this mean

Here's a little vocab list to make sure you understand the different components
of Stuart.

### Scopes

The idea with scopes is that, to allow many different workflows to take place in
the same tree, individual components should have some identifier saying which
workflow they are a part of. Each component can have only one scope. A workflow
will generally designate a certain combination of multiple scopes to be the
**ActiveScopes**.

### ext_dep

Short for external dependency, ext_deps are a great way to manage tools and
resources for a codebase. You provide a `_ext_dep.json` file that indicates the
source, type (git, web download, or NuGet), and version of something. Then, when
you call stuart_update, Stuart will collect the ext_deps that pertain to your
scope. These files will be downloaded with stuart_update and store in a folder
called `{name}_ext_dep/`. Futhermore, when using the invocable interface, you
can opt in to a setup step that will verify that the correct version of
everything has been downloaded and is present in the tree.

[extdep documentation](features/feature_extdep.md)

### plugin

Plugins are code files that can be executed according to their scope. There are
four different interfaces you could choose to implement:

1) UefiBuildPlugin - Used for platform builds, this interface has two hooks:
   pre-build and post-build. 2) CiBuildPlugin - Our CI process is to run all
   CiBuildPlugins for each package. Each plugin is essentially a test that will
   be executed on the given code tree. 3) UefiHelperPlugin - Registers one or
   more functions that can called by any part of the build system.

### CI

Continuous integration: Constantly interrogating your code base to make sure it
still passes muster. These tests can be performed as a part of your checkin
validation process to make sure your code tree stays in tip top shape!

### environment

Stuart uses a self describing environment to read and understand workspaces. We
use environment to mean the collection of path, pypath, build vars, and plugins
as they need to be configured to run a build successfully.

[SDE documentation](features/feature_sde.md)

### invocable

Invocables are a new type of script built just for EDK2! We know that the
environment needs to be available before your script can be invoked, so we
handle setting up the environment for you and then invoke your script. During
runtime, your script will have the full EDK2 environment setup and accessible.

The base class, Base Abstract Invocable, provides the API to directly provide
all the information needed for the EDK2 Environment.

EDK2 Invocable is a subclass of Base Abstract Invocable that handles most of the
argument parsing and settings management for the user.

[invocables documentation](features/feature_invocables.md)

### settings manager

Stuart's invocables are very smart but they don't know everything. The paradigm
we've come up with is to have each invocable provide an abstract Settings
Manager class with a 'get' function for each piece of information required
invocation. Invoking an edk2 invocable requires that an instance of this class
be passed in. This way, the invocable script gets all the information it needs
without needing to carry the overhead of command line parsing and loading the
class.

[settings manager documentation](features/feature_settings_manager.md)

### stuart

We found ourselves referring to our build system as 'the environment' because it
is just a complex series of system states.... But it's more fun to imagine that
your code is being managed by a helpful pet. Stuart is a mouse that lives inside
your computer. He will take care of your code for you.

## What can I ask Stuart to do

I'm glad you asked! Stuart has a variety of invocable tasks that he hopes will
be helpful for a wide variety workflows.

### stuart_setup

Sets up git repo based on the gitsubmodule file in your repo. It checks to make
sure the required repos as provided by settings manager are present.

### stuart_update

Reads ext_dep files in environment and downloads the appropriate files for the
active scopes currently defined. These scopes come from the settings manager.

### stuart_build

Builds a platform. Requires an instance of UefiBuilder to be provided in
addition to the settings manager.

### stuart_ci_setup

Intended for CI environment setup. Given a list of required repos from the
settings manager, clone each of them in the workspace.

### stuart_ci_build

Given a list of packages, runs all plugins (for active scope) on each package.
This includes compiler plugin, which builds each package for the required
targets. Stuart will checkpoint the original environment and restore that
checkpoint between each test.

## Living with Stuart

### .gitignore

We have a couple .gitignore items that are important for keeping git from
getting it's hands on Stuart!

```.gitignore
*.pyc
*_LOG.*
*_extdep/
```
