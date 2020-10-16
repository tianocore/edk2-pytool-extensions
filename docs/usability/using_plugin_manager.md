# Plugin Manager

## The Genesis

Plugins are similar to external dependencies, in that they are defined by a Json
file and they are discovered by the SDE. If you wish to learn more about the
SDE, please go read the document about the self describing environment. They are
defined by the EnvironmentDescriptorFiles which also describe external
dependencies and path descriptors.

## Types of plugins

Types of plugins are defined by the class they inherit from

- UefiBuildPlugin

  - Contains two methods, Pre and Post Build. These methods are called on Pre
    and Post Build steps in UefiBuild (not CiBuild). There is no guarantee on
    ordering between different plugins (Pre will always come before Post). Post
    is will not run if there is a critical error in the build process.
  - The idea here is to allow for custom, self-contained build functionality to
    be added without required UEFI build changes or inline code modifications.

- DscProcessorPlugin (in-progress)

  - This is a plugin type that can apply transformations to the active DSC that
    will then be used to build the system.
  - This is not production ready and _not enabled in_ any builds currently.

- UefiHelperPlugin

  - This is a helper plugin that publishes a function that can be used by other
    parts of the system. An example of this would be the Capsule signing system.
  - This really is less about plugin design and more about keeping the UEFI
    build and platform builder python files minimal and getting the desired code
    reuse.

- CiBuildPlugin

  - A plugin that runs during the main stage of CiBuild. The build step is
    actually a plugin so as ordering is not guaranteed so you don't have any
    assurance that the build is successful or that the build has started

## How it works

You might be asking yourself how does the sausage get made. In the name of
sating curiosity, here it is. The SDE discovers the plugin .json environment
descriptors in the file system tree. Once they're discovered, they're passed to
the Plugin Manager which loads each of them and puts them into the appropriate
structure. Once they're in there, they are requested by UefiBuild or CiBuild and
dispatched. Helper functions are requested from the plugin_manager and then
executed.

## Writing your own

Writing your own plugin is fairly simple. See MuEnvironment\plugin_manager.py
for the interface definition and required functions for each type of plugin.

For IUefiBuildPlugin type the plugin will simply be called during the pre and
post build steps after the platform builder object runs its step. The
UefiBuilder object will be passed during the call and therefore the environment
dictionary is available within the plugin. These plugins should be authored to
be independent and the platform build or UEFI build should not have any
dependency on the plugin. The plugin can depend on variables within the
environment dictionary but should be otherwise independent / isolated code.

For IUefiHelperPlugin type the plugin will simply register functions with the
helper object so that other parts of the platform build can use the functions.
It is acceptable for platform build to know/need the helper functions but it is
not acceptable for UEFI build super class to depend upon it. I expect most of
these plugins will be at a layer lower than the UDK as this is really to isolate
business unit logic while still allowing code reuse. Look at the HelperFunctions
object to see how a plugin registers its functions.

For ICiBuildPlugin type the plugin will be allowed to verify it's configuration
and be called by the CiBuild system. It will have the current state of the build
and access to the environment. CiBuild checkpoints the environment prior to
calling out to each plugin, so the environment can be dirtied by the plugin.

As an example of a Ci Build Plugin, we will look at one of the plugins we use,
Character Encoding Check CiBuildPlugin. This runs as part of the CI build.

### The schema

From EDK2/.pytool/Plugin/CharEncodingCheck
<https://github.com/tianocore/edk2/blob/master/.pytool/Plugin/CharEncodingCheck/CharEncodingCheck_plug_in.yaml>

```yaml
{
    "scope": "cibuild",
    "name": "Char Encoding Check Test",
    "module": "CharEncodingCheck"
  }
```

- Scope: See the SDE doc about scopes
- Name: This is the name of the plugin and will be part of the path where the
  nuget is unpacked
- Module: the python file to load

### The Python

File is from: ci\plugin\CharEncodingCheck\CharEncodingCheck.py

It's important that the filename matches the Module name in the yaml file.

```python
import os
import logging
from edk2toolext.plugins.CiBuildPlugin import ICiBuildPlugin


class CharEncodingCheck(ICiBuildPlugin):
   def GetTestName(self, packagename, environment):
      return ("CiBuild CharEncodingCheck " + packagename, "CiBuild.CharEncodingCheck." + packagename)

    #   - package is the edk2 path to package.  This means workspace/package path relative.
    #   - edk2path object configured with workspace and packages path
    #   - any additional command line args
    #   - RepositoryConfig Object (dict) for the build
    #   - PkgConfig Object (dict) for the pkg
    #   - EnvConfig Object
    #   - Plugin Manager Instance
    #   - Plugin Helper Obj Instance
    #   - test-case Object used for tracking test results
    #   - output_stream the StringIO output stream from this plugin

    def RunBuildPlugin(self, packagename, Edk2pathObj, args, repoconfig, pkgconfig, environment, PLM, PLMHelper, tc, output_stream = None):
      overall_status = 0
      files_tested = 0
      if overall_status is not 0:
          tc.SetFailed("CharEncoding {0} Failed.  Errors {1}".format(packagename, overall_status), "CHAR_ENCODING_CHECK_FAILED")
        else:
          tc.SetSuccess()
        return overall_status
```

Some things to notice are the class that this is inheriting from:
ICiBuildPlugin.

There is also this idea of the tc, which is the test unit class. You can set
this particular CiBuild step as failed, skipped, or successful. Logging standard
out or error out gets placed in the JUnit report that is later picked up by the
CI system.

## Using a plugin

Using plugins is straightforward but it exact usage depends on what type of
plugin you use. For the IUefiBuildPlugin (pre/post build) and ICiBuildPlugin
type there is nothing the UEFI build must do besides make sure the plugin is in
your workspace and scoped to an active scope. For Helper plugins basically the
UEFI builder Helper member will contain the registered functions as methods on
the object. Therefore calling any function is as simple as using
self.Helper.[your func name here]. It is by design that the parameters and
calling contract are not defined. It is expected that the caller and plugin know
about each other and are really just using the plugin system to make inclusion
and code sharing easy.

## Skipping a plugin

If you want to **skip** a plugin, set it in the environment before the
environment is initialized. For example, it can be a part of your
SettingsManager:

```python
class Settings(CiBuildSettingsManager, CiSetupSettingsManager, UpdateSettingsManager):

    def __init__(self):
        plugin_skip_list = ["DependencyCheck", "CompilerPlugin"]
        env = shell_environment.GetBuildVars()
        for plugin in plugin_skip_list:
            # KEY: Plugin name in all caps
            # VALUE: "skip"
            env.SetValue(plugin.upper(), "skip", "set from settings file")
```
