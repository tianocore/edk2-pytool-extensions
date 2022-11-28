# Creating An Invocable

Whether you spell it invocable or invocable, the idea of an Invocable is central to Stuart.
If you're unfamiliar with what it is, refer to the "Using" document in the root docs folder or feature_invocable in the
features folder.
In a nutshell, an invocable is a small python script that gets the build environment setup for it.
It gets a settings file (that the invocable defines the interface for) that provides information about what we are
being invoked on.

This guide references Project Mu, which is an open source fork of EDK2 that leverages edk2-pytools.

This guide is written in the style of a tutorial. This is based on the real example of an invocable
[here](https://github.com/microsoft/mu_basecore).

## The problem statement

One feature that Project Mu offers is that of a binary-packaged Crypto and Networking, known as SharedCrypto and
SharedNetworking respectively.
This allows your platform to skip the expensive step of compiling OpenSSL or other crypto libraries and instead use a
known-good crypto library that is built from a known good source.
For more information on SharedNetworking and SharedCrypto, go check it out
[here](https://microsoft.github.io/mu/dyn/mu_plus/SharedCryptoPkg/feature_sharedcrypto/) and
[here](https://microsoft.github.io/mu/dyn/mu_basecore/NetworkPkg/SharedNetworking/SharedNetworking/).

Now, how are Shared Binaries built?
Check out the code on [github](https://github.com/microsoft/mu_basecore) under
NetworkPkg/SharedNetworking/DriverBuilder.py (it may move, this is where it was at time of writing), which is the
invocable that powers the shared binaries.

SharedNetworking in particular is a tricky problem because we want to build every architecture into an FV and package
it into a NugetFeed.

In a nutshell here's the flow we want:

 1. Acquire the dependencies we need (Crypto, OpenSSL, etc)
 2. Pull in any tooling that we require (mu_tools, nasm)
 3. Configure the environment for building with our tool chain
 4. Go through all the architectures we want to support and build them individually
 5. If all previous steps were successful, package it into a nuget package
 6. If given an API key, then publish to nuget

Now a typical approach to this might be scripting through a batch script to invoke build.py, or invoking a stuart_build.
This is a fine approach, particularly for a one off solution.
But what if we change how nuget publishing is done?
We need to update the batch script for both Crypto and Networking.
Or perhaps we've thought of that and made a common script that our handy batch script invokes with the right parameters.
We hope you can see that as time goes on, the situation spirals out of control as more parameters and scripts are
added, fewer people will know how to work this or want to touch it.
Eventually a bright talented engineer with a little more time than experience will declare that they will attempt to
refactor this process.

In a nutshell that is the problem that the invocable framework in general is trying to solve.
Steps 1-3 are done for you. Steps 4-6+ should be trivial to implement in a setting agnostic way.

So let's start.

## The settings class

Each invocable has a definition for a settings class.
We would recommend looking through
[a few of the invocables](https://github.com/tianocore/edk2-pytool-extensions/tree/master/edk2toolext/invocables)
inside of Stuart as a reference.
You may choose to subclass another settings file, such as MultiPkgAwareSettingsInterface but in this case, we won't.

So let's start with some imports that we'll need along the way.
We'll create a new file called DriverBuilder.py

``` python
import os
import logging
from edk2toolext.environment import plugin_manager
from edk2toolext.environment.plugintypes.uefi_helper_plugin import HelperFunctions
from edk2toolext.edk2_invocable import Edk2Invocable
from edk2toolext.environment import self_describing_environment
from edk2toolext.environment import shell_environment
from edk2toolext.environment.uefi_build import UefiBuilder
from edk2toolext import edk2_logging
```

One final import is needed that will seem a little strange.

```python
import DriverBuilder
```

Stuart expects your invocable to be running in the python namespace that it is defined in.
If you run your builder directly from the command-line, it will be running in \_\_main__, which can cause problems.

**In a nutshell, you'll need to import the name of your file.**

We'll see where this is used at the end.

Now the settings class!

```python
class BinaryBuildSettingsManager():
    ''' Platform settings will be accessed through this implementation. '''

    def GetActiveScopes(self):
        ''' return tuple containing scopes that should be active for this process '''
        raise NotImplementedError()

    def GetWorkspaceRoot(self):
        ''' get WorkspacePath '''
        raise NotImplementedError()

     def GetName(self):
        ''' Get the name of the repo, platform, or product being build by CI '''
        raise NotImplementedError()

    def AddCommandLineOptions(self, parserObj):
        ''' Implement in subclass to add command line options to the argparser '''
        pass

    def RetrieveCommandLineOptions(self, args):
        '''  Implement in subclass to retrieve command line options from the argparser '''
        pass

    def GetPackagesPath(self):
        ''' Return a list of workspace relative paths that should be mapped as edk2 PackagesPath '''
        return ""

```

We've implemented a few methods that are needed to get the SDE off the ground.

- _GetActiveScopes_ is needed to init the SDE. This causes different plugins to load or not
- _GetWorkspaceRoot_ gets the folder that is the root of your workspace
- _GetPackagePaths_ gets the folder locations that you will resolve EDK2 paths against
- _GetName_ is the thing we are building, it will be used to name certain files like logs
- _AddCommandLineOptions_ gives our settings the chance to set items in the parser object
- _RetrieveCommandLineOptions_ gives us the chance to read the arguments from the command-line

Now that we have our base methods, let's add one more to control the configurations we are going to build.

```python

class BinaryBuildSettingsManager():
    ''' Platform settings will be accessed through this implementation. '''

    ....

    def GetConfigurations(self):
        '''
        Gets the next configuration of this run
        This is a generator pattern - use yield
        '''
        raise NotImplementedError()
```

- _GetConfigurations_ is our way to get the configurations we want to build. We'll use a generator/iterator pattern
here that we'll see later.

We also need some methods to have callbacks into various stages of the process so that we can do nuget commands and
prepare the nuget package.

```python

class BinaryBuildSettingsManager():
    ''' Platform settings will be accessed through this implementation. '''

    ....

     def PreFirstBuildHook(self):
        ''' Called before the first build '''
        return 0

    def PostFinalBuildHook(self, ret):
        ''' Called after the final build with the summed return code '''
        return 0

    def PostBuildHook(self, ret):
        ''' Called after each build with the return code '''
        return 0

    def PreBuildHook(self):
        ''' Called before each build '''
        return 0
```

These hooks are pretty self evident, but they'll be called at various point in the process.
Now with our current file, we can define a settings file that implements the settings class.
That doesn't really net us much.

## The invocable

The invocable is actually the simplest part of this

```python
class Edk2BinaryBuild(Edk2Invocable):
    def GetLoggingLevel(self, loggerType):
        ''' Get the logging level for a given type
        base == lowest logging level supported
        con  == Screen logging
        txt  == plain text file logging
        md   == markdown file logging
        '''
        if(loggerType == "con") and not self.Verbose:
            return logging.WARNING
        return logging.DEBUG

    def AddCommandLineOptions(self, parser):
        pass

    def RetrieveCommandLineOptions(self, args):
        '''  Retrieve command line options from the argparser '''
        pass

    def GetSettingsClass(self):
        return BinaryBuildSettingsManager

    def GetLoggingFileName(self, loggerType):
        return "BINARY_BUILDLOG"

    def Go(self):
        return 0
```

- _GetLoggingLevel_ we can get the logging level that we care about for the type of log we are creating
- _AddCommandLineOption_ similar to previous settings manager class
- _RetrieveCommandLineOptions_ similar to above
- _GetSettingsClass_ the class that we want to look for
- _GetLoggingFileName_ the name of the file we want to create for txt and markdown files.
- _Go_ is the business logic of the invocable.

Now let's implement an actual method to handle main and being called from the command-line or a pip link.

```python
def main():
    Edk2BinaryBuild().Invoke()


if __name__ == "__main__":
    DriverBuilder.main()  # otherwise we're in __main__ context
```

As you can see, we call ourselves via import rather than just directly calling main.
This is a quirk/design flaw that might be revisited in the future, but in the meantime, this is a workaround.

Now that we have a way to invoke this and execute our go, we can call if from the command-line.

If we were to run this right now, we would see this as output (assuming you created an empty settings class).

```console
SECTION - Init SDE
SECTION - Loading Plugins
SECTION - Start Invocable Tool
SECTION - Summary
PROGRESS - Success
```

We can see that we're initializing the SDE, loading plugins and helpers, and starting the invocable. All for virtually free!

Now let's start implementing the meat of the invocation.

```python
class Edk2BinaryBuild(Edk2Invocable):

  ...

    def Go(self):
        ret = 0
        env = shell_environment.GetBuildVars()
        # set our environment with specific variables that we care about that EDK2 needs
        env.SetValue("PRODUCT_NAME",
                     self.PlatformSettings.GetName(), "Platform Hard-coded")
        env.SetValue("BLD_*_BUILDID_STRING", "201905", "Current Version")
        env.SetValue("BUILDREPORTING", "TRUE", "Platform Hard-coded")
        # make sure we always do a build report
        env.SetValue("BUILDREPORT_TYPES",
                     'PCD DEPEX LIBRARY BUILD_FLAGS', "Platform Hard-coded")

        # Run pre build hook
        ret = self.PlatformSettings.PreFirstBuildHook()
        # get workspace and package paths for
        ws = self.GetWorkspaceRoot()
        pp = self.PlatformSettings.GetPackagesPath()
        # run each configuration
        for config in self.PlatformSettings.GetConfigurations():
            ret = self.PlatformSettings.PreBuildHook()  # run pre build hook
            if ret != 0:
                raise RuntimeError("Failed prebuild hook")
            edk2_logging.log_progress(f"--Running next configuration--")
            logging.info(config)  # log our configuration out to the log
            shell_environment.CheckpointBuildVars()  # checkpoint our config
            env = shell_environment.GetBuildVars() #  get our checkpointed variables
            # go through the item in the current configuration and apply to environment
            for key in config:
                env.SetValue(key, config[key], "provided by configuration")
            # make sure to set this after in case the config did
            env.SetValue("TOOL_CHAIN_TAG", "VS2017",
                         "provided by driver_builder")
            platformBuilder = UefiBuilder()  # create our builder
            # run our builder and add to ret
            ret = platformBuilder.Go(ws, os.pathsep.join(pp), self.helper, self.plugin_manager)
            # call our post build hook
            ret = self.PlatformSettings.PostBuildHook(ret)
            # if we have a non zero return code, throw an error and call our final build hook
            if ret != 0:
              self.PlatformSettings.PostFinalBuildHook(ret)  # make sure to call our post final hook
              return ret
            shell_environment.RevertBuildVars()  # revert our shell environment back to what it was
        # make sure to do our final build hook
        self.PlatformSettings.PostFinalBuildHook(ret)

        return ret
```

The comments in the code are there to help you understand it.
The basic process is:

1. Setup the environment with your product strings and configuration for EDK2
2. Call prebuild hook
3. Go through each of our configuration
4. Checkpoint the environment
5. Call prebuild hook
6. Call UefiBuild
7. Call PostBuild
8. Revert checkpoint of environment

## Settings File

Now here's the settings file for the invocable.
In this example, you would have two settings file for SharedNetworking and SharedCrypto, but the one invocable.
Here's what we will be importing:

```python
import os
import logging
from edk2toolext.invocables.edk2_ci_setup import CiSetupSettingsManager
from edk2toolext.invocables.edk2_update import UpdateSettingsManager
try:
    from DriverBuilder import BinaryBuildSettingsManager
except Exception:
    class BinaryBuildSettingsManager:
        def __init__():
            raise RuntimeError("You shouldn't be including this")
    pass
from edk2toollib.utility_functions import GetHostInfo
```

One of the key features of settings class is that it can implement multiple settings managers, or you can have multiple
classes in the file that implement that particular SettingsManager class.
The invocable finds the first class in the file that implements that particular settings class that we care about.
Now that we have our imports, we will create a SettingsManager class that implements CiSetupSettingsManager,
UpdateSettingsManager, and BinaryBuildSettingsManager.

```python
#
# ==========================================================================
# PLATFORM BUILD ENVIRONMENT CONFIGURATION
#

class SettingsManager(UpdateSettingsManager, CiSetupSettingsManager, BinaryBuildSettingsManager):
    def __init__(self):
        SCRIPT_PATH = os.path.dirname(os.path.abspath(__file__))

        WORKSPACE_PATH = os.path.dirname(os.path.dirname(SCRIPT_PATH))

        self.OUTPUT_DIR = os.path.join(WORKSPACE_PATH, "Build", ".NugetOutput")
        self.ws = WORKSPACE_PATH
        pass

    def GetActiveScopes(self):
        ''' return tuple containing scopes that should be active for this process '''
        scopes = ("corebuild", "sharednetworking_build", )
        return scopes

```

We have implemented GetActiveScopes and the init function. Let's implement the hooks.

```python
class SettingsManager(UpdateSettingsManager, CiSetupSettingsManager, BinaryBuildSettingsManager):

    ...

    def PreFirstBuildHook(self):
        output_dir = self.OUTPUT_DIR
        try:
            if os.path.exists(output_dir):
                logging.warning(f"Deleting {output_dir}")
                shutil.rmtree(output_dir, ignore_errors=True)
            os.makedirs(output_dir)
        except:
            pass

        self.nuget_version = self._GetNextVersion(self.nuget_version)
        return 0

    def PostBuildHook(self, ret):
        if ret == 0:
            ret = self._CollectNuget()
        if ret != 0:
            logging.error("Error occurred in post build hook")
        return ret

    def PostFinalBuildHook(self, ret):
        if ret != 0:
            logging.error(
                "There was failure along the way aborting NUGET publish")
            return
        self._PublishNuget()
```

Some of the functions such as _CollectNuget have been redacted for brevity.
On PostBuild we collect the files into the nuget package.
On PreBuild we figure out the next version of our nuget package and delete what we've previously collected.
On the final build, we publish the nuget file.

Now we will implement a few more pieces needed

```python
class SettingsManager(UpdateSettingsManager, CiSetupSettingsManager, BinaryBuildSettingsManager):

    ...

     def GetConfigurations(self):
        TARGETS = self.GetTargetsSupported()
        ARCHS = self.GetArchitecturesSupported()
        # combine options together
        for target in TARGETS:
            for arch in ARCHS:
                self.target = target
                self.arch = arch
                yield({"TARGET": target, "TARGET_ARCH": arch, "ACTIVE_PLATFORM": "NetworkPkg/SharedNetworking/SharedNetworkPkg.dsc"})
```

We use a generator to yield the settings we want each configuration to be.
We iterate through these in the invocable and apply them to the environment.
Since you own the invocable, you can modify this as you see fit, which makes this very modular.

Let's add in functions for the other SettingsManagers.

```python
class SettingsManager(UpdateSettingsManager, CiSetupSettingsManager, BinaryBuildSettingsManager):

    ...

    def GetWorkspaceRoot(self):
        ''' get WorkspacePath '''
        return self.ws

    def GetPackagesPath(self):
    ''' Return a list of workspace relative paths that should be mapped as edk2 PackagesPath '''
        return self.pp

    def GetRequiredSubmodules(self):
        ''' return iterable containing RequiredSubmodule objects.
        If no RequiredSubmodules return an empty iterable
        '''
        return self.rr

    def GetName(self):
        return "SharedNetworking"

    def GetPackagesSupported(self):
        return "NetworkPkg"

    def GetArchitecturesSupported(self):
        return ["IA32", "AARCH64", "X64"]

    def GetTargetsSupported(self):
        return ["DEBUG", "RELEASE"]

    def GetDependencies(self):
        return []

```

The methods implemented here are a mix of our own settings class and other invocables such as stuart_update or
stuart_setup. Hopefully they're straightforward and easy to follow.

## Conclusion

That brings us to the end of the tutorial, you should have a working invocable and a settings file (well with
some methods missing). Here they are for easy copy and pasting:

### DriverBuilder.py

```python
# @file Edk2BinaryBuild.py
# This module contains code that supports building of binary files
# This is the main entry for the build and test process of binary builds
##
# Copyright (c) Microsoft Corporation
#
# SPDX-License-Identifier: BSD-2-Clause-Patent
##
import os
import logging
from edk2toolext.environment import plugin_manager
from edk2toolext.environment.plugintypes.uefi_helper_plugin import HelperFunctions
from edk2toolext.edk2_invocable import Edk2Invocable
from edk2toolext.environment import self_describing_environment
from edk2toolext.environment import shell_environment
from edk2toolext.environment.uefi_build import UefiBuilder
from edk2toolext import edk2_logging
import DriverBuilder  # this is a little weird


class BinaryBuildSettingsManager():
    ''' Platform settings will be accessed through this implementation. '''

    def GetActiveScopes(self):
        ''' return tuple containing scopes that should be active for this process '''
        raise NotImplementedError()

    def GetWorkspaceRoot(self):
        ''' get WorkspacePath '''
        raise NotImplementedError()

    def GetPackagesPath(self):
        pass

    def GetConfigurations(self):
        '''
        Gets the next configuration of this run
        This is a generator pattern - use yield
        '''
        raise NotImplementedError()

    def PreFirstBuildHook(self):
        ''' Called before the first build '''
        return 0

    def PostFinalBuildHook(self, ret):
        ''' Called after the final build with the summed return code '''
        return 0

    def PostBuildHook(self, ret):
        ''' Called after each build with the return code '''
        return 0

    def PreBuildHook(self):
        ''' Called before each build '''
        return 0

    def GetName(self):
        ''' Get the name of the repo, platform, or product being build by CI '''
        raise NotImplementedError()

    def AddCommandLineOptions(self, parserObj):
        ''' Implement in subclass to add command line options to the argparser '''
        pass

    def RetrieveCommandLineOptions(self, args):
        '''  Implement in subclass to retrieve command line options from the argparser '''
        pass


class Edk2BinaryBuild(Edk2Invocable):
    def GetLoggingLevel(self, loggerType):
        ''' Get the logging level for a given type
        base == lowest logging level supported
        con  == Screen logging
        txt  == plain text file logging
        md   == markdown file logging
        '''
        if(loggerType == "con") and not self.Verbose:
            return logging.WARNING
        return logging.DEBUG

    def AddCommandLineOptions(self, parser):
        pass

    def RetrieveCommandLineOptions(self, args):
        '''  Retrieve command line options from the argparser '''
        pass

    def GetSettingsClass(self):
        return BinaryBuildSettingsManager

    def GetLoggingFileName(self, loggerType):
        return "BINARY_BUILDLOG"

    def Go(self):
        ret = 0
        env = shell_environment.GetBuildVars()
        # set our environment with specific variables that we care about that EDK2 needs
        env.SetValue("PRODUCT_NAME",
                     self.PlatformSettings.GetName(), "Platform Hardcoded")
        env.SetValue("BLD_*_BUILDID_STRING", "201905", "Current Version")
        env.SetValue("BUILDREPORTING", "TRUE", "Platform Hardcoded")
        # make sure we always do a build report
        env.SetValue("BUILDREPORT_TYPES",
                     'PCD DEPEX LIBRARY BUILD_FLAGS', "Platform Hardcoded")

        # Run pre build hook
        ret = self.PlatformSettings.PreFirstBuildHook()
        # get workspace and package paths for
        ws = self.GetWorkspaceRoot()
        pp = self.PlatformSettings.GetPackagesPath()
        # run each configuration
        for config in self.PlatformSettings.GetConfigurations():
            ret = self.PlatformSettings.PreBuildHook()  # run pre build hook
            if ret != 0:
                raise RuntimeError("Failed prebuild hook")
            edk2_logging.log_progress(f"--Running next configuration--")
            logging.info(config)  # log our configuration out to the log
            shell_environment.CheckpointBuildVars()  # checkpoint our config
            env = shell_environment.GetBuildVars() #  get our checkpointed variables
            # go through the item in the current configuration and apply to environment
            for key in config:
                env.SetValue(key, config[key], "provided by configuration")
            # make sure to set this after in case the config did
            env.SetValue("TOOL_CHAIN_TAG", "VS2017",
                         "provided by driver_builder")
            platformBuilder = UefiBuilder()  # create our builder
            # run our builder and add to ret
            ret = platformBuilder.Go(ws, os.pathsep.join(pp), self.helper, self.plugin_manager)
            # call our post build hook
            ret = self.PlatformSettings.PostBuildHook(ret)
            # if we have a non zero return code, throw an error and call our final build hook
            if ret != 0:
              self.PlatformSettings.PostFinalBuildHook(ret)  # make sure to call our post final hook
              return ret
            shell_environment.RevertBuildVars()  # revert our shell environment back to what it was
        # make sure to do our final build hook
        self.PlatformSettings.PostFinalBuildHook(ret)

        return ret


def main():
    Edk2BinaryBuild().Invoke()


if __name__ == "__main__":
    DriverBuilder.main()  # otherwise we're in __main__ context
```

### SharedNetworkingSettings

```python
##
# Script to Build Shared Crypto Driver
# Copyright Microsoft Corporation, 2019
#
# This is to build the SharedNetworking binaries for NuGet publishing
##
import os
import logging
from edk2toolext.environment.uefi_build import UefiBuilder
from edk2toolext.invocables.edk2_ci_setup import CiSetupSettingsManager
from edk2toolext.invocables.edk2_update import UpdateSettingsManager
try:
    from DriverBuilder_temp import BinaryBuildSettingsManager
except Exception:
    class BinaryBuildSettingsManager:
        def __init__():
            raise RuntimeError("You shouldn't be including this")
    pass
from edk2toollib.utility_functions import GetHostInfo

#
# ==========================================================================
# PLATFORM BUILD ENVIRONMENT CONFIGURATION
#

class SettingsManager(UpdateSettingsManager, CiSetupSettingsManager, BinaryBuildSettingsManager):
    def __init__(self):
        SCRIPT_PATH = os.path.dirname(os.path.abspath(__file__))

        WORKSPACE_PATH = os.path.dirname(os.path.dirname(SCRIPT_PATH))
        self.OUTPUT_DIR = os.path.join(WORKSPACE_PATH, "Build", ".NugetOutput")
        self.ws = WORKSPACE_PATH
        self.pp = ['Common/MU_TIANO', "Silicon/Arm/MU_TIANO"]
        self.sp = SCRIPT_PATH
        self.nuget_version = None
        pass

    def GetActiveScopes(self):
        ''' return tuple containing scopes that should be active for this process '''
        scopes = ("corebuild", "sharednetworking_build", )
        return scopes

    def PreFirstBuildHook(self):
        output_dir = self.OUTPUT_DIR
        try:
            if os.path.exists(output_dir):
                logging.warning(f"Deleting {output_dir}")
                shutil.rmtree(output_dir, ignore_errors=True)
            os.makedirs(output_dir)
        except:
            pass

        self.nuget_version = self._GetNextVersion(self.nuget_version)
        return 0

    def PostBuildHook(self, ret):
        if ret == 0:
            ret = self._CollectNuget()
        if ret != 0:
            logging.error("Error occurred in post build hook")
        return ret

    def PostFinalBuildHook(self, ret):
        if ret != 0:
            logging.error(
                "There was failure along the way aborting NUGET publish")
            return
        self._PublishNuget()

    def GetWorkspaceRoot(self):
        ''' get WorkspacePath '''
        return self.ws

    def GetPackagesPath(self):
        ''' Return a list of workspace relative paths that should be mapped as edk2 PackagesPath '''
        return os.pathsep.join(self.pp)

    def GetName(self):
        return "SharedNetworking"

    def GetPackagesSupported(self):
        return "NetworkPkg"

    def GetArchitecturesSupported(self):
        return ["IA32", "AARCH64", "X64"]

    def GetTargetsSupported(self):
        return ["DEBUG", "RELEASE"]

    def GetConfigurations(self):
        TARGETS = self.GetTargetsSupported()
        ARCHS = self.GetArchitecturesSupported()
        # combine options together
        for target in TARGETS:
            for arch in ARCHS:
                self.target = target
                self.arch = arch
                yield({"TARGET": target, "TARGET_ARCH": arch, "ACTIVE_PLATFORM": "NetworkPkg/SharedNetworking/SharedNetworkPkg.dsc"})

    def GetDependencies(self):
        return []

    def AddCommandLineOptions(self, parserObj):
        ''' Add command line options to the argparser '''
        parserObj.add_argument('-d', '--dump_version', '--dump-version', dest='dump_version',
                               type=bool, default=False, help='Should I dump nuget information?')
        parserObj.add_argument("-nv", "--nuget_version", "--nuget-version", dest="nug_ver",
                               type=str, default=None, help="Nuget Version for package")

    def RetrieveCommandLineOptions(self, args):
        '''  Retrieve command line options from the argparser '''
        shell_environment.GetBuildVars().SetValue(
            "TOOL_CHAIN_TAG", "VS2017", "Set default")
        self.nuget_version = args.nug_ver
        self.should_dump_version = args.dump_version
```
