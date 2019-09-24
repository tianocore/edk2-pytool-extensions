# Creating An Invocable

Whether you spell it invokable or invocable, the idea of an Invocable is central to Stuart.
If you're unfamiliar with what it is, refer to the using document in the root docs folder or feature_invocable in the features folder.
In a nutshell, an invokable is a small python file that gets the project Mu environment setup for it.
It gets a settings file (that the invocable defines the interface for) that provides information about the that we are being invoked on.

This guide is written in the style of a tutorial. This is based on the real example of an invokable that the Project Mu team wrote.

## The problem statement

One feature that Project Mu offers is that of a binary packaged Crypto and Networking, known as SharedCrypto and SharedNetworking respectively.
This allows your platform to skip the expensive step of compiling OpenSSL or other crypto libraries and instead use a known good crypto library that is built from a known good source.
For more information on Shared Networking and Shared Crypto, go check it out [here](https://microsoft.github.io/mu/dyn/mu_plus/SharedCryptoPkg/feature_sharedcrypto/) and [here](https://microsoft.github.io/mu/dyn/mu_basecore/NetworkPkg/SharedNetworking/SharedNetworking/).

Now, how is Shared Binaries built?
Check out the code on [github](https://github.com/microsoft/mu_basecore) under NetworkPkg/SharedNetworking/DriverBuilder.py (it may move, this is where it was at time of writing), which is the invokable that powers the shared binaries.

SharedNetworking in particular is a tricky problem because we want to built every architecture into an FV and package it into a NugetFeed.

In a nutshell here's the flow we want:
 1. Acquire the dependencies we need (Crypto, OpenSSL, etc)
 2. Pull in any tooling that we require (mu_tools, nasm)
 3. Configure the enviroment for building with our tool chain
 4. Go through all the architectures we want to support and build them individually
 5. If all previous steps were successful, package it into a nuget package
 6. If given an API key, then publish to nuget.

Now a typical approach to this might be scripting through a batch script to invoke build.py, or invoking a stuart_build.
This is a fine approach, particularly for a one off solution.
But what if we change how nuget publishing is done?
We need to update the batch script for both Crypto and Networking.
Or perhaps we've thought of that and made a common script that our handy batch script invokes with the right parameters.
We hope you can see that as time goes on, the sitatuion spirals out of control as more parameters and scripts are added, fewer people will know how to work this or want to touch it.
Eventually a bright talented engineer with a little more time than experience will declare that they were attempt to refactor this process.

In a nutshell that's the problem that the invokable framework in general is trying to solve.
Steps 1-3 are done for you. Steps 4-6+ should be trivial to implement in a setting agnostic way.

So let's start.

## The settings class

Each invokable has a definition for a settings class.
We would recommend looking through [a few of the invokables](https://github.com/tianocore/edk2-pytool-extensions/tree/master/edk2toolext/invocables) inside of Stuart as a reference.
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
These imports will seem a little strange but we'll discuss all of them

One final import is needed that will seem a little strange.
```python
import DriverBuilder
```
Stuart works in such a way that it expects your invokable to be running in the namespace that is named in.
If you run your builder directly from the commandline, it will be running in \_\_main__, which can cause problems.
**In a nutshell, you'll need to import the name of your file.**
We'll see where this is used at the end.

Now the settings class!

```python
class BinaryBuildSettingsManager():
    ''' Platform settings will be accessed through this implementation. '''

    def GetActiveScopes(self):
        ''' get scope '''
        raise NotImplementedError()

    def GetWorkspaceRoot(self):
        ''' get WorkspacePath '''
        raise NotImplementedError()

    def GetPackagesPath(self):
        pass

     def GetName(self):
        ''' Get the name of the repo, platform, or product being build by CI '''
        raise NotImplementedError()

    def AddCommandLineOptions(self, parserObj):
        ''' Implement in subclass to add command line options to the argparser '''
        pass

    def RetrieveCommandLineOptions(self, args):
        '''  Implement in subclass to retrieve command line options from the argparser '''
        pass

```

We've implemented a few methods that are needed to get the SDE off the ground.
- _GetActiveScopes_ is needed to init the SDE. This cause different plugins to load or not.
- _GetWorkspaceRoot_ gets the folder that is the root of your workspace.
- _GetPackagePaths_ gets the folder locations that you will resolve EDK2 paths against.
- _GetName_ is the thing we are building
- _AddCommandLineOptions_ gives our settings the chance to set items in the parser object
- _RetrieveCommandLineOptions_ gives us the chance to read the arguments from the commandline

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

- _GetConfigurations_ is our way to get the configurations we want to build. We'll use a generator/iterator pattern here that we'll see later.

We also need some methods to have callbacks into various stages of the process so that we can do nuget commands and prepare the nuget package.

```python

class BinaryBuildSettingsManager():
    ''' Platform settings will be accessed through this implementation. '''

    ....

     def PreFirstBuildHook(self):
        ''' Called after the before the first build '''
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

These hooks are pretty self evident but they'll be called at various point in the process.
Now with our current file, we can define a settings file that implements the settings class.
That doesn't really net us much.

## The invocable

The invocable is actually the simplist part of this

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

Go is the main bread and butter so to speak of an invocable. If we were to run this right now, we would see this as output (assuming you created an empty settings class).
```console
SECTION - Init SDE
SECTION - Loading Plugins
SECTION - Start Invocable Tool
SECTION - Summary
PROGRESS - Success
```
