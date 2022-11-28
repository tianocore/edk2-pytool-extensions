# Creating Something New

You want to do something new that has never been done before? You want to tailor
the process specifically to your use case? You need something to do on the
weekend?

Great! We have built out invocables
to be as robust and extensible as possible. We have `base_abstract_invocable`,
which asks for the bare minimum required for environment initialization in the form
of abstract functions that you can fill out. We have also built `edk2_invocable`, on
top of `base_abstract_invocable`, which handles getting setup and providing settings
in a manner we hope will work well for most everyone. Finally, we have the
`multipkg_aware_invocable` on top of the `edk2_invocable` that provides the invocable
with information about the differentpackages used by the platform.

## Getting Started

To get started with creating a new invocable, first review the different invocables
and determine which provides the closest amount of platform data and additional
functionality needed by your new invocable. While you could subclass your invocable
from any existing invocable, we suggest only subclassing from one of the following:
`base_abstract_invocable`, `edk2_invocable`, or `multipkg_aware_invocable`.

## The Settings Manager

Each invocable, excluding the `base_abstract_invocable` has the concept of a Settings
Manager as we talked about in the [Build a Platform](/1.%20Getting%20Started/build)
section. You will use the Settings Manager to provide platform specific information
to your invocable. First subclass the settings interface of the invocable you chose to
inherit from, then take a look at all parents of your class and understand exactly which
methods are available. If any platform data cannot be provided from the existing methods,
you then add those to your invocables setting manager.

Lets do an example where we create a new invocable, subclassing from the edk2_invocable.
We start with subclassing our invocable:

```python
from edk2toolext.edk2_invocable import Edk2InvocableSettingsInterface

class MyNewInvocableSettingsManager(Edk2InvocableSettingsInterface):
    pass

```

Next we will follow the parent chain to the base object taking note of what methods
already exist. For this example, the only Settings Manager in this chain for our new
invocable is the `Edk2InvocableSettingsInterface`. Due to this, we know the following methods are available to our invocable:

```python
GetWorkspaceRoot(self)
GetPackagesPath(self)
GetActiveScopes(self)
GetLoggingLevel(self, loggerType)
AddCommandLineOptions(self, parserObj)
RetrieveCommandLineOptions(self, args)
GetSkippedDirectories(self)
```

Next, we identify what platform data is necessary for our invocable, but is not provided by
one of the existing methods and then add it to our new invocables SettingsManager.

!!! tip
    These methods can be optional (which return a default value) or required (which will
    raise a NotImplementedError). You can override an existing optional method and change
    it to be a required method, but you cannot turn a required method into an optional one.

Lets take a look at an example of subclassing the interface for our new invocable:

```python
from edk2toolext.edk2_invocable import Edk2InvocableSettingsInterface

class MyNewInvocableSettingsManager(Edk2InvocableSettingsInterface):

    def GetActiveScopes(self):
        raise NotImplementedError() # We override this method and make it required to have atleast one active scope

    def GetPlatformVersion(self):
        return None # Optional for a platform to implement, so we return a default value
    
    def GetPlatformAlignment(self):
        raise NotImplementedError() # Required by a platform to be implemented so we raise an error
    
    # GetPackagesPath(self): # we need this method, but since it already exists, we don't need to reimplement it
```

We have now defined exactly what platform data is needed for our invocable to execute. It
will be up to the platform to implement these functions in their
[settings file](/usability/using_settings_manager). Lets move on to implementing the actual
functionality of the invocable.

## The Invocable

Before we start implementing our functionality, we once again want to take stock of all the
methods that already exist in our parent classes. In this chain, we actually have the
`Edk2Invocable` and `BaseAbstractInvocable`. While all of these methods are available to call,
not all may be implemented, so your invocable may need to implement one or two. Some methods
already have default implementations, but you can override them with custom functionality if
you wish.

!!! warning
    The only exception is that Invoke() should never be overridden. This is what sets up the
    environment for the invocable

```python
GetWorkspaceRoot() # Has default implementation
GetPackagesPath() # Has default implementation
GetActiveScopes() # Has default implementation
GetLoggingLevel() # Has default implementation
AddCommandLineOptions() # No default implementation, optional
RetrieveCommandLineOptions() # No default implementation, optional
GetSkippedDirectories() # Has default implementation
GetSettingsClass() # No default implementation, required
GetLoggingFolderRelativeToRoot() # Has default implementation
ParseCommandLineOptions() # Has default implementation
InputParametersConfiguredCallback() # No default implementation, optional
GetVerifyCheckRequired() # Has default implementation
GetLoggingFileName() # No default implementation, required
Go() # Where core logic of your invocable goes, required
ConfigureLogging() # Has default implementation
Invoke() # Core environment setup before invocable execution, should never be overridden
```

Generally, the above methods are called within `Invoke()` and are used to assist in setting
up the environment for your invocable to run in, however you are able to use any of them
inside the core logic of your invocable (`Go()`) if needed. You will use these methods, your
SettingsManager methods, and any additional custom methods you implement in the invocable to
create the core functionality of your invocable.

Lets finish up our example with implementing the invocable now.

```python
from edk2toolext.edk2_invocable import Edk2Invocable, Edk2InvocableSettingsInterface

class MyNewInvocableSettingsManager(Edk2InvocableSettingsInterface):

    def GetActiveScopes(self):
        raise NotImplementedError() # We override this method and make it required to have atleast one active scope

    def GetPlatformVersion(self):
        return None # Optional for a platform to implement, so we return a default value
    
    def GetPlatformAlignment(self):
        raise NotImplementedError() # Required by a platform to be implemented so we raise an error


class MyNewInvocable(Edk2Invocable):
    def GetSettingsClass(self):
        # Override required method
        return MyNewInvocableSettingsManager

    def GetLoggingFileName():
        # Override required method
        return "INVOCABLE"

    def AddCommandLineOptions(self, parserObj):
        # Override existing method
        parserObj.add_argument(...)

    def RetrieveCommandLineOptions(self, args):
        # Override existing method
        self.variable = args.variable

    def GetVersion(self):
        # New Method
        return self.PlatformSettings.GetPlatformVersion()

    def GetAlignment(self):
        # New Method
        return self.PlatformSettings.GetPlatformAlignment()
    
    def Go(self):
        # Do Core functionality of the invocable. Environment is already set up.
```

## The Settings File

The invocable is done! The only thing left is for the individual platforms to
update their settings file so that the invocable can successfully run. Thanks to
python's multiple inheritance, this is actually very simple to do! Lets take
[mu_tiano_platforms](https://github.com/microsoft/mu_tiano_platforms)' QemuQ35
and make the necessary changes to allow our invocable to execute on this platform.

For our plugin to work for this platform, we just need to subclass the Settings
Manager we just made, and ensure the necessary methods are implemented, i.e.
`GetActiveScopes()`, `GetPlatformVersion()`, `GetPlatformAlignment()`, and
`GetPackagesPath()`.

Taking a look at QemuQ35's setting file, [PlatformBuild.py](https://github.com/microsoft/mu_tiano_platforms/blob/main/Platforms/QemuQ35Pkg/PlatformBuild.py)
, we can actually see that the class `SettingsManager` already implements
`GetActiveScopes()` and `GetPackagesPath()`. Due to this, it is a great
candidate to add our additional settings manager to, and two additional
methods. Lets do that now.

### Before

```python
from edk2toolext.invocables.edk2_setup import SetupSettingsManager
from edk2toolext.invocables.edk2_update import UpdateSettingsManager
from edk2toolext.invocables.edk2_pr_eval import PrEvalSettingsManager
class SettingsManager(UpdateSettingsManager, SetupSettingsManager, PrEvalSettingsManager):
    ... # Existing methods removed to save space
```

### After

```python
from edk2toolext.invocables.edk2_setup import SetupSettingsManager
from edk2toolext.invocables.edk2_update import UpdateSettingsManager
from edk2toolext.invocables.edk2_pr_eval import PrEvalSettingsManager
from edk2toolext.invocables.my_new_invocable import MyNewInvocableSettingsManager # Path will be different
class SettingsManager(UpdateSettingsManager, SetupSettingsManager, PrEvalSettingsManager, MyNewInvocableSettingsManager):
    ... # Existing methods removed to save space
    
    def GetPlatformVersion(self):
        return 1
    
    def GetPlatformAlignment(self):
        return 4096
```

And Viola, your invocable will now be able to run on the QemuQ35 platform.
