# Building A Platform

You have an EDK2 implementation, a platform DSC, and a platform FDF? Great! You
are one [settings file](/features/settings_manager.md) away from a great
platform building experience.

The build process has three [stuart commands](/index.md#what-can-i-ask-stuart-to-do)
to take your firmware code tree from freshly cloned to fully built: `stuart_setup`, `stuart_update`, `stuart_build`
(hereby known has the "command(s)"). Behind the scenes, each command is an [Invocable](/features/invocable.md)
that has a corresponding [Settings Manager](/features/settings_manager.md) that the platform subclasses to provide
platform specific information.

In hopes of keeping this section as light as possible, the information provided will be broad and more conversational
then tutorial. If you want a step by step example of porting a platform, we have one! Please see
[Porting the Raspberry Pi 3](/integrate/porting.md).

## Getting Started

Stuart needs a settings file to configure itself. This settings file must provide a settings manager subclasses for each
command you plan on using. This settings manager is the interface that provides platform specific information to the
platform agnostic invocable. This is done via subclassing the corresponding settings file and overriding the necessary
methods described in the [Settings Manager](/features/settings_manager.md).

In terms of building a platform, there are five classes that you need to be aware of. The first two are interfaces that
provide functions used across all three commands and can be shared among the SettingsManagers by using
[Multiple Inheritance](/features/settings_manager.md#a-note-on-multi-inheritance).

1. [Edk2InvocableSettingsInterface](/api/edk2_invocable.md#edk2toolext.edk2_invocable.Edk2InvocableSettingsInterface)
2. [MultiPkgAwareSettingsInterface](/api/invocables/edk2_multipkg_aware_invocable.md#edk2toolext.invocables.edk2_multipkg_aware_invocable.MultiPkgAwareSettingsInterface)
3. [SetupSettingsManager](/api/invocables/edk2_setup.md#edk2toolext.invocables.edk2_setup.SetupSettingsManager)
4. [UpdateSettingsManager](/api/invocables/edk2_update.md#edk2toolext.invocables.edk2_update.UpdateSettingsManager)
5. [BuildSettingsManager](/api/invocables/edk2_ci_build.md#edk2toolext.invocables.edk2_ci_build.CiBuildSettingsManager)

The final class we inherit from in the settings file the
[UefiBuilder](/api/environment/uefi_build.md#edk2toolext.environment.uefi_build.UefiBuilder)
and is what provides the bulk of customization EDK2 Pytools affords you.
This is also where you can utilize many of the features and functionality
spread across Edk2-Pytools (Extensions and Library).

Lets take a look at each command!

## Stuart Setup

`stuart_setup` is the first command and is responsible for setting up the code tree. Currently, this only involves
preparing the git submodules necessary for build. If you've created an [Omnicache](/tools/using_omnicache_tool.md), here
is where you would use it to save on network bandwidth, disk space, and time when cloning repos. As you might expect,
`stuart_setup` does not automatically know what submodules are necessary for each platform; we must use the
[SetupSettingsManager](/api/invocables/edk2_setup.md#edk2toolext.invocables.edk2_setup.SetupSettingsManager)
to provide that information.

!!! Note
    The command specific [Settings Manager](/features/settings_manager.md) may not provide *ALL* platform data
    required by the command; it only provides the platform data specific to that command. You still need to override some
    methods from
    [Edk2InvocableSettingsInterface](/api/edk2_invocable.md#edk2toolext.edk2_invocable.Edk2InvocableSettingsInterface)
    and [MultiPkgAwareSettingsInterface](/api/invocables/edk2_multipkg_aware_invocable.md#edk2toolext.invocables.edk2_multipkg_aware_invocable.MultiPkgAwareSettingsInterface)
    that multiple (or all) commands use, which is why they are in the parent class. Don't worry though! If you miss
    overriding a required method, you'll raise a `NotImplementedError`!

**Review the `stuart_setup` specific settings manager [here](/api/invocables/edk2_setup.md#edk2toolext.invocables.edk2_setup.SetupSettingsManager).**

## Stuart Update

Next up is `stuart_update`, which is responsible for updating any external dependencies in the workspace. This includes
downloading and performing miscellaneous tasks for external dependencies. You can find details on how external
dependencies work and how to utilize them in the [ext_dep](/features/extdep.md) section.

As you'll see in the API reference for `UpdateSettingsManager`, no additional methods need to be overwritten. At first
glance, it may seem like `stuart_update` does not need any platform specific information, but it actually does. The key
takeaway is that you'll still need to inherit from `UpdateSettingsManager`; it's just that the necessary platform data
for this command comes from overriding methods in the parent class
[Edk2InvocableSettingsInterface](/api/edk2_invocable.md#edk2toolext.edk2_invocable.Edk2InvocableSettingsInterface)
and/or [MultiPkgAwareSettingsInterface](/api/invocables/edk2_multipkg_aware_invocable.md#edk2toolext.invocables.edk2_multipkg_aware_invocable.MultiPkgAwareSettingsInterface).

**Review the `stuart_update` specific settings manager [here](/api/invocables/edk2_update.md#edk2toolext.invocables.edk2_update.UpdateSettingsManager).**

## Stuart Build

Lastly is the `stuart_build` command, which actually has two phases to it. The first phase is executed via the
`stuart_build` command and uses the `BuildSettingsManager` to setup the environment in preparation for the build. It
will then invoke the `UefiBuilder`, signaling the start of the second phase which consists of most of the customization
afforded to you by EDK2 Pytools.

**Review the `stuart_build` specific settings manager [here](/api/invocables/edk2_ci_build.md#edk2toolext.invocables.edk2_ci_build.CiBuildSettingsManager).**

## UefiBuilder

So what has all of these commands been culminating to? They've all been working to prepare a
[Self Describing Environment](/features/sde.md) for the `UefiBuilder` to operate in. The purpose of the
`UefiBuilder` is to allow the platform to perform various tasks using this environment. Custom made
[UefiBuildPlugins](/features/plugin_manager.md#types-of-plugins) will automatically be run Pre and Post build for
all platforms while [UefiHelperPlugins](/features/plugin_manager.md#types-of-plugins) will be available to the
developer to help create Platform specific Pre and Post build functionality. The `UefiBuilder` class has a lot to it, so
let's take a look at each part.

### Command Line options

`UefiBuilder` has multiple built in command line options that control the flow of the build. The below code snippet
shows these command line variables and are accessible via `self.<dest>`. Developers can use this to help control flow in
any of the overrideable methods described in the following sections, however they are also used to control build flow
outside the control of the developer.

:::edk2toolext.environment.uefi_build.UefiBuilder.AddPlatformCommandLineOptions
    handler: python
    options:
        heading_level: 4
        show_signature: True
        show_root_full_path: false

While we don't provide you the ability to override this function (without being hacky like overriding it anyway and
calling the superclass in your override), there is an easy way to add CLI options to your build, which is through
Platform Environment Variables

### Platform Environment Variables

Platform environment variables are a powerful tool used throughout the build process. Not only do environment variables
allow you to control build flow within the `UefiBuilder`, but they also are used by the platform fdf and dsc. You can
set platform environment variables in the platform DSC, FDF, Settings File, and Command Line; any variable set in one is
available in the others! A simple example of this would be to add or remove features based off some criteria. With
Edk2-Pytools this is as simple as setting a single env variable during build. We will walk through this example soon.

#### Setting / Getting Environment Variables

It's easy set and get environment variables in the FDF, DSC, Settings file, and Command line as seen in the table below:

| **Type**      | **Set**                  | **Get**                         |
|---------------|--------------------------|---------------------------------|
| Command Line  | VAR [= Value]            | N/A                             |
| FDF/DSC       | DEFINE VAR = Value       | $(VAR)                          |
| Settings File | env.SetValue(Var, Value) | env.GetValue(Var, DefaultValue) |

To support parity with Edk2's build command line option -D/--define, variables passed via the command line are not
required to have a value associated with them. Variables defined this way are considered non-valued variable defines
and should be checked for existence rather then value (i.e. `if env.GetValue(var):` or `if not env.GetValue(var)`).

While you can set and get variables anywhere in the `UefiBuilder` portion of the settings file, we provide the following
three methods to set environment variables, ensuring they are available everywhere that you are allowed to customize:

- [SetPlatformEnv](/api/environment/uefi_build.md#edk2toolext.environment.uefi_build.UefiBuilder.SetPlatformEnv)

- [SetPlatfromEnvAfterTarget](/api/environment/uefi_build.md#edk2toolext.environment.uefi_build.UefiBuilder.SetPlatformEnvAfterTarget)

- [SetPlatformDefaultEnv](/api/environment/uefi_build.md#edk2toolext.environment.uefi_build.UefiBuilder.SetPlatformDefaultEnv)

!!! Warning
    `SetPlatformDefaultEnv` is not like the others. Rather then setting the environment variables directly, it should
    return a limited list of the most commonly overridden variables and their default values! The values returned are
    printed to the terminal when using the `-h, --help` flags so that develops can easily find the common ways to
    customize a platforms build. Additionally, if these variables have not been set anywhere else in the build, they
    will be set to the default values.

!!! Note
    Not all variables are passed through stuart to the actual build command. Only variables with the prefix `BLD_*_`,
    `BLD_DEBUG_` and `BLD_RELEASE_` are considered build values and consumed by the build command.

#### Example

As mentioned above, lets walk through a simple example of build customization with Edk2-Pytools. In this scenario, we
want a simple way to build our platform in three distinct ways. To keep it simple, all we want to customize is the
target type (DEBUG/RELEASE) and the inclusion of the EdkShell. These builds will be DEV, SELFHOST, and RELEASE. From the
command line, we we would call `stuart_build -c Platform.py PROFILE=DEV`. All that needs to be done is to check the
value of profile during `SetPlatformEnv()` and make our build customizations from there.

``` python

def __init__(self):
    self.profiles = {
        "DEV" : {"TARGET" : "DEBUG", "EDK_SHELL": ""},
        "SELFHOST" : {"TARGET" : "RELEASE", "EDK_SHELL": ""},
        "RELEASE" : {"TARGET" : "RELEASE"}
    }
...

def SetPlatformEnv(self):
    build_profile = self.env.GetValue("PROFILE", "DEV") # Default DEV
    if build_profile in self.profiles:
        for key, value in self.profile[build_profile].items():
            self.env.SetValue(key, value, "PROFILE VALUE")
...
```

The environment variables are set, whats next? The target is automatically picked up by the build system, so all that
needs to be done is to add the logic of including the Edk shell or not. This can be done in the platform fdf as seen below:

``` shell
!if $(EDK_SHELL)
FILE APPLICATION = PCD(gPcBdsPkgTokenSpaceGuid.PcdShellFile) {
  SECTION PE32 = <SomePath>/Shell.efi
  SECTION UI = "EdkShell"
}
!endif
```

### Pre / Post Build Customization

Edk2 Pytools offer developers multiple ways to customize the build experience, both Pre and Post Build. The first way is
through [UefiBuildPlugins](/features/plugin_manager.md#types-of-plugins) (executed automatically for all platforms)
which is discussed in [Create a Plugin](/features/creating_plugins.md) section, and through three methods to override in
the `UefiBuilder` (specific to the platform) which will be the focus here.

- [PlatformPreBuild](/api/environment/uefi_build.md#edk2toolext.environment.uefi_build.UefiBuilder.PlatformPreBuild)
- [PlatformPostBuild](/api/environment/uefi_build.md#edk2toolext.environment.uefi_build.UefiBuilder.PlatformPostBuild)
- [PlatformFlashImage](/api/environment/uefi_build.md#edk2toolext.environment.uefi_build.UefiBuilder.PlatformFlashImage)

All three of the callbacks that you can override have access to the same environment, but each happens at a different
time in the build process as outlined below. You can choose to perform specific tasks both prebuild and postbuild such
as moving files around pre build or patching in binary data post build. We also offer a callback for flashing your image
to the device, if you have the infrastructure to do so via command line. You'll have to fully implement it yourself, but
it can greatly speed up the time it takes to get your firmware on your platform.

1. `PlatformPreBuild()`
2. `UefiBuildPlugins` that implement `do_pre_build()`
3. `Build()`
4. `PlatformPostBuild()`
5. `UefiBuildPlugins` that implement `do_post_build()`
6. `PlatformFlashImage()`

Lets end this section by mentioning some of the important things (but not everything) you have access to during the
callbacks mentioned above:

#### Helper Plugins

This is another type of plugin that is talked about in the [Create a Plugin](/features/creating_plugins.md)
that allows the developers to add in extensions or helper methods to the build
environment that are easy to access. You can easily access them through
`self.Helper.<FunctionName>()`. As an example, if we made that helper called
`YamlToBin(yaml_obj)`, then we could call it via `self.Helper.JsonToBin(yaml)`.

#### The Environment

As we alluded to in one of the previous sections, you'll have access to all of the environment variables set throughout
the DSC, FDF, CLI, and anywhere else in the build. you'll be able to access the environment via `self.env`. To see the
available methods to use, please review the [VarDict](/api/environment/var_dict.md#edk2toolext.environment.var_dict.VarDict).

#### Edk2 Pytool Library

The second half of Edk2 Pytools is [Edk2 Pytool Library](https://github.com/tianocore/edk2-pytool-library), which
provides the building blocks of tools that are relevant to UEFI firmware developers. Some of these tools include file
parsers for edk2 specific file types and UEFI defined values and interfaces for usage in python. You can think of Edk2
Pytool Extensions (This) as the simple framework to get your platform building and Edk2 Pytool Library as the building
blocks to do more advanced customization of the build.
