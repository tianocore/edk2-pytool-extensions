# invocables

Invocables exist as a way to setup the EDK2 environment in a consistent way such that any script could be run in the context of a UEFI environment.
The base_abstract_invocable describes the necessities of the EDK2 environment, to be provided by the user however they wish.
Built on top of that, edk2_invocable is an attempt to do as much parsing and setup for the user as possible to minimize the requirements of individual invocable scripts.

To kick off a script, just Invoke().

## base_abstract_invocable

example: Sample_InvocableHelloWorld.py

### provided functions 

#### Invoke

Main function. Parses command line options, configures logging, bootstraps environment, loads plugins, and finally calls Go.

#### ConfigureLogging

Sets up logging using information from GetWorkspaceRoot, GetLoggingLevel, GetLoggingFileName, and GetLoggingFolderRelativeToRoot.

### abstract functions

ParseCommandLineOptions is your opportunity to use argparser or look at sys.argv before kicking off setup.
If the enviroment isn't meant to be verifiable (maybe this script involves setting up or unpacking the environment), GetVerifyCheckRequired can return False to bypass that step.
After that, GetWorkspaceRoot and GetActiveScopes is used to get the necessary information about the environment and set everything up.
Go will be called after all that setup.

Note: logging before ConfigureLogging gets called causes logging to be setup twice (once implicitly by calling it early and then again by ConfigureLogging) and you will see duplicate messages in your console.
To avoid this, do not log in ParseCommandLineOptions, GetLoggingLevel, GetWorkspaceRoot, GetLoggingFolderRelativeToRoot, or GetLoggingFileName. 
If you must have output, use print() or log another way.

## edk2_invocable

Example: edk2toolext\invocables\edk2_update.py

Basically just base_abstract_invocable + settings parsing. 

### functions

#### ParseCommandLineOptions

This is implemented for the user. It requires a Python settings file be provided. After importing the settings file, another argparser is created, which is passed to the invoking script and to the settings file. Additionally, key value pairs in the format `KEY=VALUE` will be read into the build environment, accessible by calling `shell_environment.GetBuildVars().GetValue(KEY)`. For example, to skip loading the compiler plugin, pass `CompilerPlugin=skip` as an extra argument when calling your script.

#### GetSettingsClass

This must provide a Python class that edk2_invocable can expect to find instantiated by your settings script.

##### multi inheritance

Example: NXP

In Python it is allowed and it will be helpful for you as long as you don't try to get too creative with it.
GetActiveScopes, GetWorkspaceRoot, AddCommandLineOptions, RetrieveCommandLineOptions are required to be in each Settings class.
Using a platform as an example, PlatformSetup, Update, and PlatformBuild all require settings classes, but they can all be provided by the same implementation with multi-inherence.
The caveat is that you will not know which parent class is invoking you.
If that is required, it will be necessary to break that settings class out into it's own class.
It is also worth noting that multiple classes can live in the same file and the correct one will still be located by the loading logic.

In the PlatformBuild scenario, it is even possible to have UefiBuilder, UpdateSettingsManager, SetupSettingsManager, and BuildSettingsManager all in one class.