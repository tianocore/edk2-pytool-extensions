# Porting a platform to EDK2

You've probably seen the great promises that EDK2 Pytools gives and wondered how to get started on a platform you already have.
There are many places you could be coming from but you likely have some sort of automated work flow that calls edk2's build at some point.
In this guide, two paths will be discussed and one will be shown.
The first path is porting a project that is based on Microsoft's Project Mu (a fork of EDK2).
The second is porting a project that is based on base EDK2.

In this guide, we will building a platform from EDK2-Platforms, the humble Raspberry Pi 3.
This is because you likely have one lying around somewhere or can buy it online for fairly cheap.
It is also a simpler platform compared to many intel based ones while still being large enough to show the benefits of Stuart.

We will be using Project Mu (https://microsoft.github.io/mu/) because it splits the packages of EDK2 up and offers some niceties that we will take advantage of.

This process is documented in the repo (TODO).

This guide shows one way to structure your platform code but there are many different approaches out there.
Stuart is flexible and versatile enough to be able to be adapted to many workflows.
You are encouraged to experiment and see what works best for you and your team.

## Getting Started

First we will start by creating our workspace.

```bash
mkdir rpi
cd rpi
git init
```

We'll add a `.gitignore` to keep things sensible.

```gitignore
*.pyc
*.bak
/Build
/Conf
/.vs
/.vscode
*_extdep/
```

Next we'll add our `pip_requirements.txt` file to keep our pip modules in sync with our project. You can optionally setup a virtual environment to keep different versions of pip modules, but that is left up to the reader.

```pip
edk2-pytool-library
edk2-pytool-extensions
```

You're welcome to snap to a particular version by adding `==0.12.2` or whatever version you want to keep after the pip name.

Next you'll need to install the pip modules.

```bash
pip install -r pip_requirements.txt
```

Now let's start by adding EDK2 modules.
If you were taking default EDK2, you could add it as a submodule like so:
```
git submodule add edk2 https://github.com/tianocore/edk2.git
```

We're going to be using Project Mu since we can carry less and be a little more streamlined. We will need four packages.

- BASECORE: this contains the base packages like MdeModulePkg and MdePkg
- MU_PLUS: this has the extra stuff that Mu provides like DFCI, GraphicsPkg, and SharedCrypto.
- TIANO_PLUS: this has things like ShellPkg and FmpDevicePkg.
- OEM_SAMPLE: this contains things that an OEM might find useful like a FrontPage application and a Boot menu.

You can add these all by running this command:
```bash
git submodule add https://github.com/Microsoft/mu_basecore.git MU_BASECORE
git submodule add https://github.com/Microsoft/mu_plus.git Common/MU
git submodule add https://github.com/Microsoft/mu_tiano_plus.git Common/TIANO
git submodule add https://github.com/Microsoft/mu_oem_sample.git Common/MU_OEM
git submodule add https://github.com/microsoft/mu_silicon_arm_tiano.git Silicon/ARM/MU_TIANO
```

Next we will setup a folder to keep track of our platform. In this case we'll use `RaspberryPi`

```bash
mkdir Platform
cd Platform
mkdir RaspberryPi
```

Next we will be taking the Raspberry Pi repo here (https://github.com/tianocore/edk2-platforms/tree/ce51222de1c5f2e81c3c9e5ff31bcfc3b48ccbc7/Platform/RaspberryPi) and copy it into our repo.
Master at time of writing was ce51222de1c5f2e81c3c9e5ff31bcfc3b48ccbc7, feel free to take something newer but some things might not match.
This would be like taking your DSC, FDF, DEC and putting it into your code tree.
Copy the contents of `edk2-platforms/RaspberryPi/` to the `Platform/RaspberryPi` folder.

Next we'll grab the silicon code.
First create the folder in the root of your repo.

```bash
mkdir Silicon
```

Then grab `edk2-platforms/Silicon/Broadcom/Bcm283x` and put it into `Silicon/Broadcom/Bcm283x`.
In a typical code tree, the silicon specific code might be another repo but in this case, we'll just include it in the root of our tree.
We'll also copy `edk2-platforms/Driver/OptionRomPkg` to `/OptionRomPkg`.

At this point, we're almost ready.
Our tree should look like this:

```tree
rpi
|   .gitignore
|   .gitmodules
|   pip_requirements.txt
|
|---Common
|   |---MU
|   |---MU_OEM
|   |---TIANO
|
|---MU_BASECORE
|
|---OptionRomPkg
|   |   ....
|
|---RaspberryPi
|   |   RaspberryPi.dec
|   |
|   |---AcpiTables
|   |---Drivers
|   |---Include
|   |---Library
|   |---Include
|
|---Silicon
|   |---ARM
|   |   |---MU_TIANO
|   |
|   |---Broadcom
|   |   |---Bcm283x
|   |   |   ....
```

You can see the files at the commit here (TODO)

## The settings file

The guide is written for pytool-extensions v0.12 and some things may have changed since this was written.
Please refer to the release notes to see what has changed.

Stuart needs a settings file to configure itself. It helps define where the workspace root is and what sort of things we need to initialize.
Since we are using the build in invocables, we'll need to implement three settings managers: UpdateSettingsManager, SetupSettingsManager, BuildSettingsManager.

If you're unfamiliar with what an invocable or a settings file is, please refer to our documentation.

Let's add a file: `Platform/RaspberryPi/RPi3/PlatformBuild.py`

```python
##
## Script to Build Raspberry Pi 3 firmware
##
import os
import logging
from edk2toolext.environment.uefi_build import UefiBuilder
from edk2toolext.invocables.edk2_platform_build import BuildSettingsManager
from edk2toolext.invocables.edk2_setup import SetupSettingsManager
from edk2toolext.invocables.edk2_update import UpdateSettingsManager

#
#==========================================================================
# PLATFORM BUILD ENVIRONMENT CONFIGURATION
#
class SettingsManager(UpdateSettingsManager, SetupSettingsManager, BuildSettingsManager):
    def __init__(self):
        SCRIPT_PATH = os.path.dirname(os.path.abspath(__file__))
        WORKSPACE_PATH = os.path.dirname(os.path.dirname(SCRIPT_PATH))
        self.ws = WORKSPACE_PATH

    def GetWorkspaceRoot(self):
        ''' get WorkspacePath '''
        return self.ws

```

Our settings provider can now set up our workspace path, which should resolve to your root `rpi` folder.
However, it is still missing a lot of functionality.

The three invocables that we have implemented settings for are `stuart_build`, `stuart_update`, and `stuart_setup`.
If you were to call one of these, you'd get an error and perhaps a non-implemented method.


### Setup

Let's focus on getting setup working.
Let's add Scopes and RequiredSubmodules.
```python
class SettingsManager(UpdateSettingsManager, SetupSettingsManager, BuildSettingsManager):
    def __init__(self):
        SCRIPT_PATH = os.path.dirname(os.path.abspath(__file__))
        WORKSPACE_PATH = os.path.dirname(os.path.dirname(SCRIPT_PATH))
        self.ws = WORKSPACE_PATH

    def GetWorkspaceRoot(self):
        ''' get WorkspacePath '''
        return self.ws

    def GetActiveScopes(self):
        ''' get scope '''
        return ['raspberrypi']

    def GetPackagesSupported(self):
        ''' return iterable of edk2 packages supported by this build.
        These should be edk2 workspace relative paths '''
        return ("RaspberryPi/RPi3", )

    def GetRequiredSubmodules(self):
        ''' return iterable containing RequiredSubmodule objects.
        If no RequiredSubmodules return an empty iterable
        '''
        return [
            RequiredSubmodule("MU_BASECORE"),
            RequiredSubmodule("Common/MU_OEM"),
            RequiredSubmodule("Common/MU"),
            RequiredSubmodule("Common/TIANO"),
            RequiredSubmodule("Silicon/ARM/MU_TIANO"),
        ]

    def GetArchitecturesSupported(self):
        ''' return iterable of edk2 architectures supported by this build '''
        return ("IA32", "X64")

    def GetTargetsSupported(self):
        ''' return iterable of edk2 target tags supported by this build '''
        return ("DEBUG", "RELEASE")
```

`GetScopes` allows us to get the "scopes" for this platform.
For more information, refer to the feature_sde document.
But in short, it allows us to pick which external dependencies and environmental descriptors apply to this project.
We picked raspberrypi for this project somewhat arbitrarily.
But in the future perhaps we would have a nuget feed with a driver efi inside, that has the scope raspberrypi.

`GetRequiredSubmodules` allows us to specific which submodules we care about.
If we were building certain platforms, we might not care about certain submodules and wouldn't need to bother cloning them.
In this case, we want them all so we return an iterable with all of them.

`GetPackagesSupported` allows us to specify which packages this settings file supports building.
You could use the same settings file to build multiple platforms or select between different platforms.

Now if we call setup, we should see something like this:

```cmd
C:\git\rpi>stuart_setup -c Platform\RaspberryPi\RPi3\PlatformBuild.py
SECTION - Init SDE
SECTION - Loading Plugins
SECTION - Start Invocable Tool
PROGRESS - ## Syncing Git repositories: MU_BASECORE Common/MU_OEM Common/MU Common/TIANO...
PROGRESS - Done.

PROGRESS - ## Checking Git repository: MU_BASECORE...
PROGRESS - Done.

PROGRESS - ## Checking Git repository: Common/MU_OEM...
PROGRESS - Done.

PROGRESS - ## Checking Git repository: Common/MU...
PROGRESS - Done.

PROGRESS - ## Checking Git repository: Common/TIANO...
PROGRESS - Done.

SECTION - Summary
PROGRESS - Success
```

Since we've already setup our submodules, there isn't much to do other than verify the system is in good shape.

Now let's move onto Update.

### Update

Since we defined the scopes, our settings file is already configured.
We can run the setup and it will work just fine.

```cmd
C:\git\rpi> stuart_update -c RaspberryPi\RPi3\PlatformBuild.py
SECTION - Init SDE
SECTION - Loading Plugins
SECTION - Start Invocable Tool
SECTION - Initial update of environment
SECTION -       Updated/Verified 4 dependencies
SECTION - Second pass update of environment
SECTION -       Updated/Verified 4 dependencies
SECTION - Summary
PROGRESS - Success
```

This grabs nuget feed and any other external dependency.
The EDK2 tools are precompiled for you and come down as Mu-Basetools as part of MU_BASECORE.

### Build

If you were to try a platform build, it would fail saying `RuntimeError: UefiBuild Not Found`.
Stuart provides a helper class that scaffolds out the build step.
There's a few ways to implement the UefiBuilder.
It can be a separate class in your `PlatformBuild.py`, it can be the same class as your SettingsManager, or it can be a separate file all together.
For the sake of simplicity, we're going to have it as a separate class in the same file.

``` python
class SettingsManager(UpdateSettingsManager, SetupSettingsManager, BuildSettingsManager):
    def __init__(self):
      ....

#--------------------------------------------------------------------------------------------------------
# Subclass the UEFI builder and add platform specific functionality.
#
class PlatformBuilder(UefiBuilder):
    def SetPlatformEnv(self):
      return 0
```

If we were to run it right now, we would fail because we need to implement one more function in our settings provider: GetPackagesPath.
This is needed to provide the paths to the EDK2 system. We need to provide absolute paths, so we join each path to our workspace root.

```python
class SettingsManager(UpdateSettingsManager, SetupSettingsManager, BuildSettingsManager):
    def __init__(self):
      ....

    def GetPackagesPath(self):
        ''' get module packages path '''
        pp = ['MU_BASECORE', "Common/MU_OEM", 'Common/MU', 'Common/TIANO', "Silicon/ARM/MU_TIANO", "Silicon/Broadcom", "Platform"]
        ws = self.GetWorkspaceRoot()
        return [os.path.join(ws, x) for x in pp]
```

Now when we run it, we'll see that we get an error from our UefiBuild itself.
(Replace your toolchain tag with whatever toolchain you are using.)

``` log
C:\git\rpi> stuart_build -c  Platform\RaspberryPi\RPi3\PlatformBuild.py TOOL_CHAIN_TAG=******
SECTION - Init SDE
SECTION - Loading Plugins
SECTION - Start Invocable Tool
SECTION - Loading Plugins
SECTION - Kicking off build
PROGRESS - Start time: 2019-10-21 10:20:51.834863
PROGRESS - Setting up the Environment
ERROR - Failed to find DSC file
CRITICAL - ParseDscFile failed
CRITICAL - SetEnv failed
PROGRESS - End time: 2019-10-21 10:20:51.889865  Total time Elapsed: 0:00:00
SECTION - Summary
PROGRESS - Error
```

It is failing because we don't define our active platform.

Now you might be asking yourself, wait, what about the basetools and the build.py and environmental variables?
Don't I need to set these up?
Because we're using Project Mu Basecore, this is included and already mapped out for us via enviromental descriptors.
For more information on them, go read about them here: (TODO)
But to briefly illustrate the concept, you can see the section that says Init SDE.
This means the "Self-Describing Environment" started up and found the plugins and environmental descriptors in our code tree.
If you look in the Buildlog.txt file that got generated, you'd see this at the top.

``` log
INFO - Log Started: Saturday, November 02, 2019 09:22PM
SECTION - Init SDE
DEBUG - Loading workspace: C:\git\rpi
DEBUG -   Including scopes: raspberrypi, global-win, global
DEBUG - Adding descriptor 'C:\git\rpi\MU_BASECORE\BaseTools\BinWrappers\WindowsLike\win_build_tools_path_env.json' to the environment with scope 'global-win'.
DEBUG - Adding descriptor 'C:\git\rpi\MU_BASECORE\edk2_core_path_env.json' to the environment with scope 'global'.
DEBUG - Adding descriptor 'C:\git\rpi\MU_BASECORE\BaseTools\basetools_calling_path_env.json' to the environment with scope 'global'.
DEBUG - Adding descriptor 'C:\git\rpi\MU_BASECORE\BaseTools\basetools_path_env.json' to the environment with scope 'global'.
DEBUG - Adding descriptor 'C:\git\rpi\MU_BASECORE\BaseTools\Scripts\basetools_scripts_bin_path_env.json' to the environment with scope 'global'.
DEBUG - Adding descriptor 'C:\git\rpi\MU_BASECORE\BaseTools\Source\Python\basetool_tiano_python_path_env.json' to the environment with scope 'global'.
DEBUG - Adding descriptor 'C:\git\rpi\Common\MU\SharedCryptoPkg\Package\SharedCrypto_ext_dep.json' to the environment with scope 'global'.
DEBUG - Adding descriptor 'C:\git\rpi\MU_BASECORE\BaseTools\Bin\basetools_ext_dep.json' to the environment with scope 'global'.
DEBUG - Adding descriptor 'C:\git\rpi\MU_BASECORE\BaseTools\Bin\nasm_ext_dep.json' to the environment with scope 'global'.
DEBUG - Adding descriptor 'C:\git\rpi\MU_BASECORE\NetworkPkg\SharedNetworking\SharedNetworking_ext_dep.json' to the environment with scope 'global'.
DEBUG - Adding descriptor 'C:\git\rpi\MU_BASECORE\BaseTools\Plugin\WindowsResourceCompiler\WinRcPath_plug_in.json' to the environment with scope 'global-win'.
DEBUG - Adding descriptor 'C:\git\rpi\MU_BASECORE\BaseTools\Plugin\WindowsVsToolChain\WindowsVsToolChain_plug_in.yaml' to the environment with scope 'global-win'.
DEBUG - Adding descriptor 'C:\git\rpi\MU_BASECORE\BaseTools\Plugin\BuildToolsReport\BuildToolsReportGenerator_plug_in.json' to the environment with scope 'global'.
DEBUG - Adding descriptor 'C:\git\rpi\MU_BASECORE\BaseTools\Plugin\Edk2ToolHelper\Edk2ToolHelper_plug_in.json' to the environment with scope 'global'.
DEBUG - Adding descriptor 'C:\git\rpi\MU_BASECORE\BaseTools\Plugin\FdSizeReport\FdSizeReportGenerator_plug_in.json' to the environment with scope 'global'.
DEBUG - Adding descriptor 'C:\git\rpi\MU_BASECORE\BaseTools\Plugin\FlattenPdbs\FlattenPdbs_plug_in.json' to the environment with scope 'global'.
DEBUG - Adding descriptor 'C:\git\rpi\MU_BASECORE\BaseTools\Plugin\OverrideValidation\OverrideValidation_plug_in.json' to the environment with scope 'global'.
DEBUG - Adding descriptor 'C:\git\rpi\MU_BASECORE\BaseTools\Plugin\WindowsCapsuleSupportHelper\WindowsCapsuleSupportHelper_plug_in.json' to the environment with scope 'global'.
DEBUG - Verify 'mu_nasm' returning 'True'.
INFO - C:\git\rpi\MU_BASECORE\BaseTools\Bin\mu_nasm_extdep\Windows-x86-64 was found!
DEBUG - Verify 'Mu-Basetools' returning 'True'.
INFO - C:\git\rpi\MU_BASECORE\BaseTools\Bin\Mu-Basetools_extdep\Windows-x86 was found!
DEBUG - Verify 'Mu-SharedNetworking' returning 'True'.
DEBUG - Verify 'mu_nasm' returning 'True'.
DEBUG - Verify 'Mu-SharedCrypto' returning 'True'.
SECTION - Loading Plugins
DEBUG - Loading Plugin from C:\git\rpi\MU_BASECORE\BaseTools\Plugin\WindowsResourceCompiler\WinRcPath.py
DEBUG - Loading Plugin from C:\git\rpi\MU_BASECORE\BaseTools\Plugin\WindowsVsToolChain\WindowsVsToolChain.py
DEBUG - Loading Plugin from C:\git\rpi\MU_BASECORE\BaseTools\Plugin\BuildToolsReport\BuildToolsReportGenerator.py
DEBUG - Loading Plugin from C:\git\rpi\MU_BASECORE\BaseTools\Plugin\Edk2ToolHelper\Edk2ToolHelper.py
DEBUG - Loading Plugin from C:\git\rpi\MU_BASECORE\BaseTools\Plugin\FdSizeReport\FdSizeReportGenerator.py
DEBUG - Loading Plugin from C:\git\rpi\MU_BASECORE\BaseTools\Plugin\FlattenPdbs\FlattenPdbs.py
DEBUG - Loading Plugin from C:\git\rpi\MU_BASECORE\BaseTools\Plugin\OverrideValidation\OverrideValidation.py
DEBUG - Loading Plugin from C:\git\rpi\MU_BASECORE\BaseTools\Plugin\WindowsCapsuleSupportHelper\WindowsCapsuleSupportHelper.py
DEBUG - Helper Plugin Register: Edk2Tool Helper Functions
DEBUG - Helper Plugin Register: Windows Capsule Support Helper Functions
```

You can see it is adding all the descriptors, which includes environment, external dependencies, and plugins.
We load the basetools, the nasm tools, report generators, and other tools.
We also check our external dependencies and verify they match the version we expect.
For more information, you can read the document about the SDE here: (TODO)

The code is commited as commit at this point as (TODO).

## Setting up UefiBuild

Let's start by setting our DSC and product name
``` python
#--------------------------------------------------------------------------------------------------------
# Subclass the UEFI builder and add platform specific functionality.
#
class PlatformBuilder(UefiBuilder):
    def SetPlatformEnv(self):
        self.env.SetValue("ACTIVE_PLATFORM", "RaspberryPi/RPi3/RPi3.dsc", "Platform Hardcoded")
        self.env.SetValue("PRODUCT_NAME", "RaspberryPi", "Platform Hardcoded")
        self.env.SetValue("TOOL_CHAIN_TAG", "VS2017", "Platform Hardcoded", True)
        return 0

```

We'll need to change any line that starts with `Drivers/OptionRomPkg/...` to `OptionRomPkg/...`
You can place the OptionRomPkg elsewhere, like a git submodule or subfolder, just make sure to update these.

Now if we run the build we get this error.
(You might need to open the `BUILDLOG.txt` to see the whole error)

``` log
INFO - build.py...
INFO -  : error 000E: File/directory not found in workspace
INFO - 	Platform\RaspberryPi\Drivers\LogoDxe\LogoDxe.inf is not found in packages path:
```

In the original project, there were a few errors at the commit we snapped from.
So we'll fix the LogoDxe by using the one from MdeModulePkg

``` dsc
Platform/RaspberryPi/Drivers/LogoDxe/LogoDxe.inf =>  MdeModulePkg/Logo/LogoDxe.inf # MS_CHANGE
```

At this point, you can see the code at commit {TODO}.

If you build again, the next error you'll see in `BUILDLOG.txt` will look like this:

``` log
INFO - build.py...
INFO -  : error 000E: File/directory not found in workspace
INFO - 	Platform\RaspberryPi\RPi3\DeviceTree\bcm2710-rpi-3-b.dtb is not found in packages path:
INFO - 	c:\git\rpi\MU_BASECORE
```

In the edk2-platform there was a DeviceTree folder. We'll use the devicetree from github.

First create the DeviceTree folder. Go to the root of your project.

``` cmd
mkdir Platform\RaspberryPi\DeviceTree
```

Then we'll create two files.
The first is the `Platform/RaspberryPi/DeviceTree/rpi-3-bp_ext_dep.yaml`
Paste this in:

``` yaml
##
# Download the Rpi 3b+ device tree from github
#
# Copyright (c) 2019, Microsoft Corporation
# SPDX-License-Identifier: BSD-2-Clause-Patent
##
{
  "scope": "raspberrypi",
  "type": "web",
  "name": "bcm2710_rpi_3b_plus_devicetree",
  "source": "https://github.com/raspberrypi/firmware/raw/a16470ad47c0ad66d5c98d98e08e49cd148c8fc0/boot/bcm2710-rpi-3-b-plus.dtb",
  "version": "a16470ad47c0ad66d5c98d98e08e49cd148c8fc0",
  'internal_path': "bcm2710-rpi-3-b-plus.dtb",
  "sha256": "253a2e8765aaec5bce6b2ab4e4dbd16107897cc24bb3e248ab5206c09a42cf04",
  "flags": ["set_shell_var", ],
  "var_name": "BCM2710_3BP_DT"
}
```

The second is at `Platform/RaspberryPi/DeviceTree/rpi-3-b_ext_dep.yaml`
Paste this in:

``` yaml
##
# Download the Rpi 3b device tree from github
#
# Copyright (c) 2019, Microsoft Corporation
# SPDX-License-Identifier: BSD-2-Clause-Patent
##
{
  "scope": "raspberrypi",
  "type": "web",
  "name": "bcm2710_rpi_3b_devicetree",
  "source": "https://github.com/raspberrypi/firmware/raw/a16470ad47c0ad66d5c98d98e08e49cd148c8fc0/boot/bcm2710-rpi-3-b.dtb",
  "version": "a16470ad47c0ad66d5c98d98e08e49cd148c8fc0",
  'internal_path': "./bcm2710-rpi-3-b.dtb",
  "sha256": "18ce263a6e1ce4ba7aee759885cb665d61611d2f17cee5b7e91215f7b97d2952",
  "flags": ["set_shell_var", ],
  "var_name": "BCM2710_3B_DT"
}
```

These are two external dependencies that will download the device trees from GitHub.
It includes the SHA256 of the file so it can verify the file downloaded.
Feel free to jump ahead to a newer commit hash, just be aware that you'll need to update the SHA256 (stuart will warn you and show you the new hash).

Let's run an update to fetch our new dependencies.

``` cmd
c:\git\rpi>stuart_update -c Platform\RaspberryPi\RPi3\PlatformBuild.py
```

You'll see some ouput and you'll notice two new folders in the tree.
`Platform\RaspberryPi\DeviceTree\bcm2710_rpi_3b_devicetree_extdep` and `Platform\RaspberryPi\DeviceTree\bcm2710_rpi_3b_plus_devicetree_extdep`.
Inside is the files that we want.

Because the we told to SDE to save where the file was populated into an environmental variable, we'll use that in our FDF.
This means that
```fdf
  # Device Tree support (used by FdtDxe)
  # GUIDs should match gRaspberryPi#####FdtGuid's from the .dec
  #
  FILE FREEFORM = DF5DA223-1D27-47C3-8D1B-9A41B55A18BC {
    SECTION RAW = Platform/RaspberryPi/$(PLATFORM_NAME)/DeviceTree/bcm2710-rpi-3-b.dtb
  }
  FILE FREEFORM = 3D523012-73FE-40E5-892E-1A4DF60F3C0C {
    SECTION RAW = Platform/RaspberryPi/$(PLATFORM_NAME)/DeviceTree/bcm2710-rpi-3-b-plus.dtb
  }
```
becomes
```fdf
  # Device Tree support (used by FdtDxe)
  # GUIDs should match gRaspberryPi#####FdtGuid's from the .dec
  #
  FILE FREEFORM = DF5DA223-1D27-47C3-8D1B-9A41B55A18BC {
    SECTION RAW = $(BCM2710_3B_DT)/bcm2710-rpi-3-b.dtb
  }
  FILE FREEFORM = 3D523012-73FE-40E5-892E-1A4DF60F3C0C {
    SECTION RAW = $(BCM2710_3BP_DT)/bcm2710-rpi-3-b-plus.dtb
  }
```

You can see the code committed at this point at commit: {TODO}

Now if we build it, you'll see this error.

``` log
INFO - build.py...
INFO - c:\git\rpi\Platform\RaspberryPi\RPi3\RPi3.dsc(...): error 4000: Instance of library class [BaseBinSecurityLib] is not found
INFO - 	in [c:\git\rpi\MU_BASECORE\MdeModulePkg\Core\Dxe\DxeMain.inf] [AARCH64]
INFO - 	consumed by module [c:\git\rpi\MU_BASECORE\MdeModulePkg\Core\Dxe\DxeMain.inf]
```

This is because the MU_BASECORE version DxeMain needs BaseBinSecurityLib.
We're going to use the null version.
To our [LibraryClasses.common.DXE_CORE], we're going to add the BaseBinSecurityLib.

``` dsc
[LibraryClasses.common.DXE_CORE]
  ....
  BaseBinSecurityLib|MdePkg/Library/BaseBinSecurityLibNull/BaseBinSecurityLibNull.inf #CHANGE
```

Build again, and you get this error.

``` log
INFO - build.py...
INFO - c:\git\rpi\Platform\RaspberryPi\RPi3\RPi3.dsc(...): error 4000: Instance of library class [MuVariablePolicyHelperLib] is not found
INFO - 	in [c:\git\rpi\MU_BASECORE\MdeModulePkg\Universal\Variable\RuntimeDxe\VariableRuntimeDxe.inf] [AARCH64]
INFO - 	consumed by module [c:\git\rpi\MU_BASECORE\MdeModulePkg\Universal\Variable\RuntimeDxe\VariableRuntimeDxe.inf]
```

Project Mu adds the variable policy, which is a fantastic bit of code that does some real neat stuff.
For more information, go check it out here (TODO).

Anyway- so to our DSC, we're going to add some extra classes

```dsc
[LibraryClasses.common]
    ...
    # Project MU dependencies
    MuVariablePolicyHelperLib|MdeModulePkg/Library/MuVariablePolicyHelperLib/MuVariablePolicyHelperLib.inf # CHANGE
    SecurityLockAuditLib|MdeModulePkg/Library/SecurityLockAuditDebugMessageLib/SecurityLockAuditDebugMessageLib.inf # CHANGE
```



## Future Work

Many of the capabilities and features of Stuart aren't detailed or explored here.
One area not discussed in detail or shown is external dependencies.
In the future, it would be beneficial to move the ARM Trusted Firmware (ATF) binary blob into an external dependency.
This means you can have a separate build pipeline for that which packages it up into a nuget or github release, which your platform consumes.
It addition to not having to carry a binary in your build tree, it makes the version of the binary trivial to track.
