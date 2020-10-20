# Porting a platform to EDK2 PyTools

You've probably seen the great promises that EDK2 Pytools gives and wondered how
to get started on a platform you already have. There are many places you could
be coming from but you likely have some sort of automated work flow that calls
edk2's build at some point. In this guide, two paths will be discussed and one
will be shown.

In this guide, we will building a platform from EDK2-Platforms, the humble
Raspberry Pi 3. This is because you likely have one lying around somewhere or
can buy it online for fairly cheap. It is also a simpler platform compared to
many intel based ones while still being large enough to show the benefits of
Stuart.

This process is documented in the repo (TODO).

This guide shows one way to structure your platform code but there are many
different approaches out there. Stuart is flexible and versatile enough to be
able to be adapted to many workflows. You are encouraged to experiment and see
what works best for you and your team.

Since the Raspberry Pi project in EDK2-Platforms uses GCC, we will also be using
WSLv2 (Windows Subsystem for Linux). If you're on a linux machine, you should be
able to follow this tutorial.

For information on how to use WSL, refer to the guide using_wsl.md

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

Next we'll add our `pip_requirements.txt` file to keep our pip modules in sync
with our project. You can optionally setup a virtual environment to keep
different versions of pip modules, but that is left up to the reader.

```pip
edk2-pytool-library
edk2-pytool-extensions
```

You're welcome to snap to a particular version by adding `==0.12.2` or whatever
version you want to keep after the pip name.

Next you'll need to install the pip modules. If you see that the pip isn't
installed, check out our guide to setting up WSL (or any linux distribution).

Once your pip is setup, install the requirements by executing this:

```bash
pip3 install -r pip_requirements.txt
```

Make sure you're using python 3 as opposed to python 2.

## Submodules

One of the best ways to keep track of other git projects is through submodules.
We'll add submodules for the edk2 projects we want to use.

Another option would be use the Microsoft Project Mu fork of EDK2. The parts
that it contains are:

- BASECORE: this contains the base packages like MdeModulePkg and MdePkg
- MU_PLUS: this has the extra stuff that Mu provides like DFCI, GraphicsPkg, and
  SharedCrypto.
- TIANO_PLUS: this has things like ShellPkg and FmpDevicePkg.
- OEM_SAMPLE: this contains things that an OEM might find useful like a
  FrontPage application and a Boot menu.

At the end of this document, we will detail what all is required to move over to
Project Mu. It brings some powerful things but also requires us to add some
pieces to support the new functionality.

In the meantime we'll use EDK2 as it is likely what people are familiar with.

```bash
git submodule add https://github.com/tianocore/edk2.git edk2
git submodule add https://github.com/tianocore/edk2-platforms.git platforms
git submodule add https://github.com/tianocore/edk2-non-osi.git non-osi
```

To be clear, **don't use EDK2 and MU_BASECORE in the same tree**. They overlap
since MU_BASECORE has EDK2 as an upstream.

We'll want to make sure we have the same commit so for each of the submodules,
we'll checkout a specific commit hash.

```bash
cd ~/rpi
cd edk2
git checkout edk2-stable201911
cd ..
cd platforms
git checkout 0e6e3fc4af678d5241b4e8f8c14c126212ff2522
cd ..
cd non-osi
git checkout d580026dbbe87c081dce26b1872df83fa79cd740
```

At this point, we're almost ready. Our tree should look like this:

```tree
rpi
|   .gitignore
|   .gitmodules
|   pip_requirements.txt
|
|---edk2
|   |...
|
|---platform
|   |
|   |---Drivers
|   |---Platform
|   |---Silicon
|
|---non-osi
|   |---Emulator
|   |---Platform
|   |---Silicon
|
```

You can see the files at the commit here (TODO)

## The settings file

The guide is written for pytool-extensions v0.12 and some things may have
changed since this was written. Please refer to the release notes to see what
has changed.

Stuart needs a settings file to configure itself. It helps define where the
workspace root is and what sort of things we need to initialize.  Since we are
using the build in invocables, we'll need to implement three settings managers:
UpdateSettingsManager, SetupSettingsManager, BuildSettingsManager.

If you're unfamiliar with what an invocable or a settings file is, please refer
to our documentation.

Let's add a file: `RpiPlatformBuild.py`. This will be a settings manager for
stuart

```python
##
## Script to Build Raspberry Pi 3/4 firmware
##
import os
import logging
from edk2toolext.environment.uefi_build import UefiBuilder
from edk2toolext.invocables.edk2_platform_build import BuildSettingsManager
from edk2toolext.invocables.edk2_setup import SetupSettingsManager
from edk2toolext.invocables.edk2_update import UpdateSettingsManager
from edk2toollib.utility_functions import GetHostInfo
from edk2toolext.invocables.edk2_setup import RequiredSubmodule

#
#==========================================================================
# PLATFORM BUILD ENVIRONMENT CONFIGURATION
#
class RpiSettingsManager(UpdateSettingsManager, SetupSettingsManager, BuildSettingsManager):
    def __init__(self):
        SCRIPT_PATH = os.path.dirname(os.path.abspath(__file__))
        self.ws = SCRIPT_PATH

    def GetWorkspaceRoot(self):
        ''' get WorkspacePath '''
        return self.ws

```

For more information on settings managers, please refer to the documentation.
Right now we are importing the needed classes from the pytools as well as
defining a class which will provide the settings to stuart.

The three invocables that we have implemented settings for are `stuart_build`,
`stuart_update`, and `stuart_setup`. If you were to call one of these, you'd get
an error on a non-implemented method.

Since our settings provider it is still missing a lot of functionality. While it
can now set up our workspace path, which should resolve to your root `rpi`
folder, there's still different methods of each settings manager that we haven't
implemented yet.

`GetWorkspaceRoot` returns a path to the root of your workspace. In this case,
`rpi` is the folder in question, which where our PlatformBuild.py is.

### Setup

Let's focus on getting setup working. Let's add Scopes and RequiredSubmodules.

```python
...

class RpiSettingsManager(UpdateSettingsManager, SetupSettingsManager, BuildSettingsManager):
    def __init__(self):
        SCRIPT_PATH = os.path.dirname(os.path.abspath(__file__))
        self.ws = SCRIPT_PATH

    def GetWorkspaceRoot(self):
        ''' get WorkspacePath '''
        return self.ws

    def GetActiveScopes(self):
        ''' get scope '''
        return ['raspberrypi', 'gcc_aarch64_linux']

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
        return ("AARCH64")

    def GetTargetsSupported(self):
        ''' return iterable of edk2 target tags supported by this build '''
        return ("DEBUG", "RELEASE")
```

`GetScopes` allows us to get the "scopes" for this platform. For more
information, refer to the feature_sde document. But in short, it allows us to
pick which external dependencies and environmental descriptors apply to this
project. We picked raspberrypi for this project somewhat arbitrarily. But in the
future perhaps we would have a nuget feed with a driver efi inside, that has the
scope raspberrypi.

`GetRequiredSubmodules` allows us to specific which submodules we care about. If
we were building certain platforms, we might not care about certain submodules
and wouldn't need to bother cloning them. In this case, we want them all so we
return an iterable with all of them.

`GetPackagesSupported` allows us to specify which packages this settings file
supports building. You could use the same settings file to build multiple
platforms or select between different platforms.

Now if we call setup, we should see something like this:

```cmd
~/rpi$ stuart_setup -c RpiPlatformBuild.py
SECTION - Init SDE
SECTION - Loading Plugins
SECTION - Start Invocable Tool
PROGRESS - ## Syncing Git repositories: edk2 non-osi platforms...
PROGRESS - Done.

PROGRESS - ## Checking Git repository: edk2...

PROGRESS - ## Checking Git repository: non-osi...

PROGRESS - ## Checking Git repository: platforms...

PROGRESS - Done.

SECTION - Summary
PROGRESS - Success
```

You'll also notice that there's a new folder in your tree: `Build`. In the setup
phase, we don't have an output folder from the DSC yet, so we put logs into that
folder. Inside you'll notice is a SETUPLOG. It just contains verbose information
about this process. For example, you'll see that it cloned the submodules in
EDK2 CryptoPkg.

Since we've already setup our submodules, there isn't much to do other than
verify the system is in good shape.

Now let's move onto Update.

### Update

Since we defined the scopes, our settings file is already configured. We can run
the update and it will work just fine.

```cmd
~/rpi$ stuart_update -c RpiPlatformBuild.py
SECTION - Init SDE
SECTION - Loading Plugins
SECTION - Start Invocable Tool
SECTION - Initial update of environment
SECTION -       Updated/Verified 1 dependencies
SECTION - Second pass update of environment
SECTION -       Updated/Verified 1 dependencies
SECTION - Summary
PROGRESS - Success
```

Stuart has something called the Self-Describing Environment or SDE. This allows
Stuart to infer the external dependencies, path configurations, and
environmental variables from the code tree itself. This ends up being an
incredibly powerful tool. For more information, please refer to our guide on
using the SDE.

Update verifies and updates what is in the SDE. This grabs nuget packages and
any other dependencies. EDK2 has a few external dependencies, such as GCC for
ARM/AARCH64, IASL, and NASM. If you were to build without doing an update, the
SDE would stop you and report that some external dependencies weren't satisfied.
It would prompt you to do an update.

Optionally, we'll be adding the Basetools that are precompiled through a release
pipeline. However, this is an optional step and if you wish, you can use
basetools that you've already compiled yourself. Normally, this would go inside
the submodules or in the basetools folder itself. However in this case, we'll
create a new folder called `dependencies`.

```bash
cd ~/rpi
mkdir dependencies
cd dependencies
touch basetoolsbin_ext_dep.yaml
```

Inside the file goes:

```yaml
##
# Download the compiled basetools from nuget.org
# - Nuget package contains different binaries based on the host os
# Set this downloaded folder on path
# Set a Shell variable to this path
#
# Copyright (c) 2019, Microsoft Corporation
# SPDX-License-Identifier: BSD-2-Clause-Patent
##
{
  "scope": "global",
  "type": "nuget",
  "name": "Mu-Basetools",
  "source": "https://api.nuget.org/v3/index.json",
  "version": "2019.11.0",
  "flags": ["set_shell_var", "set_path", "host_specific"],
  "var_name": "EDK_TOOLS_BIN",
}
```

Now we can re-run update and see the new external dependency get pulled down.

```bash
~/rpi$ stuart_update -c RpiPlatformBuild.py
SECTION - Init SDE
SECTION - Loading Plugins
SECTION - Start Invocable Tool
SECTION - Initial update of environment
SECTION -       Updated/Verified 2 dependencies
SECTION - Second pass update of environment
SECTION -       Updated/Verified 2 dependencies
SECTION - Summary
PROGRESS - Success
```

### Build

If you were to try a platform build, it would fail saying `RuntimeError:
UefiBuild Not Found`. Stuart provides a helper class that scaffolds out the
build step. There's a few ways to implement the UefiBuilder. It can be a
separate class in your `PlatformBuild.py`, it can be the same class as your
SettingsManager, or it can be a separate file all together. For the sake of
simplicity, we're going to have it as a separate class in the same file.

```python
...

class SettingsManager(UpdateSettingsManager, SetupSettingsManager, BuildSettingsManager):
    def __init__(self):
      ....

#--------------------------------------------------------------------------------------------------------
# Subclass the UEFI builder and add platform specific functionality.
#
class PlatformBuilder(UefiBuilder):
    def SetPlatformEnv(self):
      self.env.SetValue("ACTIVE_PLATFORM", "Platform/RaspberryPi/RPi3/RPi3.dsc", "Platform Hardcoded")
      return 0
```

If we were to run it right now, we would fail because we need to implement one
more function in our settings provider: GetPackagesPath. This is needed to
provide the paths to the EDK2 system. We need to provide absolute paths, so we
join each path to our workspace root.

```python
class SettingsManager(UpdateSettingsManager, SetupSettingsManager, BuildSettingsManager):
    def __init__(self):
      ....
      def GetTargetsSupported(self):
        ....

    def GetPackagesPath(self):
        ''' get module packages path '''
        pp = ['edk2', "non-osi", 'platforms']
        ws = self.GetWorkspaceRoot()
        return [os.path.join(ws, x) for x in pp]
```

Now when we run it, we'll see that we get an error from our UefiBuild itself.
(Replace your toolchain tag with whatever toolchain you are using.)

```log
~/rpi$ stuart_build -c  Platform/RaspberryPi/RPi3/PlatformBuild.py TOOL_CHAIN_TAG=******
SECTION - Init SDE
SECTION - Loading Plugins
SECTION - Start Invocable Tool
SECTION - Loading Plugins
SECTION - Kicking off build
PROGRESS - Start time: 2019-12-02 14:37:17.515761
PROGRESS - Setting up the Environment
PROGRESS - Running Pre Build
PROGRESS - Running Build DEBUG
ERROR - Compiler #2000 from :   Invalid parameter
CRITICAL - Build failed
PROGRESS - End time: 2019-12-02 14:37:18.313707  Total time Elapsed: 0:00:00
SECTION - Summary
PROGRESS - Error
```

It is failing because we haven't defined the architecture we are building and
many other things.

Now you might be asking yourself, wait, how are we already compiling? What about
the basetools, the CONF folder, the build tools and environmental variables?
Don't I need to set these up? Nope. Stuart does it for you. You can see in your
Build folder there should be a `BUILDLOG.txt`, `SETUPLOG.txt`, and
`UPDATELOG.txt`. The goal there is to make sure you can reliably figure out what
is going on when things do go wrong. For more information on them, go read about
them here: (TODO) The goal of Stuart is to be as magical as possible while still
being transparent and understandable as possible.

```log
INFO - Log Started: Saturday, November 02, 2019 09:22PM
SECTION - Init SDE
DEBUG - Loading workspace: C:/git/rpi
DEBUG -   Including scopes: raspberrypi, global-win, global
DEBUG - Adding descriptor 'C:/git/rpi/MU_BASECORE/BaseTools/BinWrappers/WindowsLike/win_build_tools_path_env.json' to the environment with scope 'global-win'.
DEBUG - Adding descriptor 'C:/git/rpi/MU_BASECORE/edk2_core_path_env.json' to the environment with scope 'global'.
DEBUG - Adding descriptor 'C:/git/rpi/MU_BASECORE/BaseTools/basetools_calling_path_env.json' to the environment with scope 'global'.
DEBUG - Adding descriptor 'C:/git/rpi/MU_BASECORE/BaseTools/basetools_path_env.json' to the environment with scope 'global'.
DEBUG - Adding descriptor 'C:/git/rpi/MU_BASECORE/BaseTools/Scripts/basetools_scripts_bin_path_env.json' to the environment with scope 'global'.
DEBUG - Adding descriptor 'C:/git/rpi/MU_BASECORE/BaseTools/Source/Python/basetool_tiano_python_path_env.json' to the environment with scope 'global'.
DEBUG - Adding descriptor 'C:/git/rpi/Common/MU/SharedCryptoPkg/Package/SharedCrypto_ext_dep.json' to the environment with scope 'global'.
DEBUG - Adding descriptor 'C:/git/rpi/MU_BASECORE/BaseTools/Bin/basetools_ext_dep.json' to the environment with scope 'global'.
DEBUG - Adding descriptor 'C:/git/rpi/MU_BASECORE/BaseTools/Bin/nasm_ext_dep.json' to the environment with scope 'global'.
DEBUG - Adding descriptor 'C:/git/rpi/MU_BASECORE/NetworkPkg/SharedNetworking/SharedNetworking_ext_dep.json' to the environment with scope 'global'.
DEBUG - Adding descriptor 'C:/git/rpi/MU_BASECORE/BaseTools/Plugin/WindowsResourceCompiler/WinRcPath_plug_in.json' to the environment with scope 'global-win'.
DEBUG - Adding descriptor 'C:/git/rpi/MU_BASECORE/BaseTools/Plugin/WindowsVsToolChain/WindowsVsToolChain_plug_in.yaml' to the environment with scope 'global-win'.
DEBUG - Adding descriptor 'C:/git/rpi/MU_BASECORE/BaseTools/Plugin/BuildToolsReport/BuildToolsReportGenerator_plug_in.json' to the environment with scope 'global'.
DEBUG - Adding descriptor 'C:/git/rpi/MU_BASECORE/BaseTools/Plugin/Edk2ToolHelper/Edk2ToolHelper_plug_in.json' to the environment with scope 'global'.
DEBUG - Adding descriptor 'C:/git/rpi/MU_BASECORE/BaseTools/Plugin/FdSizeReport/FdSizeReportGenerator_plug_in.json' to the environment with scope 'global'.
DEBUG - Adding descriptor 'C:/git/rpi/MU_BASECORE/BaseTools/Plugin/FlattenPdbs/FlattenPdbs_plug_in.json' to the environment with scope 'global'.
DEBUG - Adding descriptor 'C:/git/rpi/MU_BASECORE/BaseTools/Plugin/OverrideValidation/OverrideValidation_plug_in.json' to the environment with scope 'global'.
DEBUG - Adding descriptor 'C:/git/rpi/MU_BASECORE/BaseTools/Plugin/WindowsCapsuleSupportHelper/WindowsCapsuleSupportHelper_plug_in.json' to the environment with scope 'global'.
DEBUG - Verify 'mu_nasm' returning 'True'.
INFO - C:/git/rpi/MU_BASECORE/BaseTools/Bin/mu_nasm_extdep/Windows-x86-64 was found!
DEBUG - Verify 'Mu-Basetools' returning 'True'.
INFO - C:/git/rpi/MU_BASECORE/BaseTools/Bin/Mu-Basetools_extdep/Windows-x86 was found!
DEBUG - Verify 'Mu-SharedNetworking' returning 'True'.
DEBUG - Verify 'mu_nasm' returning 'True'.
DEBUG - Verify 'Mu-SharedCrypto' returning 'True'.
SECTION - Loading Plugins
DEBUG - Loading Plugin from C:/git/rpi/MU_BASECORE/BaseTools/Plugin/WindowsResourceCompiler/WinRcPath.py
DEBUG - Loading Plugin from C:/git/rpi/MU_BASECORE/BaseTools/Plugin/WindowsVsToolChain/WindowsVsToolChain.py
DEBUG - Loading Plugin from C:/git/rpi/MU_BASECORE/BaseTools/Plugin/BuildToolsReport/BuildToolsReportGenerator.py
DEBUG - Loading Plugin from C:/git/rpi/MU_BASECORE/BaseTools/Plugin/Edk2ToolHelper/Edk2ToolHelper.py
DEBUG - Loading Plugin from C:/git/rpi/MU_BASECORE/BaseTools/Plugin/FdSizeReport/FdSizeReportGenerator.py
DEBUG - Loading Plugin from C:/git/rpi/MU_BASECORE/BaseTools/Plugin/FlattenPdbs/FlattenPdbs.py
DEBUG - Loading Plugin from C:/git/rpi/MU_BASECORE/BaseTools/Plugin/OverrideValidation/OverrideValidation.py
DEBUG - Loading Plugin from C:/git/rpi/MU_BASECORE/BaseTools/Plugin/WindowsCapsuleSupportHelper/WindowsCapsuleSupportHelper.py
DEBUG - Helper Plugin Register: Edk2Tool Helper Functions
DEBUG - Helper Plugin Register: Windows Capsule Support Helper Functions
```

You can see it is adding all the descriptors, which includes environment,
external dependencies, and plugins. We load the basetools, the nasm tools,
report generators, and other tools. We also check our external dependencies and
verify they match the version we expect.

The code is commited as commit at this point as (TODO).

## Setting up UefiBuild

Let's start by setting our DSC and product name

```python
...
#--------------------------------------------------------------------------------------------------------
# Subclass the UEFI builder and add platform specific functionality.
#
class PlatformBuilder(UefiBuilder):
    def SetPlatformEnv(self):
        self.env.SetValue("ACTIVE_PLATFORM", "Platform/RaspberryPi/RPi3/RPi3.dsc", "Platform Hardcoded")
        self.env.SetValue("PRODUCT_NAME", "RaspberryPi", "Platform Hardcoded")
        self.env.SetValue("TARGET_ARCH", "AARCH64", "Platform Hardcoded")
        os = GetHostInfo().os
        if os.lower() == "windows":
            self.env.SetValue("TOOL_CHAIN_TAG", "VS2017", "Platform Hardcoded", True)
        else:
            self.env.SetValue("TOOL_CHAIN_TAG", "GCC5", "Platform Hardcoded", True)

        return 0

```

At this point, when we run a build, we get this:

```log
~/rpi$ stuart_update -c RpiPlatformBuild.py TOOL_CHAIN_TAG=GCC5
SECTION - Init SDE
SECTION - Loading Plugins
SECTION - Start Invocable Tool
SECTION - Initial update of environment
SECTION -       Updated/Verified 2 dependencies
SECTION - Second pass update of environment
SECTION -       Updated/Verified 2 dependencies
SECTION - Summary
PROGRESS - Success
~/rpi$ stuart_build -c RpiPlatformBuild.py TOOL_CHAIN_TAG=GCC5
SECTION - Init SDE
SECTION - Loading Plugins
SECTION - Start Invocable Tool
SECTION - Loading Plugins
SECTION - Kicking off build
PROGRESS - Start time: 2019-12-02 14:51:54.604488
PROGRESS - Setting up the Environment
PROGRESS - Running Pre Build
PROGRESS - Running Build DEBUG
PROGRESS - Running Post Build
PROGRESS - End time: 2019-12-02 14:52:51.642897  Total time Elapsed: 0:00:57
SECTION - Log file is located at: ~/rpi/Build/BUILDLOG.txt
SECTION - Summary
PROGRESS - Success
```

Fantastic!

If you want, you can call it a day and load your new ROM on an SD card and boot
your UEFI powered Raspberry Pi.

However, there are a few things we'd like to tweak.

Right now, the DeviceTree image is a binary file checked into the non-osi git
repo. A better approach might be using the image directly. Ideally, it would be
from a Nuget feed or other auditable release pipeline.

First we'll create a new file

```cmd
mkdir Platform/RaspberryPi/DeviceTree
```

Then we'll create two files. The first is the
`dependencies/rpi-3-bp_ext_dep.yaml`

```bash
touch dependencies/rpi-3-bp_ext_dep.yaml
```

Paste this in:

```yaml
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
  "internal_path": "bcm2710-rpi-3-b-plus.dtb",
  "sha256": "253a2e8765aaec5bce6b2ab4e4dbd16107897cc24bb3e248ab5206c09a42cf04",
  "flags": ["set_build_var"],
  "var_name": "BLD_*_BCM2710_3BP_DT",
}
```

The second is at `dependencies/rpi-3-b_ext_dep.yaml`

```bash
touch dependencies/rpi-3-b_ext_dep.yaml
```

Paste this in:

```yaml
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
  "internal_path": "./bcm2710-rpi-3-b.dtb",
  "sha256": "18ce263a6e1ce4ba7aee759885cb665d61611d2f17cee5b7e91215f7b97d2952",
  "flags": ["set_build_var"],
  "var_name": "BLD_*_BCM2710_3B_DT",
}
```

These are two external dependencies that will download the device trees from
GitHub. It includes the SHA256 of the file so it can verify the file downloaded.
Feel free to jump ahead to a newer commit hash, just be aware that you'll need
to update the SHA256 (stuart will warn you and show you the new hash).

Let's run an update to fetch our new dependencies.

```bash
~/rpi$ stuart_update -c RpiPlatformBuild.py
```

You'll see some ouput and you'll notice two new folders in the tree.
`bcm2710_rpi_3b_devicetree_extdep` and `bcm2710_rpi_3b_plus_devicetree_extdep`.
Inside is the files that we want.

Because the we told to SDE to save where the file was populated into an
environmental variable, we'll use that in our FDF.

This means that

```fdf
  # Device Tree support (used by FdtDxe)
  # GUIDs should match gRaspberryPi#####FdtGuids from the .dec
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
  # MU_CHANGE START
  # Device Tree support (used by FdtDxe)
  # GUIDs should match gRaspberryPi#####FdtGuids from the .dec
  #
  FILE FREEFORM = DF5DA223-1D27-47C3-8D1B-9A41B55A18BC {
    SECTION RAW = $(BCM2710_3B_DT)/bcm2710-rpi-3-b.dtb
  }
  FILE FREEFORM = 3D523012-73FE-40E5-892E-1A4DF60F3C0C {
    SECTION RAW = $(BCM2710_3BP_DT)/bcm2710-rpi-3-b-plus.dtb
  }
  # MU_CHANGE END
```

We can now build it and it will stay in sync with the upstream device tree. We
could apply this technique to the ATF (Arm Trusted Firmware). Since it comes
from the same place.

## Notes

As of time of writing, VS2017 doesn't support the ASM files used in this
project. So you'll need to use GCC. Using WSL is the recommended course for
windows, but MacOS and Linux machines can follow the guide here.

## Project Mu

Using Project Mu is fairly easy. Instead of adding edk2, you would add these
repos instead.

You can add these all by running this command:

```bash
git submodule add https://github.com/Microsoft/mu_basecore.git MU_BASECORE
git submodule add https://github.com/Microsoft/mu_plus.git Common/MU
git submodule add https://github.com/Microsoft/mu_tiano_plus.git Common/TIANO
git submodule add https://github.com/Microsoft/mu_oem_sample.git Common/MU_OEM
git submodule add https://github.com/microsoft/mu_silicon_arm_tiano.git Silicon/ARM/MU_TIANO
git submodule add https://github.com/tianocore/edk2-platforms.git platforms
git submodule add https://github.com/tianocore/edk2-non-osi.git non-osi
```

Refer to the documentation in the various repos for the informations on how to
enable features such as DFCI, SharedCrypto, etc.

## Future Work

Many of the capabilities and features of Stuart aren't detailed or explored
here. One area not discussed in detail or shown is external dependencies. In the
future, it would be beneficial to move the ARM Trusted Firmware (ATF) binary
blob into an external dependency. This means you can have a separate build
pipeline for that which packages it up into a nuget or github release, which
your platform consumes. It addition to not having to carry a binary in your
build tree, it makes the version of the binary trivial to track.
