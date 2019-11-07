# Windows Subsystem for Linux for UEFI Development

There are many firmware projects that require GCC.
While support for GCC on windows exists, many of the UEFI community use Linux as their main dev machines.
This guide is focued on setting up a Linux WSL for UEFI development.
This guide also uses Visual Studio Code as it has fantastic capabilities that makes working in linux much easier
If you have a linux machine, you can follow the later half of this guide to just setup the environment.

For reference, this tutorial was written for a 1903 version of Windows.

The best documentation at time of writing can be found: https://docs.microsoft.com/en-us/windows/wsl/wsl2-install

## Getting Started

Following the guide, we need to check the minimum version requirements.
Check the document as mentioned to find the Windows version needed for WSL.

Install the optional windows components through powershell.
These commands may change, so check the document.
But the commands to run in an Admin Powershell window were these:

``` powershell
Enable-WindowsOptionalFeature -Online -FeatureName Microsoft-Windows-Subsystem-Linux
Enable-WindowsOptionalFeature -Online -FeatureName VirtualMachinePlatform
```

You might need to reboot to fully enable the WSL subsystem.
Once you are rebooted, we can setup our distro.
We are using Ubuntu-18.04 LTS.
We now need to set it to use WSLv2.
You use either of these commands

``` powershell
wsl --set-default-version 2
```

This will set the default WSL environment as version 2.
Or you can set a specific distro to be version 2.

``` powershell
wsl --set-version Ubuntu-18.04 2
```

This will take a few minutes. As it converts the distro to WSLv2.
You can check to make sure the converstion was successful.

``` powershell
wsl --list --verbose
```
You should see something like this:

```
 NAME            STATE           VERSION
* Ubuntu-18.04    Stopped         2
```

## Starting your WSL Environment

Starting your new environment is easy.
Open the Ubuntu-18.04 app in your start menu or type `wsl` into the command window (note that this will launch your default instance, which may not be Ubuntu-18.04 if you have multiple environments installed).

When you first start the environment, it will do initial first time setup that may take a few minutes.
It will prompt you for a new username and password.
This can be unique from your windows username and password.

## Setting up EDK2

The guide here (https://github.com/tianocore/tianocore.github.io/wiki/Using-EDK-II-with-Native-GCC) is pretty fantastic and most of the advice applies.

Run this command in WSL to install the pieces needed.

```bash
sudo apt-get install build-essential uuid-dev iasl git gcc-5 nasm python3-distutils
```

If you aren't use Project Mu's BASECORE, you'll need to compile the basetools.


## Setting up VS Code

Visual Studio code makes developing in WSL much easier.
This guide here is pretty informative: https://code.visualstudio.com/docs/remote/wsl

Install Visual Studio Code in your windows environment.
Then install the Remote Development VS Code extension.

You should see the installation of the VS Code server if you are doing this for the first time.
If you don't see it, make sure your extension is installed properly.

Naviagate to the folder you want to use in your WSL terminal and then run code

```bash
cd my_project_folder
code .
```

## Using VS Code

You can use your VS Code editor just like you're editing locally.
Opening a terminal in VS Code opens a WSL window, which makes compilation much easier.

## Questions

If you have any questions or comments, feel free to leave an issue on our github repo here (TODO)
