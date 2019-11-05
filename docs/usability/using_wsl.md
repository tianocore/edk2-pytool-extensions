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
Open the Ubuntu-18.04 app in your start menu or type wsl into the command window (note that this will launch your default instance, which may not be Ubuntu-18.04 if you have multiple environments installed).

When you first start the environment, it will do initial first time setup that may take a few minutes.
It will prompt you for a new username and password.
This can be unique from your windows username and password.
