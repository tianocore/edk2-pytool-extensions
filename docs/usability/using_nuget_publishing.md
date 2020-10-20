# NugetPublishing

Tool to help create and publish nuget packages for Project Mu resources

## Usage

See NugetPublishing -h

## OPTIONAL: host_specific folders

The possible different setups for the host are: OS: Linux, Windows, Java
Architecture: x86 or ARM Highest Order Bit: 32 or 64

Before the path to the NuGet package contents is published, the Python
environment can look inside at several sub-folders and decide which one to use
based on the Host OS, highest order bit available, and the architecture of the
processor. To do so, add "host_specific" to your flags like so:

```inf
"flags": ["host_specific"],
```

If this flag is present, the environment will make a list possible sub-folders
that would be acceptable for the host machine. For this example, a 64 bit
Windows machine with an x86 processor was used:

1. Windows-x86-64
2. Windows-x86
3. Windows-64
4. x86-64
5. Windows
6. x86
7. 64

The environment will look for these folders, following this order, and select
the first one it finds. If none are found, the flag will be ignored.

## Operations

Nuget Publish supports four operations:

* New: creates a new configuration file
* Pack: creates a packed nuspec using a configuration file
* Push: pushes the packed nuspec to NuGet.org
* PackAndPush: packs and then pushes

You can call one of these functions by calling:

```cmd
nuget-publish -Operation New
```

You can get more information by adding -h to the operation you want to know
about.

```cmd
nuget-publish -Operation Push -h
```

## Tags

For Pack as well as PackAndPush, you can add tags to the nuspec package that is
created. This can be done through the `--t` or the `-tag` option on Pack or
PackAndPush.

This looks like:

```cmd
nuget-publish -Operation Pack ... -t TAG1 -t TAG2,TAG3
```

You can also add the tags into your config.json file via the attribute
`tag_string`. It should be a space separate list of words.

## Authentication

For publishing most service providers require authentication.  The **--ApiKey**
parameter allows the caller to supply a unique key for authorization.  There are
numerous ways to authenticate. For example

* Azure Dev Ops:
  * VSTS credential manager.  In an interactive session a dialog will popup for
    the user to login
  * Tokens can also be used as the API key.  Go to your account page to generate
    a token that can push packages
* NuGet.org
  * Must use an API key.  Go to your account page and generate a key.

## Pushing to an Authenticated Stream

If you have a specific credential provider executable needed to push to your
stream, you'll need to follow the instructions
[here](https://docs.microsoft.com/en-us/nuget/reference/extensibility/nuget-exe-credential-providers)
to make the executable available to find. You can add it to
%LocalAppData%\NuGet\CredentialProvider or you can add an environmental variable
NUGET_CREDENTIALPROVIDERS_PATH with the location of your provider. If you have
multiple, they can be semicolon separated.

## Example: Creating new config file for first use

This will create the config files and place them in the current directory:

```cmd
NugetPublishing --Operation New --Name iasl --Author ProjectMu --ConfigFileFolderPath . --Description "Description of item." --FeedUrl https://api.nuget.org/v3/index.json --ProjectUrl http://aka.ms/projectmu --LicenseType BSD2
```

For help run: `NugetPublishing --Operation New --help`

## Example: Publishing new version of tool

Using an existing config file publish a new iasl.exe.  See the example file
**iasl.config.json**

1. Download version from acpica.org
2. Unzip
3. Make a new folder (for my example I will call it "new")
4. Copy the assets to publish into this new folder (in this case just iasl.exe)
5. Run the iasl.exe -v command to see the version.
6. Open cmd prompt in the NugetPublishing dir
7. Pack and push (here is my example command. )

  ```cmd
  NugetPublishing --Operation PackAndPush --ConfigFilePath iasl.config.json --Version 20180209.0.0 --InputFolderPath "C:\temp\iasl-win-20180209\new"  --ApiKey <your key here>
  ```
