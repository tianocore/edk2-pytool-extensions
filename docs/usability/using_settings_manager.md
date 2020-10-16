
# Settings manager

Each edk2 invocable has an abstract definition of a Settings Manager class that
provides needed information such as scope, repositories, command-line options,
and other things. This allows scopes to be dynamic but in a standardized way.
Below is a sample implementation of a settings manager for your reference.

This is an implementation of both Update and Setup Settings Managers using
multiple inheritance. You can see that they add their own command line argument
`--production` that is used to toggle the use of the `production` scope. For any
given invocable, you can pass `-h` or `--help` to show a list of available
command line options. If you call `-c <path> --help` this list will also include
command line options provided from the settings file you provided.

These examples are for building a platform; which needs an instance of
UpdateSettingsManager, SetupSettingsManager, BuildSettingsManager, and
UefiBuilder.

## All settings are grouped together

```python

class SettingsManager(UpdateSettingsManager, SetupSettingsManager, BuildSettingsManager):
    def __init__(self):
        SCRIPT_PATH = os.path.dirname(os.path.abspath(__file__))
        self.WORKSPACE_PATH = os.path.dirname(os.path.dirname(SCRIPT_PATH))
        self.PRODUCTION_SCOPE = ('production', )
        self.BASE_SCOPE = ('imxfamily', 'imx8')
        self.production = None

    def GetProjectScope(self):
        ''' get scope '''
        SCOPE = self.BASE_SCOPE
        if self.production:
            SCOPE += self.PRODUCTION_SCOPE
        return SCOPE

    def GetWorkspaceRoot(self):
        ''' get WorkspacePath '''
        return self.WORKSPACE_PATH

    def GetPackagesPath(self):
        ''' Return a list of workspace relative paths that should be mapped as edk2 PackagesPath '''
        return ['MU_BASECORE','Silicon/ARM/NXP', 'Common/MU','Common/MU_TIANO', 'Common/MU_OEM_SAMPLE','Silicon/ARM/MU_TIANO']

    def GetRequiredSubmodules(self):
        ''' return iterable containing RequiredSubmodule objects.
        If no RequiredSubmodules return an empty iterable
        '''
        return [RequiredSubmodule('MU_BASECORE'),
                RequiredSubmodule('Silicon/ARM/NXP'),
                RequiredSubmodule('Common/MU'),
                RequiredSubmodule('Common/MU_TIANO'),
                RequiredSubmodule('Common/MU_OEM_SAMPLE'),
                RequiredSubmodule('Silicon/ARM/MU_TIANO') ]

    def AddCommandLineOptions(self, parserObj):
        ''' Add command line options to the argparser '''
        parserObj.add_argument('--production', dest="production", action='store_true', default=False)

    def RetrieveCommandLineOptions(self, args):
        '''  Retrieve command line options from the argparser '''
        self.production = args.production

#--------------------------------------------------------------------------------------------------------
# Subclass the UEFI builder and add platform specific functionality.
#
class PlatformBuilder(UefiBuilder):

    def SetPlatformEnv(self):
        return 0

    def SetPlatformEnvAfterTarget(self):
        return 0

    def PlatformPostBuild(self):
        return 0

    def PlatformPreBuild(self):
        return 0

    def PlatformGatedBuildShouldHappen(self):
        return False

    def ComputeVersionValue(self):
        return 0

    def ValidateVersionValue(self):
        return 0

    def PlatformFlashImage(self):
        raise Exception("Flashing not supported")
```

## Build Settings is grouped with UefiBuilder, other settings are separate

```python
class SettingsManager(UpdateSettingsManager, SetupSettingsManager):
    def __init__(self):
        SCRIPT_PATH = os.path.dirname(os.path.abspath(__file__))
        self.WORKSPACE_PATH = os.path.dirname(os.path.dirname(SCRIPT_PATH))
        self.PRODUCTION_SCOPE = ('production', )
        self.BASE_SCOPE = ('imxfamily', 'imx8')
        self.production = None

    def GetProjectScope(self):
        ''' get scope '''
        SCOPE = self.BASE_SCOPE
        if self.production:
            SCOPE += self.PRODUCTION_SCOPE
        return SCOPE

    def GetWorkspaceRoot(self):
        ''' get WorkspacePath '''
        return self.WORKSPACE_PATH

    def GetPackagesPath(self):
        ''' Return a list of workspace relative paths that should be mapped as edk2 PackagesPath '''
        return ['MU_BASECORE','Silicon/ARM/NXP', 'Common/MU','Common/MU_TIANO', 'Common/MU_OEM_SAMPLE','Silicon/ARM/MU_TIANO']

    def GetRequiredSubmodules(self):
        ''' return iterable containing RequiredSubmodule objects.
        If no RequiredSubmodules return an empty iterable
        '''
        return [RequiredSubmodule('MU_BASECORE'),
                RequiredSubmodule('Silicon/ARM/NXP'),
                RequiredSubmodule('Common/MU'),
                RequiredSubmodule('Common/MU_TIANO'),
                RequiredSubmodule('Common/MU_OEM_SAMPLE'),
                RequiredSubmodule('Silicon/ARM/MU_TIANO')]

    def AddCommandLineOptions(self, parserObj):
        ''' Add command line options to the argparser '''
        parserObj.add_argument('--production', dest="production", action='store_true', default=False)

    def RetrieveCommandLineOptions(self, args):
        '''  Retrieve command line options from the argparser '''
        self.production = args.production

class PlatformBuilder(UefiBuilder, BuildSettingsManager):
    def __init__(self):
        UefiBuilder.__init__(self)
        SCRIPT_PATH = os.path.dirname(os.path.abspath(__file__))
        self.WORKSPACE_PATH = os.path.dirname(os.path.dirname(SCRIPT_PATH))
        self.PRODUCTION_SCOPE = ('production', )
        self.BASE_SCOPE = ('imxfamily', 'imx8')
        MODULE_PKGS = ['MU_BASECORE','Silicon/ARM/NXP', 'Common/MU','Common/MU_TIANO', 'Common/MU_OEM_SAMPLE','Silicon/ARM/MU_TIANO']
        self.MODULE_PKG_PATHS = os.pathsep.join(os.path.join(self.WORKSPACE_PATH, pkg_name) for pkg_name in MODULE_PKGS)
        self.production = None

    def GetProjectScope(self):
        ''' return tuple containing scopes that should be active for this process '''
        SCOPE = self.BASE_SCOPE
        if self.production:
            SCOPE += self.PRODUCTION_SCOPE
        return SCOPE

    def GetWorkspaceRoot(self):
        ''' get WorkspacePath '''
        return self.WORKSPACE_PATH

    def GetPackagesPath(self):
        ''' Return a list of workspace relative paths that should be mapped as edk2 PackagesPath '''
        return ['MU_BASECORE','Silicon/ARM/NXP', 'Common/MU','Common/MU_TIANO', 'Common/MU_OEM_SAMPLE','Silicon/ARM/MU_TIANO']

    def AddCommandLineOptions(self, parserObj):
        ''' Add command line options to the argparser '''
        UefiBuilder.AddCommandLineOptions(self, parserObj)
        parserObj.add_argument('--production', dest="production", action='store_true', default=False)

    def RetrieveCommandLineOptions(self, args):
        '''  Retrieve command line options from the argparser '''
        UefiBuilder.RetrieveCommandLineOptions(self, args)
        self.production = args.production
```

## A note on multi-inheritance

You might notice if you implement several classes, how does the system know
which AddCommandLineOptions to call when it's doing update vs setup? The answer
is that it doesn't. It's a classic case of the diamond problem and python's
answer for this is the MRO. Currently, our advice is to not call super into the
settings classes in this package. You can call super to your classes that you
have implemented that subclass pytool settings classes.
