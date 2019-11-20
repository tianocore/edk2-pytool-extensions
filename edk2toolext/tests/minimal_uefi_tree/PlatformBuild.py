import os
from edk2toolext.invocables.edk2_platform_build import BuildSettingsManager
from edk2toolext.invocables.edk2_setup import SetupSettingsManager
from edk2toolext.invocables.edk2_ci_setup import Edk2CiBuildSetup
from edk2toolext.invocables.edk2_ci_setup import CiSetupSettingsManager
from edk2toolext.invocables.edk2_ci_build import CiBuildSettingsManager
from edk2toolext.invocables.edk2_update import UpdateSettingsManager


class TestSettingsManager(BuildSettingsManager, SetupSettingsManager, Edk2CiBuildSetup, CiSetupSettingsManager, CiBuildSettingsManager, UpdateSettingsManager):

    def GetActiveScopes(self):
        return []

    def GetWorkspaceRoot(self):
        return os.path.dirname(__file__)

    def GetPackagesPath(self):
        return []

    def GetRequiredSubmodules(self):
        return []

    def GetDependencies(self):
        return []

    def AddCommandLineOptions(self, parserObj):
        pass

    def RetrieveCommandLineOptions(self, args):
        pass

    def GetName(self):
        return "TestEdk2Invocable"

    def GetArchitecturesSupported(self):
        return []

    def GetPackagesSupported(self):
        return []

    def GetTargetsSupported(self):
        return []

from edk2toolext.environment.uefi_build import UefiBuilder
class TestBuilder(UefiBuilder):
    def SetPlatformEnv(self):
        self.env.SetValue("EDK2_BASE_TOOLS_DIR", self.ws, "empty")
        return 0