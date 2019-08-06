# @file Edk2Update
# Updates external dependencies for project_scope in workspace_path
# as listed in Platform Config file.
##
# Copyright (c) Microsoft Corporation
#
# SPDX-License-Identifier: BSD-2-Clause-Patent
##
import logging
from edk2toolext import edk2_logging
from edk2toolext.environment import self_describing_environment
from edk2toolext.edk2_invocable import Edk2Invocable


class UpdateSettingsManager():
    ''' Platform settings will be accessed through this implementation. '''

    def GetActiveScopes(self):
        ''' get scope '''
        raise NotImplementedError()

    def GetWorkspaceRoot(self):
        ''' get WorkspacePath '''
        raise NotImplementedError()

    def AddCommandLineOptions(self, parserObj):
        ''' Implement in subclass to add command line options to the argparser '''
        pass

    def RetrieveCommandLineOptions(self, args):
        '''  Implement in subclass to retrieve command line options from the argparser '''
        pass

    def GetLoggingLevel(self, loggerType):
        ''' Get the logging level for a given type
        base == lowest logging level supported
        con  == Screen logging
        txt  == plain text file logging
        md   == markdown file logging
        '''
        pass


def build_env_changed(build_env, build_env_2):
    ''' return True if build_env has changed '''

    return (build_env.paths != build_env_2.paths) or \
           (build_env.extdeps != build_env_2.extdeps) or \
           (build_env.plugins != build_env_2.plugins)


class Edk2Update(Edk2Invocable):
    ''' Updates dependencies in workspace for active scopes '''

    def PerformUpdate(self):
        (build_env, shell_env) = self_describing_environment.BootstrapEnvironment(
            self.GetWorkspaceRoot(), self.GetActiveScopes())
        self_describing_environment.UpdateDependencies(self.GetWorkspaceRoot(), self.GetActiveScopes())
        return (build_env, shell_env)

    def GetVerifyCheckRequired(self):
        ''' Will not call self_describing_environment.VerifyEnvironment because ext_deps haven't been unpacked yet '''
        return False

    def GetSettingsClass(self):
        '''  Providing UpddateSettingsManger '''
        return UpdateSettingsManager

    def GetLoggingFileName(self, loggerType):
        return "UPDATE_LOG"

    def Go(self):
        # Get the environment set up.
        RetryCount = 0
        logging.log(edk2_logging.SECTION, "First Update")

        (build_env_old, shell_env_old) = self.PerformUpdate()
        self_describing_environment.DestroyEnvironment()

        while True:
            RetryCount += 1
            logging.log(edk2_logging.SECTION, f"Retry Count: {RetryCount}")

            (build_env, shell_env) = self.PerformUpdate()

            if not build_env_changed(build_env, build_env_old):
                break

            build_env_old = build_env

            self_describing_environment.DestroyEnvironment()

        return 0


def main():
    Edk2Update().Invoke()
