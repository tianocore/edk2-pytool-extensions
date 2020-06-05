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
from edk2toolext.invocables.edk2_multipkg_aware_invocable import Edk2MultiPkgAwareInvocable
from edk2toolext.invocables.edk2_multipkg_aware_invocable import MultiPkgAwareSettingsInterface


class UpdateSettingsManager(MultiPkgAwareSettingsInterface):
    ''' Platform settings will be accessed through this implementation.

    Update settings manager has no additional APIs not already defined in it's super class  '''
    pass


def build_env_changed(build_env, build_env_2):
    ''' return True if build_env has changed '''

    return (build_env.paths != build_env_2.paths) or \
           (build_env.extdeps != build_env_2.extdeps) or \
           (build_env.plugins != build_env_2.plugins)


class Edk2Update(Edk2MultiPkgAwareInvocable):
    ''' Updates dependencies in workspace for active scopes '''

    MAX_RETRY_COUNT = 10

    def PerformUpdate(self):
        ws_root = self.GetWorkspaceRoot()
        scopes = self.GetActiveScopes()
        (build_env, shell_env) = self_describing_environment.BootstrapEnvironment(ws_root, scopes)
        (success, failure) = self_describing_environment.UpdateDependencies(ws_root, scopes)
        if success != 0:
            logging.log(edk2_logging.SECTION, f"\tUpdated/Verified {success} dependencies")
        return (build_env, shell_env, failure)

    def GetVerifyCheckRequired(self):
        ''' Will not call self_describing_environment.VerifyEnvironment because ext_deps haven't been unpacked yet '''
        return False

    def GetSettingsClass(self):
        '''  Providing UpdateSettingsManger '''
        return UpdateSettingsManager

    def GetLoggingFileName(self, loggerType):
        return "UPDATE_LOG"

    def AddCommandLineOptions(self, parserObj):
        ''' adds command line options to the argparser '''
        super().AddCommandLineOptions(parserObj)

    def RetrieveCommandLineOptions(self, args):
        '''  Retrieve command line options from the argparser '''
        super().RetrieveCommandLineOptions(args)

    def Go(self):
        # Get the environment set up.
        RetryCount = 0
        failure_count = 0
        logging.log(edk2_logging.SECTION, "Initial update of environment")

        (build_env_old, shell_env_old, _) = self.PerformUpdate()
        self_describing_environment.DestroyEnvironment()

        # Loop updating dependencies until there are 0 new dependencies or
        # we have exceeded retry count.  This allows dependencies to carry
        # files that influence the SDE.
        logging.log(edk2_logging.SECTION, "Second pass update of environment")
        while RetryCount < Edk2Update.MAX_RETRY_COUNT:
            (build_env, shell_env, failure_count) = self.PerformUpdate()

            if not build_env_changed(build_env, build_env_old):  # check if the environment changed on our last update
                break
            # if the environment has changed, increment the retry count and notify user
            RetryCount += 1
            logging.log(edk2_logging.SECTION,
                        f"Something in the environment changed. Updating environment again. Pass {RetryCount}")

            build_env_old = build_env
            self_describing_environment.DestroyEnvironment()

        if failure_count != 0:
            logging.error(f"We were unable to successfully update {failure_count} dependencies in environment")
        if RetryCount >= Edk2Update.MAX_RETRY_COUNT:
            logging.error(f"We did an update more than {Edk2Update.MAX_RETRY_COUNT} times.")
            logging.error("Please check your dependencies and make sure you don't have any circular ones.")
            return 1
        return failure_count


def main():
    Edk2Update().Invoke()
