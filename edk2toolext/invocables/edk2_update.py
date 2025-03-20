# @file Edk2Update
# Updates external dependencies for project_scope in workspace_path
# as listed in Platform Config file.
##
# Copyright (c) Microsoft Corporation
#
# SPDX-License-Identifier: BSD-2-Clause-Patent
##
"""Updates external dependencies.

Contains a UpdateSettingsManager that must be subclassed in a build settings
file. This provides platform specific information to Edk2Update invocable
while allowing the invocable itself to remain platform agnostic.
"""

import argparse
import logging
import timeit

from edk2toolext import edk2_logging
from edk2toolext.environment import self_describing_environment
from edk2toolext.invocables.edk2_multipkg_aware_invocable import (
    Edk2MultiPkgAwareInvocable,
    MultiPkgAwareSettingsInterface,
)


class UpdateSettingsManager(MultiPkgAwareSettingsInterface):
    """Platform specific settings for Edk2Update.

    Provides information necessary for `stuart_update.exe` or `edk2_update.py`
    when updating the platform.

    Update settings manager has no additional APIs not already defined in it's super class, however
    The class should still be overwritten by the platform.
    """


def build_env_changed(
    build_env: self_describing_environment.self_describing_environment,
    build_env_2: self_describing_environment.self_describing_environment,
) -> bool:
    """Return True if build_env has changed."""
    return (
        (build_env.paths != build_env_2.paths)
        or (build_env.extdeps != build_env_2.extdeps)
        or (build_env.plugins != build_env_2.plugins)
    )


class Edk2Update(Edk2MultiPkgAwareInvocable):
    """Updates dependencies in workspace for active scopes."""

    MAX_RETRY_COUNT = 10

    def PerformUpdate(self) -> tuple:
        """Updates the dependencies."""
        ws_root = self.GetWorkspaceRoot()
        scopes = self.GetActiveScopes()
        skipped_dirs = self.GetSkippedDirectories()
        (build_env, shell_env) = self_describing_environment.BootstrapEnvironment(ws_root, scopes, skipped_dirs)
        (success, failure) = self_describing_environment.UpdateDependencies(ws_root, scopes, skipped_dirs)
        if success != 0:
            logging.log(edk2_logging.SECTION, f"\tUpdated/Verified {success} dependencies")
        return (build_env, shell_env, failure)

    def GetVerifyCheckRequired(self) -> bool:
        """Will not call self_describing_environment.VerifyEnvironment because ext_deps haven't been unpacked yet."""
        return False

    def GetSettingsClass(self) -> type:
        """Returns the UpdateSettingsManager class.

        !!! warning
            UpdateSettingsManager must be subclassed in your platform settings file.
        """
        return UpdateSettingsManager

    def GetLoggingFileName(self, loggerType: str) -> str:
        """Returns the filename (UPDATE_LOG) of where the logs for the Edk2CiBuild invocable are stored in."""
        return "UPDATE_LOG"

    def AddCommandLineOptions(self, parserObj: argparse.ArgumentParser) -> None:
        """Adds command line options to the argparser."""
        super().AddCommandLineOptions(parserObj)

    def RetrieveCommandLineOptions(self, args: argparse.Namespace) -> None:
        """Retrieve command line options from the argparser."""
        super().RetrieveCommandLineOptions(args)

    def Go(self) -> int:
        """Executes the core functionality of the Edk2Update invocable."""
        full_start_time = timeit.default_timer()

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
            logging.log(
                edk2_logging.SECTION,
                f"Something in the environment changed. Updating environment again. Pass {RetryCount}",
            )

            build_env_old = build_env
            self_describing_environment.DestroyEnvironment()

        edk2_logging.perf_measurement("Complete Update", timeit.default_timer() - full_start_time)

        if failure_count != 0:
            logging.error(f"We were unable to successfully update {failure_count} dependencies in environment")
        if RetryCount >= Edk2Update.MAX_RETRY_COUNT:
            logging.error(f"We did an update more than {Edk2Update.MAX_RETRY_COUNT} times.")
            logging.error("Please check your dependencies and make sure you don't have any circular ones.")
            return 1
        return failure_count


def main() -> None:
    """Entry point to invoke Edk2Update."""
    Edk2Update().Invoke()
