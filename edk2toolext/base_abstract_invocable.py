# @file base_abstract_invocable
# Base class for an Invocable. Loads environment before calling subclass.
##
# Copyright (c) Microsoft Corporation
#
# SPDX-License-Identifier: BSD-2-Clause-Patent
##

"""The Base abstract Invocable that all other invocables should inherit from."""

import logging
import os
import sys
from datetime import datetime
from typing import Optional

from edk2toolext import edk2_logging
from edk2toolext.environment import plugin_manager, self_describing_environment
from edk2toolext.environment.plugintypes.uefi_helper_plugin import HelperFunctions


class BaseAbstractInvocable(object):
    """The Abstract Invocable.

    The base abstract invocable that other invocables should inherit from.
    Provides base functionality to configure logging and the environment.

    Attributes:
        log_filename (str): logfile path
        log_perf_measurements (bool): whether to measure and log invocable command performance or not
        plugin_manager (plugin_manager.PluginManager): the plugin manager
        helper (HelperFunctions): container for all helper functions
    """

    def __init__(self) -> None:
        """Init the Invocable."""
        self.log_filename = None
        self.log_perf_measurements = False
        return

    def ParseCommandLineOptions(self) -> None:
        """Parse command line arguments.

        !!! tip
            Required Override in a subclass
        """
        raise NotImplementedError()

    def GetWorkspaceRoot(self) -> str:
        """Return the workspace root for initializing the Self Describing Environment.

        !!! tip
            Required Override in a subclass

        Returns:
            (str): absolute path to workspace root

        """
        raise NotImplementedError()

    def GetActiveScopes(self) -> tuple:
        """Return tuple containing scopes that should be active for this process.

        !!! tip
            Required Override in a subclass

        !!! warning
            A single scope should end in a comma i.e. (scope,)

        Returns:
            (Tuple): scopes
        """
        raise NotImplementedError()

    def GetSkippedDirectories(self) -> tuple:
        """Return tuple containing workspace-relative directory paths that should be skipped for processing.

        !!! tip
            Optional Override in a subclass

        !!! warning
            A single directory should end with a comma i.e. (dir,)

        Returns:
            (Tuple): directories
        """
        return ()

    def GetLoggingLevel(self, loggerType: str) -> Optional[int]:
        """Get the logging level depending on logger type.

        !!! tip
            Required Override in a subclass

        Args:
            loggerType (str): type of logger being logged to

        Returns:
            (int): The logging level
            (None): No logging of this type

        !!! note "loggerType possible values"
            "base": lowest logging level supported

            "con": logs to screen

            "txt": logs to plain text file
        """
        raise NotImplementedError()

    def GetLoggingFolderRelativeToRoot(self) -> str:
        """Return the path to a directory to hold all log files.

        !!! hint
            Required Override in a subclass

        Returns:
            (str): path to the directory
        """
        raise NotImplementedError()

    def InputParametersConfiguredCallback(self) -> int:
        """A Callback once all input parameters are collected.

        !!! hint
            Optional override in subclass
        """

    def GetVerifyCheckRequired(self) -> bool:
        """Will call self_describing_environment.VerifyEnvironment if this returns True.

        !!! hint
            Optional override in a subclass

        Returns:
            (bool): whether verify check is required or not
        """
        return True

    def GetLoggingFileName(self, loggerType: str) -> Optional[str]:
        """Get the logging File name to provide file name customization.

        !!! hint
            Required Override this in a subclass

        Args:
            loggerType (str): values can be base, con, txt, md. See hint below

        Returns:
            (str): filename
            (None): No logging file should be created

        !!! note "loggerType possible values"
            "base": lowest logging level supported

            "con": logs to screen

            "txt": logs to plain text file
        """
        raise NotImplementedError()

    def Go(self) -> None:
        """Main function to run.

        Main function to run after the environment and logging has been configured.

        !!! tip
            Required Override in a subclass
        """
        raise NotImplementedError()

    def ConfigureLogging(self) -> None:
        """Sets up the logging.

        !!! tip
            Optional override in a subclass if new behavior is needed
        """
        logger = logging.getLogger("")
        logger.setLevel(self.GetLoggingLevel("base"))

        # Adjust console mode depending on mode.
        edk2_logging.setup_section_level()

        edk2_logging.setup_console_logging(self.GetLoggingLevel("con"))

        log_directory = os.path.join(self.GetWorkspaceRoot(), self.GetLoggingFolderRelativeToRoot())

        txtlogfile = self.GetLoggingLevel("txt")
        if txtlogfile is not None:
            logfile, filelogger = edk2_logging.setup_txt_logger(
                log_directory, self.GetLoggingFileName("txt"), txtlogfile
            )
            self.log_filename = logfile

        edk2_logging.setup_performance_logger(
            self.log_perf_measurements, log_directory, f"{self.GetLoggingFileName('txt')}_PERF"
        )

        logging.info("Log Started: " + datetime.strftime(datetime.now(), "%A, %B %d, %Y %I:%M%p"))

    def Invoke(self) -> None:
        """Main process function to configure logging and the environment.

        !!! danger
            Do not override this method
        """
        import timeit

        overall_start_time = timeit.default_timer()

        self.ParseCommandLineOptions()
        self.ConfigureLogging()
        self.InputParametersConfiguredCallback()

        logging.log(edk2_logging.SECTION, "Init Self Describing Environment")

        #
        # Next, get the environment set up.
        #
        start_time = timeit.default_timer()
        (build_env, shell_env) = self_describing_environment.BootstrapEnvironment(
            self.GetWorkspaceRoot(), self.GetActiveScopes(), self.GetSkippedDirectories()
        )
        edk2_logging.perf_measurement("Bootstrap Environment", timeit.default_timer() - start_time)

        start_time = timeit.default_timer()
        # Make sure the environment verifies IF it is required for this invocation
        if self.GetVerifyCheckRequired() and not self_describing_environment.VerifyEnvironment(
            self.GetWorkspaceRoot(), self.GetActiveScopes(), self.GetSkippedDirectories()
        ):
            raise RuntimeError(
                "External Dependencies in the environment are out of date. "
                "Consider running stuart_update to possibly resolve this issue."
            )
        edk2_logging.perf_measurement("Verify Environment", timeit.default_timer() - start_time)

        start_time = timeit.default_timer()

        # Load plugins
        logging.log(edk2_logging.SECTION, "Loading Plugins")

        self.plugin_manager = plugin_manager.PluginManager()
        failedPlugins = self.plugin_manager.SetListOfEnvironmentDescriptors(build_env.plugins)
        if failedPlugins:
            logging.critical("One or more plugins failed to load. Halting build.")
            for a in failedPlugins:
                logging.error("Failed Plugin: {0}".format(a["name"]))
            raise Exception("One or more plugins failed to load.")

        self.helper = HelperFunctions()
        if self.helper.LoadFromPluginManager(self.plugin_manager) > 0:
            raise Exception("One or more helper plugins failed to load.")

        edk2_logging.perf_measurement("Plugin Load", timeit.default_timer() - start_time)

        logging.log(edk2_logging.SECTION, "Start Invocable Tool")
        edk2_logging.perf_measurement("Start Invocable", timeit.default_timer() - overall_start_time)
        retcode = self.Go()
        logging.log(edk2_logging.SECTION, "Summary")
        if retcode != 0:
            logging.error("Error")
        else:
            edk2_logging.log_progress("Success")

        logging.shutdown()
        sys.exit(retcode)
