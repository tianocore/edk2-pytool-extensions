# @file base_abstract_invocable
# Base class for an Invocable. Loads environment before calling subclass.
##
# Copyright (c) Microsoft Corporation
#
# SPDX-License-Identifier: BSD-2-Clause-Patent
##
import os
import sys
import logging
from datetime import datetime
from edk2toolext import edk2_logging
from edk2toolext.environment import plugin_manager
from edk2toolext.environment.plugintypes.uefi_helper_plugin import HelperFunctions
from edk2toolext.environment import self_describing_environment


class BaseAbstractInvocable(object):

    def __init__(self):
        self.log_filename = None
        return

    def ParseCommandLineOptions(self):
        ''' parse arguments '''
        raise NotImplementedError()

    def GetWorkspaceRoot(self):
        ''' Return the workspace root for initializing the SDE '''
        raise NotImplementedError()

    def GetActiveScopes(self):
        ''' return tuple containing scopes that should be active for this process '''
        raise NotImplementedError()

    def GetLoggingLevel(self, loggerType):
        ''' Get the logging level for a given type (return Logging.Level)
        base == lowest logging level supported
        con  == Screen logging
        txt  == plain text file logging
        md   == markdown file logging
        '''
        raise NotImplementedError()

    def GetLoggingFolderRelativeToRoot(self):
        ''' Return a path to folder for log files '''
        raise NotImplementedError()

    def InputParametersConfiguredCallback(self):
        ''' This function is called once all the input parameters
        are collected and can be used to initialize environment
        '''
        pass

    def GetVerifyCheckRequired(self):
        ''' Will call self_describing_environment.VerifyEnvironment if this returns True '''
        return True

    def GetLoggingFileName(self, loggerType):
        ''' Get the logging file name for the type.
        Return None if the logger shouldn't be created

        base == lowest logging level supported
        con  == Screen logging
        txt  == plain text file logging
        md   == markdown file logging
        '''
        raise NotImplementedError()

    def Go(self):
        ''' Main function to run '''
        raise NotImplementedError()

    def ConfigureLogging(self):
        ''' Set up the logging.  This function only needs to be overridden if new behavior is needed'''

        logger = logging.getLogger('')
        logger.setLevel(self.GetLoggingLevel("base"))

        # Adjust console mode depending on mode.
        edk2_logging.setup_section_level()

        edk2_logging.setup_console_logging(self.GetLoggingLevel("con"))

        log_directory = os.path.join(self.GetWorkspaceRoot(), self.GetLoggingFolderRelativeToRoot())

        txtlogfile = self.GetLoggingLevel("txt")
        if(txtlogfile is not None):
            logfile, filelogger = edk2_logging.setup_txt_logger(log_directory,
                                                                self.GetLoggingFileName("txt"),
                                                                txtlogfile)
            self.log_filename = logfile

        md_log_file = self.GetLoggingLevel("md")
        if(md_log_file is not None):
            md_file, md_logger = edk2_logging.setup_markdown_logger(log_directory,
                                                                    self.GetLoggingFileName("md"),
                                                                    md_log_file)

        logging.info("Log Started: " + datetime.strftime(datetime.now(), "%A, %B %d, %Y %I:%M%p"))

        return

    def Invoke(self):
        ''' Main process function.  Should not need to be overwritten '''

        self.ParseCommandLineOptions()
        self.ConfigureLogging()
        self.InputParametersConfiguredCallback()

        logging.log(edk2_logging.SECTION, "Init SDE")

        #
        # Next, get the environment set up.
        #
        (build_env, shell_env) = self_describing_environment.BootstrapEnvironment(
            self.GetWorkspaceRoot(), self.GetActiveScopes())

        # Make sure the environment verifies IF it is required for this invocation
        if self.GetVerifyCheckRequired() and not self_describing_environment.VerifyEnvironment(
                self.GetWorkspaceRoot(), self.GetActiveScopes()):
            raise RuntimeError("SDE is not current.  Please update your env before running this tool.")

        # Load plugins
        logging.log(edk2_logging.SECTION, "Loading Plugins")

        self.plugin_manager = plugin_manager.PluginManager()
        failedPlugins = self.plugin_manager.SetListOfEnvironmentDescriptors(
            build_env.plugins)
        if failedPlugins:
            logging.critical("One or more plugins failed to load. Halting build.")
            for a in failedPlugins:
                logging.error("Failed Plugin: {0}".format(a["name"]))
            raise Exception("One or more plugins failed to load.")

        self.helper = HelperFunctions()
        if(self.helper.LoadFromPluginManager(self.plugin_manager) > 0):
            raise Exception("One or more helper plugins failed to load.")

        logging.log(edk2_logging.SECTION, "Start Invocable Tool")
        retcode = self.Go()
        logging.log(edk2_logging.SECTION, "Summary")
        if(retcode != 0):
            logging.error("Error")
        else:
            edk2_logging.log_progress("Success")

        logging.shutdown()
        sys.exit(retcode)
