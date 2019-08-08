# @file edk2_invocable
# Middle layer providing Project MU specific parsing to Invocable tools.
##
# Copyright (c) Microsoft Corporation
#
# SPDX-License-Identifier: BSD-2-Clause-Patent
##

import os
import sys
import logging
import argparse
from edk2toolext.environment import shell_environment
from edk2toollib.utility_functions import GetHostInfo
from edk2toollib.utility_functions import locate_class_in_module
from edk2toollib.utility_functions import import_module_by_file_name
from edk2toolext.base_abstract_invocable import BaseAbstractInvocable


class Edk2Invocable(BaseAbstractInvocable):

    def GetWorkspaceRoot(self):
        try:
            return self.PlatformSettings.GetWorkspaceRoot()
        except AttributeError:
            raise RuntimeError("Can't call this before PlatformSettings has been set up!")

    def GetActiveScopes(self):
        try:
            scopes = self.PlatformSettings.GetActiveScopes()
        except AttributeError:
            raise RuntimeError("Can't call this before PlatformSettings has been set up!")

        # Add any OS-specific scope.
        if GetHostInfo().os == "Windows":
            scopes += ('global-win',)
        elif GetHostInfo().os == "Linux":
            scopes += ('global-nix',)
        # Add the global scope. To be deprecated.
        scopes += ('global',)
        return scopes

    def GetLoggingLevel(self, loggerType):
        ''' Get the logging level for a given type
        base == lowest logging level supported
        con  == Screen logging
        txt  == plain text file logging
        md   == markdown file logging
        '''
        try:
            level = self.PlatformSettings.GetLoggingLevel(loggerType)
            if level is not None:
                return level
        except:
            pass

        if(loggerType == "con") and not self.Verbose:
            return logging.WARN
        return logging.DEBUG

    def AddCommandLineOptions(self, parserObj):
        ''' Implement in subclass to add command line options to the argparser '''
        pass

    def RetrieveCommandLineOptions(self, args):
        '''  Implement in subclass to retrieve command line options from the argparser '''
        pass

    def GetSettingsClass(self):
        '''  Child class should provide the class that contains their required settings '''
        raise NotImplementedError()

    def GetLoggingFolderRelativeToRoot(self):
        return "Build"

    def ParseCommandLineOptions(self):
        '''
        Parses command line options.
        Sets up argparser specifically to get PlatformSettingsManager instance.
        Then sets up second argparser and passes it to child class and to PlatformSettingsManager.
        Finally, parses all known args and then reads the unknown args in to build vars.
        '''
        # first argparser will only get settings manager and help will be disabled
        settingsParserObj = argparse.ArgumentParser(add_help=False)
        # instantiate the second argparser that will get passed around

        epilog = '''
<key>=<value>               - Set an env variable for the pre/post build process
BLD_*_<key>=<value>         - Set a build flag for all build types.
Key=value will get passed to build process
BLD_<TARGET>_<key>=<value>  - Set a build flag for build type of <target>
Key=value will get passed to build process for given build type)'''

        parserObj = argparse.ArgumentParser(epilog=epilog)

        settingsParserObj.add_argument('-c', '--platform_module', dest='platform_module',
                                       default="PlatformBuild.py", type=str,
                                       help='Provide the Platform Module relative to the current working directory.'
                                            f'This should contain a {self.GetSettingsClass().__name__} instance.')

        # get the settings manager from the provided file and load an instance
        settingsArg, unknown_args = settingsParserObj.parse_known_args()
        try:
            self.PlatformModule = import_module_by_file_name(os.path.abspath(settingsArg.platform_module))
            self.PlatformSettings = locate_class_in_module(
                self.PlatformModule, self.GetSettingsClass())()
        except (TypeError, FileNotFoundError) as e:
            # Gracefully exit if setup doesn't go well.
            try:
                # If this works, we can provide help for whatever special functions
                # the subclass is offering.
                self.AddCommandLineOptions(settingsParserObj)
            except:
                # If it didn't work, oh well.
                pass
            print(e)
            settingsParserObj.print_help()
            sys.exit(0)

        # now to get the big arg parser going...
        # first pass it to the subclass
        self.AddCommandLineOptions(parserObj)

        # next pass it to the settings manager
        self.PlatformSettings.AddCommandLineOptions(parserObj)

        default_build_config_path = os.path.join(self.GetWorkspaceRoot(), "BuildConfig.conf")

        # add the common stuff that everyone will need
        parserObj.add_argument('--build-config', dest='build_config', default=default_build_config_path, type=str,
                               help='Provide shell variables in a file')
        parserObj.add_argument('--verbose', '--VERBOSE', '-v', dest="verbose", action='store_true', default=False,
                               help='verbose')

        # setup sys.argv and argparse round 2
        sys.argv = [sys.argv[0]] + unknown_args
        args, unknown_args = parserObj.parse_known_args()
        self.Verbose = args.verbose

        # give the parsed args to the subclass
        self.RetrieveCommandLineOptions(args)

        # give the parsed args to platform settings manager
        self.PlatformSettings.RetrieveCommandLineOptions(args)

        #
        # Look through unknown_args and BuildConfig for strings that are x=y,
        # set env.SetValue(x, y),
        # then remove this item from the list.
        #
        env = shell_environment.GetBuildVars()
        BuildConfig = os.path.abspath(args.build_config)

        if os.path.isfile(BuildConfig):
            with open(BuildConfig) as file:
                for line in file:
                    stripped_line = line.strip()
                    if not stripped_line.startswith("#"):
                        unknown_args.append(line)

        i = 0
        while i < len(unknown_args):
            unknown_arg = unknown_args[i]
            if(unknown_arg.count("=") == 1):
                tokens = unknown_arg.strip().split("=")
                env.SetValue(tokens[0].strip().upper(), tokens[1].strip(), "From CmdLine")
                del unknown_args[i]
            else:
                i += 1

        if len(unknown_args) > 0:
            parserObj.print_help()
            raise RuntimeError(f"Unknown variables passed in: {unknown_args}")
