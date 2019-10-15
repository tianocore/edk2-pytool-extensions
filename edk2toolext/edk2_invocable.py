# @file edk2_invocable
# Class Object providing Edk2 specific Invocable functionality
#
# This should not be instantiated but should be used as baseclass
##
# Copyright (c) Microsoft Corporation
#
# SPDX-License-Identifier: BSD-2-Clause-Patent
##

import os
import sys
import logging
import inspect
import pkg_resources
import argparse
from edk2toolext.environment import shell_environment
from edk2toollib.utility_functions import GetHostInfo
from edk2toolext.environment import version_aggregator
from edk2toollib.utility_functions import locate_class_in_module
from edk2toollib.utility_functions import import_module_by_file_name
from edk2toolext.base_abstract_invocable import BaseAbstractInvocable


class Edk2Invocable(BaseAbstractInvocable):

    # Collects all pip package names they will be printed
    # as well as reported to the global version_aggregator
    @classmethod
    def collect_python_pip_info(cls):
        # Get the current python version
        cur_py = "%d.%d.%d" % sys.version_info[:3]
        ver_agg = version_aggregator.GetVersionAggregator()
        ver_agg.ReportVersion("Python", cur_py, version_aggregator.VersionTypes.TOOL)
        # Get a list of all the packages currently installed in pip
        pip_packages = [p for p in pkg_resources.working_set]
        # go through all installed pip versions
        for package in pip_packages:
            version = pkg_resources.get_distribution(package).version
            logging.info("{0} version: {1}".format(package.project_name, version))
            ver_agg.ReportVersion(package.project_name, version, version_aggregator.VersionTypes.PIP)

    def GetWorkspaceRoot(self):
        try:
            return self.PlatformSettings.GetWorkspaceRoot()
        except AttributeError:
            raise RuntimeError("Can't call this before PlatformSettings has been set up!")

    def GetActiveScopes(self):
        ''' return tuple containing scopes that should be active for this process '''
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
        except (TypeError):
            # Gracefully exit if the file we loaded isn't the right type
            class_name = self.GetSettingsClass().__name__
            print(f"Unable to use {settingsArg.platform_module} as a {class_name}")
            print("Did you mean to use a different kind of invokable?")
            try:
                # If this works, we can provide help for whatever special functions
                # the subclass is offering.
                self.AddCommandLineOptions(settingsParserObj)
                Module = self.PlatformModule
                module_contents = dir(Module)
                # Filter through the Module, we're only looking for classes.
                classList = [getattr(Module, obj) for obj in module_contents if inspect.isclass(getattr(Module, obj))]
                # Get the name of all the classes
                classNameList = [obj.__name__ for obj in classList]
                # TODO improve filter to no longer catch imports as well as declared classes
                imported_classes = ", ".join(classNameList)  # Join the classes together
                print(f"The module you imported contains {imported_classes}")
            except Exception:
                # Otherwise, oh well we'll just ignore this.
                raise
                pass
            settingsParserObj.print_help()
            sys.exit(1)

        except (FileNotFoundError):
            # Gracefully exit if we can't find the file
            print(f"We weren't able to find {settingsArg.platform_module}")
            settingsParserObj.print_help()
            sys.exit(2)

        except Exception as e:
            print(f"Error: We had trouble loading {settingsArg.platform_module}. Is the path correct?")
            # Gracefully exit if setup doesn't go well.
            settingsParserObj.print_help()
            print(e)
            sys.exit(2)

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

        for argument in unknown_args:
            if argument.count("=") != 1:
                raise RuntimeError(f"Unknown variable passed in via CLI: {argument}")
            tokens = argument.strip().split("=")
            env.SetValue(tokens[0].strip().upper(), tokens[1].strip(), "From CmdLine")

        unknown_args.clear()  # remove the arguments we've already consumed

        if os.path.isfile(BuildConfig):
            with open(BuildConfig) as file:
                for line in file:
                    stripped_line = line.strip().partition("#")[0]
                    if len(stripped_line) == 0:
                        continue
                    unknown_args.append(stripped_line)

        for argument in unknown_args:
            if argument.count("=") != 1:
                raise RuntimeError(f"Unknown variable passed in via BuildConfig: {argument}")
            tokens = argument.strip().split("=")
            env.SetValue(tokens[0].strip().upper(), tokens[1].strip(), "From BuildConf")
