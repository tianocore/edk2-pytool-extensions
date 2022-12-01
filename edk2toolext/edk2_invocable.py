# @file edk2_invocable
# Class Object providing Edk2 specific Invocable functionality
#
# This should not be instantiated but should be used as baseclass
##
# Copyright (c) Microsoft Corporation
#
# SPDX-License-Identifier: BSD-2-Clause-Patent
##

"""Edk2 Invocable Interface to be overriden in a subclass.

Provides two main classes, the Edk2InvocableSettingsInterface and the
Edk2Invocable, which should be used as subclasses to create invocables that
perform tasks associated with the EDK2 build system. Any Edk2Invocable subclass
should be platform agnostic and work for any platform. Platform specific data
is provided via the Edk2InvocableSettingsInterface.
"""
import os
import sys
import logging
import inspect
import pkg_resources
import argparse
from typing import Iterable, Tuple
from textwrap import dedent
from edk2toolext.environment import shell_environment
from edk2toollib.utility_functions import GetHostInfo
from edk2toolext.environment import version_aggregator
from edk2toollib.utility_functions import locate_class_in_module
from edk2toollib.utility_functions import import_module_by_file_name
from edk2toolext.base_abstract_invocable import BaseAbstractInvocable


class Edk2InvocableSettingsInterface():
    """Settings APIs to support an Edk2Invocable.

    This is an interface definition only to show which functions are
    required to be implemented and can be implemented in a settings
    manager.

    !!! example "Example of Overriding Edk2InvocableSettingsInterface"
        ``` python
        import os
        import logging
        import argparse
        from typing import Iterable, Tuple
        from edk2toolext.edk2_invocable import Edk2InvocableSettingsInterface

        class NewInvocableSettingsManager(Edk2InvocableSettingsInterface):
            def GetWorkspaceRoot(self) -> str:
                return os.path.abspath(__file__)
            def GetPackagesPath(self) -> Iterable[os.PathLike]
                return ["C:/src/MU_BASECORE", "Common/MU"]
            def GetActiveScopes(self) -> Tuple[str]:
                return ("edk2-build", "pipbuild-win")
            def GetLoggingLevel(self, loggerType: str) -> str:
                if loggerType == 'txt':
                    return logging.WARNING
                else:
                    return logging.INFO
            def AddCommandLineOptions(self, parserObj: object) -> None:
                parserObj.add_argument('-a', "--arch", dest="build_arch", type=str, default="IA32,X64")
            def RetrieveCommandLineOptions(self, args: object) -> None:
                self.arch = args.build_arch
            def GetSkippedDirectories(self) -> Tuple[str]:
                return ("Downloads/Extra")
        ```

    !!! warning
        This interface should not be subclassed directly unless you are creating a new invocable
        Other invocables subclass from this interface, so you have the ability to
        call the functions in this class as a part of those invocable settings managers.
    """

    def GetWorkspaceRoot(self) -> str:
        """Return the workspace root for initializing the SDE.

        !!! tip
            Required Override in a subclass

        The absolute path to the root of the workspace

        Returns:
            (str): path to workspace root
        """
        raise NotImplementedError()

    def GetPackagesPath(self) -> Iterable[os.PathLike]:
        """Provides an iterable of paths should should be mapped as edk2 PackagePaths.

        !!! tip
            Optional Override in a subclass

        Returns:
            (Iterable[os.PathLike]): paths
        """
        return []

    def GetActiveScopes(self) -> Tuple[str]:
        """Provides scopes that should be active for this process.

        !!! tip
            Optional Override in a subclass

        Returns:
            (Tuple[str]): scopes
        """
        return ()

    def GetLoggingLevel(self, loggerType: str) -> str:
        """Get the logging level depending on logger type.

        !!! tip
            Optional Override in a subclass

        Returns:
            (Logging.Level): The logging level

        !!! note "loggerType possible values"
            "base": lowest logging level supported

            "con": logs to screen

            "txt": logs to plain text file

            "md": logs to markdown file
        """
        return None

    def AddCommandLineOptions(self, parserObj: object) -> None:
        """Add command line options to the argparser.

        !!! tip
            Optional override in a subclass

        Args:
            parserObj: Argparser object.
        """
        pass

    def RetrieveCommandLineOptions(self, args: object) -> None:
        """Retrieve Command line options from the argparser.

        !!! tip
            Optional override in a subclass

        Args:
            args: argparser args namespace containing command line options
        """
        pass

    def GetSkippedDirectories(self) -> Tuple[str]:
        """Returns a tuple containing workspace-relative directories to be skipped.

        !!! tip
            Optional override in a subclass

        Returns:
            (Tuple[str]): directories to be skipped.
        """
        return ()


class Edk2Invocable(BaseAbstractInvocable):
    """Base class for Edk2 based invocables.

    Edk2 means it has common features like workspace, packagespath,
    scopes, and other name value pairs

    Attributes:
        PlatformSettings (Edk2InvocableSettingsInterface): A settings class
        PlatformModule (object): The platform module
        Verbose (bool): CLI Argument to determine whether or not to have verbose

    !!! tip
        Checkout BaseAbstractInvocable Attributes to find any additional attributes that might exist.

    !!! warning
        This Invocable should only be subclassed if creating a new invocable
    """

    @classmethod
    def collect_python_pip_info(cls):
        """Class method to collect all pip packages names and versions.

        Reports them to the global version_aggregator as well as print them to the screen.
        """
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

    def GetWorkspaceRoot(self) -> os.PathLike:
        """Returns the absolute path to the workspace root.

        !!! note
            Workspace Root is platform specific and thus provided by the PlatformSettings

        Returns:
            absolute path to workspace root
        """
        try:
            return self.PlatformSettings.GetWorkspaceRoot()
        except AttributeError:
            raise RuntimeError("Can't call this before PlatformSettings has been set up!")

    def GetPackagesPath(self) -> Iterable[os.PathLike]:
        """Returns an iterable of packages path.

        !!! note
            PackagesPath is platform specific and thus provided by the PlatformSettings

        Returns:
            Packages path
        """
        try:
            return [x for x in self.PlatformSettings.GetPackagesPath() if x not in self.GetSkippedDirectories()]
        except AttributeError:
            raise RuntimeError("Can't call this before PlatformSettings has been set up!")

    def GetActiveScopes(self) -> Tuple[str]:
        """Returns an iterable of Active scopes.

        !!! note
            Scopes are platform specific and thus provided by the PlatformSettings

        This function adds an os specific scope in addition to scopes provided by SettingsManager

        Returns:
            active scopes
        """
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
        """Get the logging level for a given logger type.

        !!! note
            Logging Level is platform specific and thus provided by the PlatformSettings

        Returns:
            (logging.Level): logging level
        """
        try:
            level = self.PlatformSettings.GetLoggingLevel(loggerType)
            if level is not None:
                return level
        except Exception:
            pass

        if (loggerType == "con") and not self.Verbose:
            return logging.WARNING
        return logging.DEBUG

    def AddCommandLineOptions(self, parserObj):
        """Add command line options to the argparser.

        !!! note
            Optional Override to add functionality
        """
        pass

    def RetrieveCommandLineOptions(self, args):
        """Retrieve command line options from the argparser.

        !!! note
            Optional Override to add functionality
        """
        pass

    def GetSkippedDirectories(self):
        """Returns a Tuple containing workspace-relative directories that should be skipped.

        !!! tip
            Override in a subclass to add invocable specific directories to skip

        !!! note
            Skipped Directories are platform specific and thus provided by the PlatformSettings

        Returns:
            (Tuple[str]): skipped directories as relative paths
        """
        try:
            return self.PlatformSettings.GetSkippedDirectories()
        except AttributeError:
            raise RuntimeError("Can't call this before PlatformSettings has been set up!")

    def GetSettingsClass(self):
        """The required settings manager for the invocable.

        !!! note
            Required override to define Edk2InvocableSettingsInterface subclass specific to the invocable

        Returns:
            (Edk2InvocableSettingsInterface): Subclass of Edk2InvocableSettingsInterface
        """
        raise NotImplementedError()

    def GetLoggingFolderRelativeToRoot(self):
        """Directory containing all logging files."""
        return "Build"

    def ParseCommandLineOptions(self):
        """Parses command line options.

        Sets up argparser specifically to get PlatformSettingsManager instance.
        Then sets up second argparser and passes it to child class and to PlatformSettingsManager.
        Finally, parses all known args and then reads the unknown args in to build vars.
        """
        # first argparser will only get settings manager and help will be disabled
        settingsParserObj = argparse.ArgumentParser(add_help=False)
        # instantiate the second argparser that will get passed around

        epilog = dedent('''\
            positional arguments:
              <key>=<value>              - Set an env variable for the pre/post build process
              BLD_*_<key>=<value>        - Set a build flag for all build types
                                           (key=value will get passed to build process)
              BLD_<TARGET>_<key>=<value> - Set a build flag for build type of <target>
                                           (key=value will get passed to build process for given build type)
            ''')

        parserObj = argparse.ArgumentParser(epilog=epilog, formatter_class=argparse.RawDescriptionHelpFormatter,)

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
            print("Did you mean to use a different kind of invocable?")
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
                raise

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
