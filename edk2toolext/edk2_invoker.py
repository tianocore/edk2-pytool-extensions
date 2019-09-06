# If stuart is a mouse, then this would be the king of mice
import argparse
import logging
import sys
import os
import inspect
from edk2toolext.invocables.edk2_setup import Edk2PlatformSetup
from edk2toolext.invocables.edk2_ci_setup import Edk2CiBuildSetup
from edk2toolext.invocables.edk2_update import Edk2Update
from edk2toolext.invocables.edk2_platform_build import Edk2PlatformBuild
from edk2toolext.invocables.edk2_ci_build import Edk2CiBuild
from edk2toollib.utility_functions import import_module_by_file_name
try:
    from importlib import reload  # Python 3.4+ only.
except ImportError:
    print("You need at least Python 3.4+. Please upgrade!")
    raise


def GetInvokableClasses(rawInvokableList=[]):
    packageListSet = set()
    for item in rawInvokableList:  # Parse out the individual packages
        item_list = item.split(",")
        for indiv_item in item_list:
            packageListSet.add(indiv_item.strip().lower())
    requestedInvokeList = list(packageListSet)

    invokablesToTry = {
        "setup": Edk2PlatformSetup,
        "ci_setup": Edk2CiBuildSetup,
        "update": Edk2Update,
        "build": Edk2PlatformBuild,
        "ci_build": Edk2CiBuild
    }
    if len(requestedInvokeList) == 0:
        requestedInvokeList = invokablesToTry.keys()

    invokablesSupported = {}
    for requestedInvoke in requestedInvokeList:
        if requestedInvoke not in invokablesToTry.keys():
            raise RuntimeError(f"{requestedInvoke} is not a valid invokable")
        invokablesSupported[requestedInvoke] = invokablesToTry[requestedInvoke]

    return invokablesSupported


def GetInvokableIsSupported(settingsModule, invokable):
    ''' Given a settings module, figure out if the invokable supported '''
    module_contents = dir(settingsModule)
    moduleClassList = [getattr(settingsModule, obj)
                       for obj in module_contents if inspect.isclass(getattr(settingsModule, obj))]
    invokableSettingsClass = invokable().GetSettingsClass()
    for obj in moduleClassList:
        if obj == invokableSettingsClass:
            return True
    return False


def main():
    print("     ) _     _")
    print("    ( (^)-~-(^)")
    print("__,-.\_( 0 0 )__,-.___")
    print("  'W'   \   /   'W'")
    print("         >o<")

    # set up the parsers
    invokeParser = argparse.ArgumentParser(add_help=False)
    settingsParserObj = argparse.ArgumentParser(add_help=False)

    invokeParser.add_argument("-invoke", "--i", dest="invokables", default=[], type=str, action="append",
                              help="The invokable you want to invoke (setup, build, ci_build, ci_setup, update)")

    settingsParserObj.add_argument('-c', '--platform_module', dest='platform_module',
                                   default="PlatformBuild.py", type=str,
                                   help='Provide the Platform Module relative to the current working directory.')
    # first parse the invoke parser
    invokeSettings, remainingArgs = invokeParser.parse_known_args()
    # then the platform settings parser
    settingsArg, _ = settingsParserObj.parse_known_args()
    # get the invokable classes the user is requested
    invokableClasses = GetInvokableClasses(invokeSettings.invokables)
    # keep track of if we requested invokables
    requestedInvokables = len(invokeSettings.invokables) > 0
    # create the proper argv
    args = [sys.argv[0], ]
    args.extend(remainingArgs)

    # try to import the settings module
    try:
        settingsFilePath = os.path.abspath(settingsArg.platform_module)
        settingsModule = import_module_by_file_name(settingsFilePath)
    except (TypeError, FileNotFoundError) as e:
        print(f"We were unable to load your settings file: {settingsFilePath}")
        return 1
    # go through each of the invokable class and see if they're in the our settings file
    for invokable_key in invokableClasses:
        sys.argv = args  # reset the arguments since they've since been consumed
        # get the invokable we're about to do
        invokable = invokableClasses[invokable_key]
        if GetInvokableIsSupported(settingsModule, invokable):  # check if this invokable?
            print("================ STUART ================")
            print(f" Invoking: {invokable_key}")
            try:  # do the thing
                invokable().Invoke()
            except SystemExit as e:  # check if we caught fire
                if e.code != 0:
                    # stop drop and roll
                    print(f"We failed with a nonzero error code from {invokable_key}")
                    raise e
            finally:
                # this is hacky to close logging and restart it back to a default state
                logging.disable(logging.NOTSET)
                logging.shutdown()
                reload(logging)  # otherwise we get errors trying to talk to closed handlers

        elif requestedInvokables:
            # if we requested specific invokables and we can't run them, throw out some nasty errors
            print("================ STUART ================")
            print(f" Invoking: {invokable_key}")
            print("WARNING: We can't do " + str(invokable_key))
            raise RuntimeError(f"Invalid invokable {invokable_key}")


if __name__ == '__main__':
    retcode = main()
    logging.shutdown()
    sys.exit(retcode)
