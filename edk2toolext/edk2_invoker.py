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

def main():
  print("     ) _     _")
  print("    ( (^)-~-(^)")
  print("__,-.\_( 0 0 )__,-.___")
  print("  'W'   \   /   'W'")
  print("         >o<")

  invokablesToTry = [Edk2PlatformSetup, Edk2CiBuildSetup, Edk2Update, Edk2PlatformSetup, Edk2CiBuild]
  invokableSettingsClasses = [obj().GetSettingsClass() for obj in invokablesToTry]

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
                                  help='Provide the Platform Module relative to the current working directory.')
  allArgs = sys.argv
  settingsArg, _ = settingsParserObj.parse_known_intermixed_args()

  parserObj.add_argument("-invoke", "--i", dest="invokables", default=[], type=str, help="The invokable you want to invoke (setup, build, ci_build, ci_setup, update)")


  moduleClassList = []
  try:
    settingsFilePath = os.path.abspath(settingsArg.platform_module)
    platformModule = import_module_by_file_name(settingsFilePath)
    module_contents = dir(platformModule)
    # Filter through the Module, we're only looking for classes.
    moduleClassList = [getattr(platformModule, obj) for obj in module_contents if inspect.isclass(getattr(platformModule, obj))]
  except (TypeError, FileNotFoundError) as e:
    print(f"We were unable to load your settings file: {settingsFilePath}")
    return 1

  # go through each of the invokable settings class and see if they're in the our module
  for invokable in invokableSettingsClasses:
    if invokable in moduleClassList:
      print("We can do" + str(invokable))
    else:
      print("We can't do "+ str(invokable))

if __name__ == '__main__':
    retcode = main()
    logging.shutdown()
    sys.exit(retcode)
