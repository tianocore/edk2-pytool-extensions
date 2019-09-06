# If stuart is a mouse, then this would be the king of mice
import argparse
import logging
import sys
from edk2toolext.invocables.edk2_setup import Edk2PlatformSetup
from edk2toolext.invocables.edk2_ci_setup import Edk2CiBuildSetup
from edk2toolext.invocables.edk2_update import Edk2Update
from edk2toolext.invocables.edk2_build import Edk2PlatformSetup
from edk2toolext.invocables.edk2_ci_build import Edk2CiBuild


def main():
  print("     ) _     _")
  print("    ( (^)-~-(^)")
  print("__,-.\_( 0 0 )__,-.___")
  print("  'W'   \   /   'W'")
  print("         >o<")
  print("Stuart")

  invokablesToTry = [Edk2PlatformSetup, Edk2CiBuildSetup, Edk2Update, Edk2PlatformSetup, Edk2CiBuild]


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

  platformModule = import_module_by_file_name(os.path.abspath(settingsArg.platform_module))

if __name__ == '__main__':
    retcode = main()
    logging.shutdown()
    sys.exit(retcode)
