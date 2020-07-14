import os
import sys
import argparse
import PEObject

TOOL_DESCRIPTION = """
Versioninfo Tool is a command-line tool to assist in generating VERSIONINFO
resource files for use with Resource Compiler. It takes a JSON representing
versioning info and produces a resource file that satifies UEFI SBAT requirements
and is compatible with Resource Compiler.

An example call might look like:
%s -o /path/to/version.JSON /path/to/output
""" % (os.path.basename(sys.argv[0]),)


def get_cli_options(args=None):
    '''
    will parse the primary options from the command line. If provided, will take the options as
    an array in the first parameter
    '''
    parser = argparse.ArgumentParser(description=TOOL_DESCRIPTION, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument('input_file', type=str,
                        help='a filesystem path to a json/PE file to load')
    parser.add_argument('output_dir', type=str,
                        help='a filesystem path to the directory to save output file. if directory does not exist, entire directory path will be created. if directory does exist, contents will be updated') # noqa
    
    command_group = parser.add_mutually_exclusive_group()
    command_group.add_argument('-e', '--encode', action='store_const', const='e', dest='mode', 
                        help='(default) outsputs VERSIONINFO.rc of given json file')
    command_group.add_argument('-d', '--dump', action='store_const', dest='mode', const='d', 
                        help='outputs json file of VERSIONINFO given PE file')
    parser.set_defaults(mode='e')
    return parser.parse_args(args=args)

def main():
    args = get_cli_options()
    output_dir = args.output_dir
    if not output_dir.endswith('\\'):
        output_dir += '\\'
    if args.mode == 'd':
        PEObject.writeResourceJSON(args.input_file, output_dir)
    else:
        PEObject.generateRCfile(args.input_file, output_dir)
        

if __name__ == '__main__':
    main()