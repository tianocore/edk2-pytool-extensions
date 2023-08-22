# @file report_generator.py
# An executable that allows a user to select a report and execute it on a given database.
##
# Copyright (c) Microsoft Corporation
#
# SPDX-License-Identifier: BSD-2-Clause-Patent
##
"""An executable that allows a user to select a report and execute it on a given database."""
import logging
import pathlib
import sys
from argparse import ArgumentParser
from datetime import datetime

from edk2toollib.database import Edk2DB

from edk2toolext import edk2_logging
from edk2toolext.environment.reporttypes import CoverageReport, ComponentDumpQuery

REPORTS = [CoverageReport(), ComponentDumpQuery()]


def setup_logging(verbose: bool):
    """Setup logging for the tool."""
    logger = logging.getLogger('')
    logger.setLevel(logging.DEBUG if verbose else logging.INFO)
    edk2_logging.setup_section_level()
    edk2_logging.setup_console_logging(logging.DEBUG if verbose else logging.INFO)
    logging.info("Log Started: " + datetime.strftime(datetime.now(), "%A, %B %d, %Y %I:%M%p"))


def parse_args():
    """Parse the arguments for the tool."""
    parser = ArgumentParser("A tool to generate reports on a edk2 workspace.")
    parser.add_argument('--verbose', '--VERBOSE', '-v', dest="verbose", action='store_true', default=False,
                        help='verbose')
    parser.add_argument('-db', '--database', '--DATABASE', dest='database', type = pathlib.Path,
                        default=pathlib.Path("Report","DATABASE.db"),
                        help="The database to use when generating reports.")

    # Register the report arguments as subparser
    subparsers = parser.add_subparsers(dest='cmd', required=[])
    for report in REPORTS:
        name, description = report.report_info()
        report_parser = subparsers.add_parser(name, help=description)
        report.add_cli_options(report_parser)

    return parser.parse_args()

def main():
    """Main functionality of the executable."""
    args = parse_args()
    setup_logging(args.verbose)

    # Verify arguments
    db_path = args.database
    if not db_path.exists():
        logging.error(f"Database not found at path: [{db_path}]")
        return -1
    del args.database
    cmd = args.cmd
    del args.cmd

    with Edk2DB(Edk2DB.FILE_RO, db_path = db_path) as db:
        for report in REPORTS:
            name, _ = report.report_info()
            if name == cmd:
                return report.run_report(db, args)
    return -1


def go():
    """Main entry into the report generator tool.

    Sets up the logger for the tool and then runs the tool.
    """
    # setup main console as logger
    logger = logging.getLogger('')
    logger.setLevel(logging.DEBUG)
    formatter = logging.Formatter("%(levelname)s - %(message)s")
    console = logging.StreamHandler()
    console.setLevel(logging.WARNING)
    console.setFormatter(formatter)
    logger.addHandler(console)

    # call main worker function
    retcode = main()

    if retcode != 0:
        logging.critical("Failed.  Return Code: %d" % retcode)
    else:
        logging.critical("Success!")
    # end logging
    logging.shutdown()
    sys.exit(retcode)


if __name__ == '__main__':
    go()
