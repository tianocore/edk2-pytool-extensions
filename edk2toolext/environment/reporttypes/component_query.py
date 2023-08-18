# @file component_query.py
# A query to print information about a component that could be compiled.
##
# Copyright (c) Microsoft Corporation
#
# SPDX-License-Identifier: BSD-2-Clause-Patent
##
"""An interface to create custom reports with."""
from argparse import ArgumentParser, Namespace
import sys
from pathlib import Path

from edk2toollib.database import Edk2DB, Query
from edk2toollib.uefi.edk2.path_utilities import Edk2Path
from edk2toollib.database.queries import ComponentQuery

class Report:
    """The interface to create custom reports."""
    def report_info(self):
        """Returns the report standard information.

        Returns:
            (str, str): A tuple of (name, description)
        """
        return ("component", "Queries information about a component that that was parsed from a DSC.")

    def add_cli_options(self, parserobj: ArgumentParser):
        """Configure command line arguments for this report."""
        parserobj.add_argument(dest="component", action="store", help="The component to query.")
        parserobj.add_argument("-f", "--file", dest="file", default=sys.stdout, help="The file (or stdout), to write the report to.")
        parserobj.add_argument("-d", "--depth", dest="depth", type=int, default=999, help="The depth to recurse when printing libraries used.")

    def run_report(self, db: Edk2DB, args: Namespace) -> None:
        """Generate a report."""
        if isinstance(args.file, str):
            if Path(args.file).exists():
                Path(args.file).unlink()
            self.file = open(args.file, 'w+')
        else:
            self.file = args.file

        self.depth = args.depth
        self.component = args.component

        table_name = "instanced_inf"
        table = db.table(table_name)

        print(args.component, file=self.file)
        libraries = table.search(Query().PATH == args.component)[0]['LIBRARIES_USED']
        for library in libraries:
            self.print_libraries_used_recursive(table, library, [])

    def print_libraries_used_recursive(self, table, library, visited, depth = 1):
        if depth > self.depth:
            return
        print(f'{"  "*depth}{library}', file=self.file)
        libraries = table.search((Query().PATH == library) & (Query().COMPONENT == self.component))[0]['LIBRARIES_USED']
        for library in libraries:
            if library in visited:
                continue
            visited.append(library)
            self.print_libraries_used_recursive(table, library, visited.copy(), depth=depth+1)
        return

