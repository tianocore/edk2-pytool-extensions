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
from pathlib import PurePath, Path

from edk2toollib.database import Edk2DB, Query


class Report:
    """The interface to create custom reports."""
    def report_info(self):
        """Returns the report standard information.

        Returns:
            (str, str): A tuple of (name, description)
        """
        return ("dump-component-libs", "Recursively dumps the libraries used by a component, and libraries used by "
                "those libraries.")

    def add_cli_options(self, parserobj: ArgumentParser):
        """Configure command line arguments for this report."""
        parserobj.add_argument(dest="component", action="store", help="The component to query.")
        parserobj.add_argument("-f", "--file", dest="file", default=sys.stdout, help="The file, to write the report to."
                               " Defaults to stdout.")
        parserobj.add_argument("-d", "--depth", dest="depth", type=int, default=999, help="The depth to recurse when "
                               "printing libraries used.")

    def run_report(self, db: Edk2DB, args: Namespace) -> None:
        """Runs the report."""
        if isinstance(args.file, str):
            if Path(args.file).exists():
                Path(args.file).unlink()
            self.file = open(args.file, 'w+')
        else:
            self.file = args.file

        self.depth = args.depth

        table_name = "instanced_inf"
        table = db.table(table_name)

        def compare_path(path):
            return PurePath(path).as_posix() in PurePath(args.component).as_posix()

        inf = table.search(Query().PATH.test(compare_path))[0]

        libraries = inf['LIBRARIES_USED']
        inf_path = inf['PATH']

        print(inf_path, file=self.file)
        for library in libraries:
            self.print_libraries_used_recursive(table, library, inf_path, [])

    def print_libraries_used_recursive(self, table, library, component, visited, depth = 1):
        """Prints the libraries used in a provided library / component."""
        library_class, library_instance = library
        if depth > self.depth:
            return
        print(f'{"  "*depth}- {library_class}| {library_instance or "NOT FOUND IN DSC"}', file=self.file)
        libraries = table.search((Query().PATH == library_instance) & (Query().COMPONENT == component))[0]['LIBRARIES_USED']
        for library in libraries:
            if library in visited:
                continue
            visited.append(library)
            self.print_libraries_used_recursive(table, library, component, visited.copy(), depth=depth+1)
        return

