# @file component_query.py
# A query to print information about a component that could be compiled.
##
# Copyright (c) Microsoft Corporation
#
# SPDX-License-Identifier: BSD-2-Clause-Patent
##
"""An interface to create custom reports with."""
import sys
from argparse import ArgumentParser, Namespace
from pathlib import Path, PurePath
from typing import Tuple

from edk2toollib.database import Edk2DB


class ComponentDumpReport:
    """The interface to create custom reports."""
    def report_info(self):
        """Returns the report standard information.

        Returns:
            (str, str): A tuple of (name, description)
        """
        return ("component-libs", "Dumps the library instances used by a component.")

    def add_cli_options(self, parserobj: ArgumentParser):
        """Configure command line arguments for this report."""
        parserobj.add_argument(dest="component", action="store", help="The component to query.")
        parserobj.add_argument("-o", "--out", dest="file", default=sys.stdout, help="The file, to write the report to."
                               " Defaults to stdout.")
        parserobj.add_argument("-d", "--depth", dest="depth", type=int, default=999, help="The depth to recurse when "
                               "printing libraries used.")
        parserobj.add_argument("-f", "--flatten", dest="flatten", action="store_true",
                               help="Flatten the list of libraries used in the component.")
        parserobj.add_argument("-s", "--sort", dest="sort", action="store_true",
                               help="Sort the libraries listed in alphabetical order.")

    def run_report(self, db: Edk2DB, args: Namespace) -> None:
        """Runs the report."""
        if isinstance(args.file, str):
            if Path(args.file).exists():
                Path(args.file).unlink()
            self.file = open(args.file, 'w+')
        else:
            self.file = args.file

        self.depth = args.depth
        self.sort = args.sort

        table_name = "instanced_inf"
        table = db.table(table_name)

        def compare_path(path):
            return PurePath(path).as_posix() in PurePath(args.component).as_posix()

        inf = table.search(Query().PATH.test(compare_path))[0]

        # Print in flat format
        if args.flatten:
            return self.print_libraries_flat(table, inf['PATH'])

        # Print in recursive format
        libraries = inf['LIBRARIES_USED']
        if self.sort:
            libraries = sorted(libraries)

        print(inf['PATH'], file=self.file)
        for library in libraries:
            self.print_libraries_recursive(table, library, inf['PATH'], [])

    def print_libraries_recursive(self, table, library: Tuple[str, str], component: str, visited: list, depth: int = 0):
        """Prints the libraries used in a provided library / component."""
        library_class, library_instance = library
        if depth > self.depth:
            return
        print(f'{"  "*depth}- {library_class}| {library_instance or "NOT FOUND IN DSC"}', file=self.file)
        if library_instance is None:
            return
        libraries = table.search(
            (Query().PATH == library_instance) & (Query().COMPONENT == component)
        )[0]['LIBRARIES_USED']

        if self.sort:
            libraries = sorted(libraries)

        for library in libraries:
            if library in visited:
                continue
            visited.append(library)
            self.print_libraries_recursive(table, library, component, visited.copy(), depth=depth+1)
        return

    def print_libraries_flat(self, table, component):
        """Prints the libraries used in a provided component."""
        libraries = table.search(Query().COMPONENT == component)

        if self.sort:
            libraries = sorted(libraries, key=lambda x: x['LIBRARY_CLASS'])

        for library in libraries:
            print(f'- {library["LIBRARY_CLASS"]}| {library["PATH"]}', file=self.file)
