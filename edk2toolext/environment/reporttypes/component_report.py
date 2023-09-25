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

COMPONENT_QUERY = """
SELECT path
FROM instanced_inf
WHERE
    (path LIKE ? OR ? LIKE '%' || path || '%')
    AND env = ?;
"""

LIBRARY_QUERY = """
SELECT ii.class, iij.instanced_inf2
FROM instanced_inf_junction AS iij
JOIN instanced_inf as ii
    ON
        ii.env = iij.env
        AND ii.component = iij.component
        AND iij.instanced_inf2 = ii.path
WHERE
    iij.env = ?
    AND iij.component = ?
    AND iij.instanced_inf1 = ?;
"""

FLAT_LIBRARY_QUERY = """
SELECT class, path
FROM instanced_inf
WHERE
    component = ?
    AND env = ?
    AND path != component;
"""

ID_QUERY = """
SELECT id
FROM environment
ORDER BY date
DESC LIMIT 1;
"""

class ComponentDumpReport:
    """The interface to create custom reports."""
    def report_info(self):
        """Returns the report standard information.

        Returns:
            (str, str): A tuple of (name, description)
        """
        return ("component-libs", "Dumps the library instances used by  component.")

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
        parserobj.add_argument("-e", "--env", dest="env_id", action="store",
                               help="The environment id to generate the report for.")

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
        self.conn = db.connection

        self.env_id = args.env_id or self.conn.execute(ID_QUERY).fetchone()[0]
        self.component = PurePath(args.component).as_posix()

        inf_path, = self.conn.execute(
            COMPONENT_QUERY, (f'%{self.component}%', self.component, self.env_id)).fetchone()
        # Print in flat format
        if args.flatten:
            return self.print_libraries_flat(inf_path)

        # Print in recursive format
        libraries = self.conn.execute(LIBRARY_QUERY, (self.env_id, self.component, self.component)).fetchall()

        if self.sort:
            libraries = sorted(libraries, key=lambda x: x[1])

        print(inf_path, file=self.file)
        for library in libraries:
            self.print_libraries_recursive(library, [])

    def print_libraries_recursive(self, library: Tuple[str, str], visited: list, depth: int = 0):
        """Prints the libraries used in a provided library / component."""
        library_class, library_instance = library
        if depth >= self.depth:
            return
        print(f'{"  "*depth}- {library_class}| {library_instance or "NOT FOUND IN DSC"}', file=self.file)

        if library_instance is None:
            return

        libraries = self.conn.execute(LIBRARY_QUERY, (self.env_id, self.component, library_instance)).fetchall()

        if self.sort:
            libraries = sorted(libraries, key=lambda x: x[1])

        for library in libraries:
            if library in visited:
                continue
            visited.append(library)
            self.print_libraries_recursive( library, visited.copy(), depth=depth+1)
        return

    def print_libraries_flat(self, component):
        """Prints the libraries used in a provided component."""
        libraries = self.conn.execute(FLAT_LIBRARY_QUERY, (component,self.env_id)).fetchall()

        length = max(len(item[0]) for item in libraries)
        if self.sort:
            libraries = sorted(libraries, key=lambda x: x[0])

        for library in libraries:
            print(f'- {library[0]:{length}}| {library[1]}', file=self.file)
