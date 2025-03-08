# @file component_report.py
# A report to print information about a component that could be compiled.
##
# Copyright (c) Microsoft Corporation
#
# SPDX-License-Identifier: BSD-2-Clause-Patent
##
"""A report to print information about a component that could be compiled."""

import sys
from argparse import ArgumentParser, Namespace
from pathlib import Path, PurePath
from typing import Tuple

from edk2toollib.database import Edk2DB, Environment, InstancedInf, Session
from sqlalchemy import desc


class ComponentDumpReport:
    """A report to print information about a component that could be compiled."""

    def report_info(self) -> Tuple[str, str]:
        """Returns the report standard information.

        Returns:
            (str, str): A tuple of (name, description)
        """
        return ("component-libs", "Dumps the library instances used by  component.")

    def add_cli_options(self, parserobj: ArgumentParser) -> None:
        """Configure command line arguments for this report."""
        parserobj.add_argument(dest="component", action="store", help="The component to query.")
        parserobj.add_argument(
            "-o",
            "--out",
            dest="file",
            default=sys.stdout,
            help="The file, to write the report to. Defaults to stdout.",
        )
        parserobj.add_argument(
            "-d",
            "--depth",
            dest="depth",
            type=int,
            default=999,
            help="The depth to recurse when printing libraries used.",
        )
        parserobj.add_argument(
            "-f",
            "--flatten",
            dest="flatten",
            action="store_true",
            help="Flatten the list of libraries used in the component.",
        )
        parserobj.add_argument(
            "-s", "--sort", dest="sort", action="store_true", help="Sort the libraries listed in alphabetical order."
        )
        parserobj.add_argument(
            "-e", "--env", dest="env_id", action="store", help="The environment id to generate the report for."
        )

    def run_report(self, db: Edk2DB, args: Namespace) -> None:
        """Runs the report."""
        if isinstance(args.file, str):
            if Path(args.file).exists():
                Path(args.file).unlink()
            self.file = open(args.file, "w+")
        else:
            self.file = args.file

        self.depth = args.depth
        self.sort = args.sort

        self.component = PurePath(args.component).as_posix()

        with db.session() as session:
            self.env_id = args.env_id or session.query(Environment).order_by(desc(Environment.date)).first().id
            component = (
                session.query(InstancedInf)
                .filter_by(env=self.env_id, cls=None)
                .filter(InstancedInf.path.like(f"%{self.component}%"))
                .one()
            )

            if args.flatten:
                return self.print_libraries_flat(component.path, session)

            libraries = component.libraries
            if self.sort:
                libraries = sorted(libraries, key=lambda x: x.cls)

            print(component.path, file=self.file)
            for library in libraries:
                self.print_libraries_recursive(library, [], session)

    def print_libraries_recursive(self, library: InstancedInf, visited: list, session: Session, depth: int = 0) -> None:
        """Prints the libraries used in a provided library / component."""
        if depth >= self.depth:
            return

        library_class = library.cls
        library_instance = library.path

        print(f"{'  ' * depth}- {library_class}| {library_instance or 'NOT FOUND IN DSC'}", file=self.file)

        if library_instance is None:
            return
        libraries = library.libraries

        if self.sort:
            libraries = sorted(libraries, key=lambda x: x[1])

        for library in libraries:
            if library in visited:
                continue
            visited.append(library)
            self.print_libraries_recursive(library, visited.copy(), session, depth=depth + 1)
        return

    def print_libraries_flat(self, component: str, session: Session) -> None:
        """Prints the libraries used in a provided component."""
        libraries = (
            session.query(InstancedInf)
            .filter_by(env=self.env_id, component=component)
            .filter(InstancedInf.cls.isnot(None))
            .all()
        )

        length = max(len(library.cls) for library in libraries)
        if self.sort:
            libraries = sorted(libraries, key=lambda x: x.cls)

        for library in libraries:
            print(f"- {library.cls:{length}}| {library.path}", file=self.file)
