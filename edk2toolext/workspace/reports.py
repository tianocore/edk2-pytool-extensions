##
# Copyright (c) Microsoft Corporation
#
# SPDX-License-Identifier: BSD-2-Clause-Patent
##
"""This file provides classes responsible for generating reports on the workspace for edk2report.

Each file preforms this task by using the database created by the parsers.
"""

from tinydb.table import Document
from collections import namedtuple
from edk2toolext.workspace.parsers import Utilities
from tinydb import Query, TinyDB
from edk2toolext.environment.var_dict import VarDict
from tabulate import tabulate

class Report:
    """An interface for a report."""

    @classmethod
    def report_name(self):
        """Return the name of the report.
        
        This name is used when specifying the report to generate via the command line.
        It should not contain any spaces.
        """
        raise NotImplementedError
    
    def report_cli_args(self):
        """Return a list of command line arguments for this report.
        
        Return a named tuple containing name, description.
        
        namedtuple("Arg", ["name", "description"]])
        """
        return []

    def generate_report(self, db: TinyDB, env: VarDict) -> None:
        """Generate a report."""
        raise NotImplementedError
    
    def to_stdout(self, documents: list[Document], tablefmt = "simple"):
        print(tabulate(documents, headers="keys", tablefmt=tablefmt))

class LicenseReport(Report):
    """A report that lists all of the licenses in the workspace."""

    @classmethod
    def report_name(self):
        """Return the name of the report.
        
        This name is used when specifying the report to generate via the command line.
        It should not contain any spaces.
        """
        return "no-license"

    def report_cli_args(self):
        """Return a list of command line arguments for this report."""
        Arg = namedtuple("Arg", ["name", "description"])
        
        return [
            Arg("INCLUDE", "A comma separated list strings to include in the search"),
            Arg("EXCLUDE", "A comma separated list strings to exclude in the search")
        ]
      
    def generate_report(self, db: TinyDB, env: VarDict) -> None:
        """Generate a report."""
        table = db.table("source")
        regex = ""
        include = env.GetValue("INCLUDE", None)
        exclude = env.GetValue("EXCLUDE", None)

        regex = "^"

        if include:
            regex+=f"(?=.*({include.replace(',', '|')}))"
        if exclude:
            regex+=f"(?!.*({exclude.replace(',', '|')})).*$"
        

        result = table.search( (Query().license == "") & (Query().path.search(regex)))
        
        Utilities.table_print( result )

        print(f"\n{len(result)} files with no license found.")

class LibraryInfReport(Report):

    @classmethod
    def report_name(self):
        """Return the name of the report.
        
        This name is used when specifying the report to generate via the command line.
        It should not contain any spaces.
        """
        return "list-library"

    def report_cli_args(self):
        """Return a list of command line arguments for this report."""
        Arg = namedtuple("Arg", ["name", "description"])
        
        return [
            Arg("LIBRARY", "The library class to search for")
        ]

    def generate_report(self, db: TinyDB, env: VarDict) -> None:
        """Generate a report."""
        table = db.table("inf")

        lib_type = env.GetValue("LIBRARY", "")

        result = table.search( (Query().library_class.matches(lib_type)))
        self.to_stdout(result)

class Utilities:

    @classmethod
    def to_cli_table(cls, documents: list[Document]) -> str:
        columns = list(documents[0].keys())
        widths = [max(len(str(row[col])) for row in documents) for col in columns]

        for i, col in enumerate(columns):
            print(col.ljust(widths[i]), end=' ')
        print()

        for width in widths:
            print('-' * width, end=' ')
        print()

        for row in documents:
            for i,col in enumerate(columns):
                print(str(row[col]).ljust(widths[i]), end=' ')
            print()