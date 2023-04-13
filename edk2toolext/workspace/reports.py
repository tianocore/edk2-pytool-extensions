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
from tinydb import Query, TinyDB
from edk2toolext.environment.var_dict import VarDict
from tabulate import tabulate
from pathlib import Path
from argparse import ArgumentParser

class Report:
    """An interface for a report."""

    @classmethod
    def report_info(self):
        """Returns the report standard information

        Returns:
            (str, str): A tuple of (name, description)
        """
        raise NotImplementedError
    
    def add_cli_options(self, parserobj: ArgumentParser):
        """Configure command line arguments for this report."""
        return

    def generate_report(self, db: TinyDB, env: VarDict) -> None:
        """Generate a report."""
        raise NotImplementedError

    def to_stdout(self, documents: list[Document], tablefmt = "simple"):
        print(tabulate(documents, headers="keys", tablefmt=tablefmt))
    
    def columns(self, column_list: list[str], documents: list[Document], ):
        """Given a list of Documents, return it with only the specified columns."""
        filtered_list = []
        for document in documents:
            filtered_dict = {k: v for k, v in document.items() if k in column_list}
            filtered_list.append(Document(filtered_dict, document.doc_id))
        return filtered_list

class CoverageReport(Report):
    def report_info(self):
        """Returns the report standard information

        Returns:
            (str, str): A tuple of (name, description)
        """
        return ("coverage", "Associates coverage data to build objects like libraries and components.")

    def add_cli_options(self, parserobj: ArgumentParser):
        """Configure command line arguments for this report."""
        parserobj.add_argument("--XML", "--xml",
                               dest="xml", action="store", help="The path to the XML file parse.")


class LicenseReport(Report):
    """A report that lists all of the licenses in the workspace."""

    @classmethod
    def report_info(self):
        """Returns the report standard information

        Returns:
            (str, str): A tuple of (name, description)
        """
        return ("no-license", "Returns a list of files that do not have a valid license.")

    def add_cli_options(self, parserobj: ArgumentParser):
        """Configure command line arguments for this report."""
        
        parserobj.add_argument("--Include", "--INCLUDE",
                               dest = "include", action="store", help="A comma separated list strings to include in the search.")
        parserobj.add_argument("--Exclude", "--EXCLUDE",
                               dest = "exclude", action="store", help="A comma separated list strings to exclude in the search.")

      
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
        
        result = table.search( (Query().LICENSE == "") & (Query().PATH.search(regex)))
        
        self.to_stdout( result )

        print(f"\n{len(result)} files with no license found.")

class LibraryInfReport(Report):

    @classmethod
    def report_info(self):
        """Returns the report standard information

        Returns:
            (str, str): A tuple of (name, description)
        """
        return ("list-library", "Generates a list of library instances for a given library")

    def add_cli_options(self, parserobj: ArgumentParser):
        """Configure command line arguments for this report."""
        
        parserobj.add_argument("--Library", "--LIBRARY",
                               dest="library", action="store", help="The library class to search for.")

    def generate_report(self, db: TinyDB, env: VarDict) -> None:
        """Generate a report."""
        table = db.table("inf")

        lib_type = env.GetValue("LIBRARY", "")

        result = table.search((Query().LIBRARY_CLASS != "") & (Query().LIBRARY_CLASS.matches(lib_type)))
        r = self.columns(["LIBRARY_CLASS", "PATH"], result)
        self.to_stdout(r)
