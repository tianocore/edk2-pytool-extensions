##
# Copyright (c) Microsoft Corporation
#
# SPDX-License-Identifier: BSD-2-Clause-Patent
##
"""This file provides classes responsible for generating reports on the workspace for edk2report.

Each file preforms this task by using the database created by the parsers.
"""

from tinydb.table import Document
from tinydb import Query, TinyDB
from edk2toolext.environment.var_dict import VarDict
from tabulate import tabulate
from pathlib import Path
from argparse import ArgumentParser
import xml.etree.ElementTree as ET

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

    def generate_report(self, db: TinyDB, args) -> None:
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
        parserobj.add_argument("--XML", "--xml", required = True,
                               dest="xml", action="store", help="The path to the XML file parse.")
        parserobj.add_argument("-s", "--scope", "--Scope", "--SCOPE", default="inf", choices=["inf", "pkg"],
                                dest="scope", action="store", help="The scope to associate coverage data")
        parserobj.add_argument("--ignore-empty", action="store_true", help="To ignore inf's with no coverage.")
        parserobj.add_argument("--lib-only", action="store_true", help="To only show results for library INFs")

    def generate_report(self, db: TinyDB, args) -> None:
        
        files = self._build_file_dict(args.xml)
        
        if args.scope == "inf":
            self.to_stdout(self._get_inf_cov(files, db, args.ignore_empty, args.lib_only))

    def _get_inf_cov(self, files: dict, db: TinyDB, ignore_empty: bool, library_only: bool):
        table = db.table("inf")

        if library_only:
            table = table.search( Query().LIBRARY_CLASS != "")

        inf_entries = []
        # TODO: Count untested files
        for entry in table:
            if not entry["SOURCES_USED"]:
                continue
            
            hit = 0
            total = 0
            missed = 0
            for source in entry["SOURCES_USED"]:
                if source in files:
                    total += len(files[source])
                    hit += len({key: value for key, value in files[source].items() if value == "1"})
                    missed += len({key: value for key, value in files[source].items() if value == "0"})
            
            if not ignore_empty or total > 0:
                inf_entries.append(
                    {
                        "PATH": entry["PATH"],
                        "HIT": hit,
                        "MISS": missed,
                        "TOTAL": total,
                        "PERCENT": "0.0%" if total == 0 else f"{round((hit / total)*100,2)}%" 
                    }
                )
            
        return inf_entries


    def _build_file_dict(self, xml_path: str) -> dict:
        tree = ET.parse(xml_path)
        
        file_hits = {}
        for package in tree.iter("package"):
            for file in package.iter("class"):
                name = file.attrib["name"]
                line_hit_dict = file_hits.get(name, {})
                for line in file.iter('line'):
                    num = line.attrib["number"]
                    hit = line.attrib["hits"]

                    if line_hit_dict.get(num, 0) == 0:
                        line_hit_dict[num] = hit
                file_hits[name] = line_hit_dict

        # Delete any empty entries.
        return {k: v for k, v in file_hits.items() if v}
                    

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

class ComponentInfo(Report):

    @classmethod
    def report_info(self):
        """Returns the report standard information

        Returns:
            (str, str): A tuple of (name, description)
        """
        return("component-info", "Provides information about a specific component.")
    
    def add_cli_options(self, parserobj: ArgumentParser):
        """Configure command line arguments for this report."""
        parserobj.add_argument("-c", "--component", "--Component", "--COMPONENT",
                               dest="component", action="store", help="The component to get information on.")
        parserobj.add_argument("-p", "--pkg", "--Pkg", "--PKG",
                               dest="package", action="store", help="The package the component is used in.")
    
    def generate_report(self, db: TinyDB, args) -> None:
        pkg = args.package
        component = args.component
        table = db.table(f'{pkg}_inf')
        entries = table.search(Query().PATH == component)
        for e in entries:
            print(e)
        
        print(entries)
