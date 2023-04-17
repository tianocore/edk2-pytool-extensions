# @file reports.py
# A file containing the report generators used by edk2_report.py
##
# Copyright (c) Microsoft Corporation
#
# SPDX-License-Identifier: BSD-2-Clause-Patent
##
"""This file provides classes responsible for generating reports on the workspace for edk2report.

Each report preforms this task by using the database created by the parsers.
"""
import re

from argparse import ArgumentParser, Namespace
from pathlib import Path
from tabulate import tabulate
from tinydb import Query, TinyDB
from tinydb.table import Document
import xml.dom.minidom as minidom
import xml.etree.ElementTree as ET

from edk2toolext.environment.var_dict import VarDict
from edk2toollib.uefi.edk2.path_utilities import Edk2Path


class WorkspaceReport:
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

    def generate_report(self, db: TinyDB, edk2path: Edk2Path, args: Namespace) -> None:
        """Generate a report."""
        raise NotImplementedError

    def to_stdout(self, documents: list[Document], tablefmt = "simple"):
        print(tabulate(documents, headers="keys", tablefmt=tablefmt, maxcolwidths=100))
    
    def columns(self, column_list: list[str], documents: list[Document], ):
        """Given a list of Documents, return it with only the specified columns."""
        filtered_list = []
        for document in documents:
            filtered_dict = {k: v for k, v in document.items() if k in column_list}
            filtered_list.append(Document(filtered_dict, document.doc_id))
        return filtered_list


class CoverageReport(WorkspaceReport):
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

    def generate_report(self, db: TinyDB, args: Namespace) -> None:
        self.args = args
        files = self._build_file_dict(args.xml)
        
        if args.scope == "inf":
            self._get_inf_cov(files, db, args.ignore_empty, args.lib_only)
        return 0

    def _get_inf_cov(self, files: dict, db: TinyDB, ignore_empty: bool, library_only: bool):
        table = db.table("inf")
        import pprint

        if library_only:
            table = table.search( Query().LIBRARY_CLASS != "")

        root = ET.Element("coverage")

        sources = ET.SubElement(root, "sources")

        # Set the sources so that reports can find the right paths.
        source = ET.SubElement(sources, "source")
        source.text = self.args.workspace_root
        for pp in self.args.packages_path_list:
            source = ET.SubElement(sources, "source")
            source.text = pp

        packages = ET.SubElement(root, "packages")
        for entry in table:
            if not entry["SOURCES_USED"]:
                continue

            inf = ET.SubElement(packages, "package", path=entry["PATH"], name=Path(entry["PATH"]).name)
            classes = ET.SubElement(inf, "classes")
            found = False
            for source in entry["SOURCES_USED"]:
                source = Path(Path(entry["PATH"]).parent, source).as_posix()
                if source in files:
                    found = True
                    classes.append(files[source])
            if not found:
                packages.remove(inf)

        xml_string = ET.tostring(root,"utf-8")
        dom = minidom.parseString(xml_string)
        dt = minidom.getDOMImplementation('').createDocumentType('coverage', None, "http://cobertura.sourceforge.net/xml/coverage-04.dtd")
        dom.insertBefore(dt, dom.documentElement)
        p = Path("tmp.xml")
        p.unlink(missing_ok=True)
        with open(p, 'wb') as f:
            f.write(dom.toxml(encoding="utf-8"))

    def _build_file_dict(self, xml_path: str) -> dict:
        tree = ET.parse(xml_path)
        regex = re.compile('|'.join(map(re.escape, self.args.package_list)))
        file_dict = {}
        for file in tree.iter("class"):
            # Add the file results if they do not exist
            filename = file.get("filename")
            match = regex.search(filename)
            
            # Skip the file if it is not in a package the user care about (-p)
            if not match:
                continue
            
            path = Path(filename[match.start():]).as_posix()
            if path not in file_dict:
                file.attrib["filename"] = path
                file.attrib["name"] = Path(path).name
                file_dict[path] = file
            
            # Merge the file results
            else:
                to_update = file_dict[path]
                
                # Merge lines first
                for line in file.find("lines").iter():
                    line_number = line.attrib.get("number")
                    if not line_number:
                        continue
                    match = to_update.find("lines").find(f".//line[@number='{line_number}']")
                    match.set("hits", str(int(match.attrib.get("hits")) + int(line.attrib.get("hits"))))
        return file_dict     

class LicenseReport(WorkspaceReport):
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
        
        parserobj.add_argument("--include", "--Include", "--INCLUDE",
                               dest = "include", action="store", help="A comma separated list strings to include in the search.")
        parserobj.add_argument("--exclude", "--Exclude", "--EXCLUDE",
                               dest = "exclude", action="store", help="A comma separated list strings to exclude in the search.")

      
    def generate_report(self, db: TinyDB, args: Namespace) -> None:
        """Generate a report."""
        table = db.table("source")
        regex = ""
        include = args.include
        exclude = args.exclude

        regex = "^"

        if include:
            regex+=f"(?=.*({include.replace(',', '|')}))"
        if exclude:
            regex+=f"(?!.*({exclude.replace(',', '|')})).*$"
        
        result = table.search( (Query().LICENSE == "") & (Query().PATH.search(regex)))
        
        self.to_stdout( result )

        print(f"\n{len(result)} files with no license found.")
        return 0


class LibraryInfReport(WorkspaceReport):

    @classmethod
    def report_info(self):
        """Returns the report standard information

        Returns:
            (str, str): A tuple of (name, description)
        """
        return ("list-library", "Generates a list of library instances for a given library")

    def add_cli_options(self, parserobj: ArgumentParser):
        """Configure command line arguments for this report."""
        parserobj.add_argument("--library", "--Library", "--LIBRARY", default = "",
                               dest="library", action="store", help="The library class to search for.")

    def generate_report(self, db: TinyDB, args: Namespace) -> None:
        """Generate a report."""
        table = db.table("inf")

        lib_type = args.library

        result = table.search((Query().LIBRARY_CLASS != "") & (Query().LIBRARY_CLASS.matches(lib_type)))
        r = self.columns(["LIBRARY_CLASS", "PATH"], result)
        self.to_stdout(r)
        return 0


class ComponentInfo(WorkspaceReport):

    @classmethod
    def report_info(self):
        """Returns the report standard information

        Returns:
            (str, str): A tuple of (name, description)
        """
        return("component-info", "Provides information about a specific component.")
    
    def add_cli_options(self, parserobj: ArgumentParser):
        """Configure command line arguments for this report."""
        parserobj.add_argument("-c", "--component", "--Component", "--COMPONENT", default="",
                               dest="component", action="store", help="The component to get information on.")
        parserobj.add_argument("-p", "--pkg", "--Pkg", "--PKG",
                               dest="package", action="store", help="The package the component is used in.")
    
    def generate_report(self, db: TinyDB, args: Namespace) -> None:
        pkg = args.package
        component = args.component
        table = db.table(f'{pkg}_inf')
        entries = table.search((Query().PATH.search(component)) & ~ (Query().COMPONENT.exists()))
        
        self.to_stdout(self.columns(["NAME", "MODULE_TYPE", "LIBRARIES"], entries))
        return 0