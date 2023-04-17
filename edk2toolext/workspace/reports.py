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
import xml.dom.minidom as minidom
from edk2toollib.uefi.edk2.path_utilities import Edk2Path
import re

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

    def generate_report(self, db: TinyDB, edk2path: Edk2Path, args) -> None:
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

    def generate_report(self, db: TinyDB, args) -> None:
        self.args = args
        files = self._build_file_dict(args.xml)
        
        if args.scope == "inf":
            self.to_stdout(self._get_inf_cov(files, db, args.ignore_empty, args.lib_only))
    
    def _get_inf_cov(self, files: dict, db: TinyDB, ignore_empty: bool, library_only: bool):
        table = db.table("inf")
        import pprint
        
        if library_only:
            table = table.search( Query().LIBRARY_CLASS != "")

        root = ET.Element("coverage")
        #root.insert(0, ET.XML(r'<?xml version="1.0" encoding="utf-8"?>'))
        #root.insert(0,ET.fromstring('!DOCTYPE coverage SYSTEM "http://cobertura.sourceforge.net/xml/coverage-04.dtd"'))
        sources = ET.SubElement(root, "sources")
        source = ET.SubElement(sources, "source")
        source.text = "."

        packages = ET.SubElement(root, "packages")

        #pprint.pprint(files)
        #exit()

        for entry in table:
            if not entry["SOURCES_USED"]:
                continue

            inf = ET.SubElement(packages, "package", name=entry["PATH"])
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
        #print(dom.toprettyxml(encoding="utf-8"))
        #print(dom.toprettyxml())

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
        
        parserobj.add_argument("--Include", "--INCLUDE",
                               dest = "include", action="store", help="A comma separated list strings to include in the search.")
        parserobj.add_argument("--Exclude", "--EXCLUDE",
                               dest = "exclude", action="store", help="A comma separated list strings to exclude in the search.")

      
    def generate_report(self, db: TinyDB, edk2path: Edk2Path, env: VarDict) -> None:
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
        parserobj.add_argument("--Library", "--LIBRARY",
                               dest="library", action="store", help="The library class to search for.")

    def generate_report(self, db: TinyDB, edk2path: Edk2Path, env: VarDict) -> None:
        """Generate a report."""
        table = db.table("inf")

        lib_type = env.GetValue("LIBRARY", "")

        result = table.search((Query().LIBRARY_CLASS != "") & (Query().LIBRARY_CLASS.matches(lib_type)))
        r = self.columns(["LIBRARY_CLASS", "PATH"], result)
        self.to_stdout(r)


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
        parserobj.add_argument("-c", "--component", "--Component", "--COMPONENT",
                               dest="component", action="store", help="The component to get information on.")
        parserobj.add_argument("-p", "--pkg", "--Pkg", "--PKG",
                               dest="package", action="store", help="The package the component is used in.")
    
    def generate_report(self, db: TinyDB, edk2path: Edk2Path, args) -> None:
        pkg = args.package
        component = args.component
        table = db.table(f'{pkg}_inf')
        entries = table.search(Query().PATH == component)
        for e in entries:
            print(e)
        
        print(entries)
