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
import logging

from argparse import ArgumentParser, Namespace
from functools import reduce
from pathlib import Path
from tabulate import tabulate
from tinydb import Query, TinyDB
from tinydb.table import Document
import xml.dom.minidom as minidom
import xml.etree.ElementTree as ET

from edk2toollib.uefi.edk2.path_utilities import Edk2Path


class WorkspaceReport:
    """An interface for a report."""

    def report_info(self):
        """Returns the report standard information.

        Returns:
            (str, str): A tuple of (name, description)
        """
        raise NotImplementedError

    def add_cli_options(self, parserobj: ArgumentParser):
        """Configure command line arguments for this report."""
        return

    def run_report(self, db: TinyDB, edk2path: Edk2Path, args: Namespace) -> None:
        """Generate a report."""
        raise NotImplementedError

    def to_stdout(self, documents: list[Document], tablefmt="simple"):
        """Prints a tinydb table as a ascii table."""
        print(tabulate(documents, headers="keys", tablefmt=tablefmt, maxcolwidths=100))

    def columns(self, column_list: list[str], documents: list[Document], ):
        """Given a list of Documents, return it with only the specified columns."""
        filtered_list = []
        for document in documents:
            filtered_dict = {k: v for k, v in document.items() if k in column_list}
            filtered_list.append(Document(filtered_dict, document.doc_id))
        return filtered_list


class CoverageReport(WorkspaceReport):
    """A Report that converts coverage data from exe scope to INF scope."""

    def report_info(self):
        """Returns the report standard information.

        Returns:
            (str, str): A tuple of (name, description)
        """
        return ("coverage", "Associates coverage data to build objects like libraries and components.")

    def add_cli_options(self, parserobj: ArgumentParser):
        """Configure command line arguments for this report."""
        parserobj.add_argument("--XML", "--xml", required=True,
                               dest="xml", action="store", help="The path to the XML file parse.")
        parserobj.add_argument("-s", "--scope", "--Scope", "--SCOPE", default="inf", choices=["inf", "pkg"],
                               dest="scope", action="store", help="The scope to associate coverage data")
        parserobj.add_argument("--ignore-empty", action="store_true", help="To ignore inf's with no coverage.")
        parserobj.add_argument("--lib-only", action="store_true", help="To only show results for library INFs")

    def run_report(self, db: TinyDB, args: Namespace) -> None:
        """Generate the Coverage report."""
        self.args = args
        files = self._build_file_dict(args.xml)

        if args.scope == "inf":
            self._get_inf_cov(files, db, args.ignore_empty, args.lib_only)
        return 0

    def _get_inf_cov(self, files: dict, db: TinyDB, ignore_empty: bool, library_only: bool):
        table = db.table("inf")

        if library_only:
            table = table.search(Query().LIBRARY_CLASS != "")

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

        xml_string = ET.tostring(root, "utf-8")
        dom = minidom.parseString(xml_string)
        dt = minidom.getDOMImplementation('').createDocumentType(
            'coverage', None, "http://cobertura.sourceforge.net/xml/coverage-04.dtd")
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

    def report_info(self):
        """Returns the report standard information.

        Returns:
            (str, str): A tuple of (name, description)
        """
        return ("no-license", "Returns a list of files that do not have a valid license.")

    def add_cli_options(self, parserobj: ArgumentParser):
        """Configure command line arguments for this report."""
        parserobj.add_argument("--include", "--Include", "--INCLUDE",
                               dest="include", action="store",
                               help="A comma separated list strings to include in the search.")
        parserobj.add_argument("--exclude", "--Exclude", "--EXCLUDE",
                               dest="exclude", action="store",
                               help="A comma separated list strings to exclude in the search.")

    def run_report(self, db: TinyDB, args: Namespace) -> None:
        """Generate the License report."""
        table = db.table("source")
        regex = ""
        include = args.include
        exclude = args.exclude

        regex = "^"

        if include:
            regex += f"(?=.*({include.replace(',', '|')}))"
        if exclude:
            regex += f"(?!.*({exclude.replace(',', '|')})).*$"

        result = table.search((Query().LICENSE == "") & (Query().PATH.search(regex)))

        self.to_stdout(result)

        print(f"\n{len(result)} files with no license found.")
        return 0


class LibraryInfReport(WorkspaceReport):
    """A report that generates a list of library instances for a given library."""

    def report_info(self):
        """Returns the report standard information

        Returns:
            (str, str): A tuple of (name, description)
        """
        return ("list-library", "Generates a list of library instances for a given library")

    def add_cli_options(self, parserobj: ArgumentParser):
        """Configure command line arguments for this report."""
        parserobj.add_argument("--library", "--Library", "--LIBRARY", default="",
                               dest="library", action="store", help="The library class to search for.")

    def run_report(self, db: TinyDB, args: Namespace) -> None:
        """Generate the Library INF report."""
        table = db.table("inf")

        lib_type = args.library

        result = table.search((Query().LIBRARY_CLASS != "") & (Query().LIBRARY_CLASS.matches(lib_type)))
        r = self.columns(["LIBRARY_CLASS", "PATH"], result)
        self.to_stdout(r)
        return 0


class ComponentInfo(WorkspaceReport):
    """A report that provides information about a specific component."""

    def report_info(self):
        """Returns the report standard information

        Returns:
            (str, str): A tuple of (name, description)
        """
        return ("component-info", "Provides information about a specific component.")

    def add_cli_options(self, parserobj: ArgumentParser):
        """Configure command line arguments for this report."""
        parserobj.add_argument("-c", "--component", "--Component", "--COMPONENT", default="",
                               dest="component", action="store", help="The component to get information on.")
        parserobj.add_argument("-p", "--pkg", "--Pkg", "--PKG",
                               dest="package", action="store", help="The package the component is used in.")

    def run_report(self, db: TinyDB, args: Namespace) -> None:
        """Generate the Component Info report."""
        pkg = args.package
        component = args.component
        table = db.table(f'{pkg}_inf')
        entries = table.search((Query().PATH.search(component)) & ~ (Query().COMPONENT.exists()))

        self.to_stdout(self.columns(["NAME", "MODULE_TYPE", "LIBRARIES"], entries))
        return 0


class UnusedComponents(WorkspaceReport):
    """A report that returns any unused components for a specific build."""

    def report_info(self):
        """Returns the report standard information

        Returns:
            (str, str): A tuple of (name, description)
        """
        return ("unused", "Returns any unused components for a specific build")

    def add_cli_options(self, parserobj: ArgumentParser):
        """Configure command line arguments for this report."""
        parserobj.add_argument("-p", "--package", "--Package", "--PACKAGE",
                               required=True, dest="package", action="store",
                               help="The package name to find unused components / libraries in."
                               "ex: MyPlatformPkg")
        parserobj.add_argument("--ignoreapp", "--IgnoreApp", "--IGNOREAPP",
                               dest="ignoreapp", action="store_true",
                               help="Ignore unused UEFI Application components.")

    def run_report(self, db: TinyDB, args: Namespace) -> None:
        """Generate the Unused Component report."""
        total_unused_components = []
        total_unused_libraries = []

        for target in ["DEBUG", "RELEASE"]:
            fdf_table_name = f'{args.package}_{target}_fdf'
            dsc_table_name = f'{args.package}_{target}_dsc'
            logging.debug("Quering the following tables:")
            logging.debug(f"  {fdf_table_name}, {dsc_table_name}")
            fdf = db.table(fdf_table_name)
            dsc = db.table(dsc_table_name)
            if len(fdf) == 0 or len(dsc) == 0:
                logging.error(f"Missing Data! fdf table size: {len(fdf)}, dsc table size: {len(dsc)}. ")
                logging.error("Verify name of fdf/dsc and that they have been parsed.")
                return -1

            all_components = []
            fdf_components = []

            # Grab all components from the DSC
            entries = dsc.search(~ Query().COMPONENT.exists())
            for entry in entries:
                if args.ignoreapp and entry["MODULE_TYPE"] == "UEFI_APPLICATION":
                    continue
                all_components.append(entry["PATH"])

            # Grab all components from the FDF
            for entry in fdf:
                fdf_components.extend(entry["INF_LIST"])

            # Calculate the unused components for this target
            unused_components = set(all_components) - set(fdf_components)
            used_components = set(fdf_components)

            unused_component_library_list = []
            used_component_library_list = []

            # Grab all libraries used by components that are not used
            for component in unused_components:
                self._recurse_inf(component, dsc, unused_component_library_list)

            # Grab all libraries used by components that are used
            for component in used_components:
                self._recurse_inf(component, dsc, used_component_library_list)

            # The unused libraries for this target is the difference between the two
            unused_libraries = set(unused_component_library_list) - set(used_component_library_list)

            # Insert so we have an array of arrays. This is because at the end, we need to take the
            # Intersection of the arrays
            total_unused_components.append(unused_components)
            total_unused_libraries.append(unused_libraries - unused_components)

        print("Unused Components:")
        for inf in reduce(lambda acc, curr: acc.intersection(curr), total_unused_components):
            print(f'  {inf}')

        print("Unused Libraries:")
        for inf in reduce(lambda acc, curr: acc.intersection(curr), total_unused_libraries):
            print(f'  {inf}')

        return 0

    def _recurse_inf(self, inf, table, library_list):
        if inf in library_list:
            return

        library_list.append(inf)
        for inf in table.search(Query().PATH == inf)[0]["LIBRARIES_USED"]:
            self._recurse_inf(inf, table, library_list)
