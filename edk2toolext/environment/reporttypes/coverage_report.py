# @file coverage_report.py
# A report ingests a cobertura.xml file and organizes it by INF.
##
# Copyright (c) Microsoft Corporation
#
# SPDX-License-Identifier: BSD-2-Clause-Patent
##
"""A report ingests a cobertura.xml file and organizes it by INF."""
import logging
import re
import xml.dom.minidom as minidom
import xml.etree.ElementTree as ET
from argparse import ArgumentParser, Namespace
from pathlib import Path
import os

from edk2toollib.database import Edk2DB

from edk2toolext.environment.reporttypes.base_report import Report

SOURCE_QUERY = """
SELECT inf.path, inf.library_class, junction.key2 as source
FROM
    inf
    LEFT JOIN junction ON inf.path = junction.key1
WHERE
    junction.table1 = 'inf'
    AND junction.table2 = 'source'
    AND junction.env = ?;
"""

PACKAGE_PATH_QUERY = """
SELECT value
FROM environment_values
WHERE
    key = 'PACKAGES_PATH'
    AND id = ?;
"""

PACKAGE_LIST_QUERY = """
SELECT name
FROM package;
"""

ID_QUERY = """
SELECT id
FROM environment
ORDER BY date
DESC LIMIT 1;
"""

class CoverageReport(Report):
    """A report ingests a cobertura.xml file and organizes it by INF."""
    def report_info(self):
        """Returns the report standard information.

        Returns:
            (str, str): A tuple of (name, description)
        """
        return ("coverage", "Reorganizes an xml coverage report by INF rather than executable.")

    def add_cli_options(self, parserobj: ArgumentParser):
        """Configure command line arguments for this report."""
        parserobj.add_argument(dest="xml", action="store", help="The path to the XML file parse.")
        parserobj.add_argument("-o", "--output", "--Output", "--OUTPUT", dest="output", default="Coverage.xml",
                               help="The path to the output XML file.", action="store")
        parserobj.add_argument("-s", "--scope", "--Scope", "--SCOPE", default="inf", choices=["inf"],
                               dest="scope", action="store", help="The scope to associate coverage data")
        parserobj.add_argument("-p", "--package", "--Package", "--PACKAGE", dest="package_list", action="append",
                               default=[],
                               help="The package to include in the report. Can be specified multiple times.")
        parserobj.add_argument("-ws", "--workspace", "--Workspace", "--WORKSPACE", dest="workspace",
                               help="The Workspace root associated with the xml argument.", default=".")
        parserobj.add_argument("--library", action="store_true", dest="lib_only", default="False",
                               help="To only show results for library INFs")

    def run_report(self, db: Edk2DB, args: Namespace) -> None:
        """Generate the Coverage report."""
        self.args = args

        # If not packages are specified, use all packages in the database
        self.args.package_list = self.args.package_list or \
            [pkg for pkg, in db.connection.execute(PACKAGE_LIST_QUERY).fetchall()]

        files = self._build_file_dict(args.xml)

        if args.scope == "inf":
            logging.info("Organizing coverage report by INF.")
            self._get_inf_cov(files, db, args.lib_only)
        return 0

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

    def _get_inf_cov(self, files: dict, db: Edk2DB, library_only: bool):
        env_id, = db.connection.execute(ID_QUERY).fetchone()
        pp_list, = db.connection.execute(PACKAGE_PATH_QUERY, (env_id,)).fetchone()
        pp_list = pp_list.split(os.pathsep)

        # Build dictionary containing source files for each INF
        # If library_only, filter out INFs that do not have a library_class
        entry_dict = {}
        for inf, library_class, source in db.connection.execute(SOURCE_QUERY, (env_id,)):
            if library_only and library_class is None:
                continue
            if inf not in entry_dict:
                entry_dict[inf] = [source]
            else:
                entry_dict[inf].append(source)

        root = ET.Element("coverage")

        sources = ET.SubElement(root, "sources")
        # Set the sources so that reports can find the right paths.
        source = ET.SubElement(sources, "source")
        source.text = self.args.workspace
        for pp in pp_list:
            source = ET.SubElement(sources, "source")
            source.text = Path(str(self.args.workspace, pp))

        packages = ET.SubElement(root, "packages")
        for path, source_list in entry_dict.items():
            if not source_list:
                continue
            inf = ET.SubElement(packages, "package", path=path, name=Path(path).name)
            classes = ET.SubElement(inf, "classes")
            found = False
            for source in source_list:
                match = next((key for key in files.keys() if Path(source).is_relative_to(key)), None)
                if match is not None:
                    found = True
                    classes.append(files[match])
            if not found:
                packages.remove(inf)

        xml_string = ET.tostring(root, "utf-8")
        dom = minidom.parseString(xml_string)
        dt = minidom.getDOMImplementation('').createDocumentType(
            'coverage', None, "http://cobertura.sourceforge.net/xml/coverage-04.dtd")
        dom.insertBefore(dt, dom.documentElement)
        p = Path(self.args.output)
        p.unlink(missing_ok=True)
        with open(p, 'wb') as f:
            f.write(dom.toxml(encoding="utf-8"))
