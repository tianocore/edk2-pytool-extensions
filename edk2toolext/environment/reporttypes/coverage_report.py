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

from edk2toollib.database import Edk2DB, Query

from edk2toolext.environment.reporttypes.base_report import Report


class CoverageReport(Report):
    """A report ingests a cobertura.xml file and organizes it by INF."""
    def report_info(self):
        """Returns the report standard information.

        Returns:
            (str, str): A tuple of (name, description)
        """
        return ("coverage", "Converts an xml coverage report into a similar xml coverage report, but organized as specified by `-s`.")

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
                               help="The Workspace root to associate with the report.", default=".")
        parserobj.add_argument("--library", action="store_true", dest="lib_only", default="False",
                               help="To only show results for library INFs")

    def run_report(self, db: Edk2DB, args: Namespace) -> None:
        """Generate the Coverage report."""
        self.args = args
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
        inf_table = db.table("inf")
        env_table = db.table("environment")
        packages_path = env_table.all()[-1]["PACKAGES_PATH"].split(";")
        if library_only:
            inf_table = inf_table.search(Query().LIBRARY_CLASS != "")

        root = ET.Element("coverage")

        sources = ET.SubElement(root, "sources")
        # Set the sources so that reports can find the right paths.
        source = ET.SubElement(sources, "source")
        source.text = self.args.workspace
        for pp in packages_path:
            source = ET.SubElement(sources, "source")
            source.text = pp

        packages = ET.SubElement(root, "packages")
        for entry in inf_table:
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
        p = Path(self.args.output)
        p.unlink(missing_ok=True)
        with open(p, 'wb') as f:
            f.write(dom.toxml(encoding="utf-8"))
