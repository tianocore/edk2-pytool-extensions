# @file coverage_report.py
# A report ingests a cobertura.xml file and organizes it by INF.
##
# Copyright (c) Microsoft Corporation
#
# SPDX-License-Identifier: BSD-2-Clause-Patent
##
"""A report ingests a cobertura.xml file and organizes it by INF."""
import logging
import os
import re
import xml.dom.minidom as minidom
import xml.etree.ElementTree as ET
from argparse import ArgumentParser, Namespace, Action
from pathlib import Path
import json

from edk2toollib.database import Edk2DB

from edk2toolext.environment.reporttypes.base_report import Report

SOURCE_QUERY = """
SELECT inf.path, junction.key2 as source
FROM
    inf
    LEFT JOIN junction ON inf.path = junction.key1
WHERE
    junction.table1 = 'inf'
    AND junction.table2 = 'source'
    AND junction.env = ?;
"""

INSTANCED_SOURCE_QUERY = """
SELECT DISTINCT instanced_inf, source
FROM instanced_inf_source_junction
WHERE env = ?
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

ID_QUERY_BY_PACKAGE = """
SELECT environment.id
FROM
    environment
    LEFT JOIN environment_values ON environment.id = environment_values.id
WHERE
    environment_values.key = 'ACTIVE_PLATFORM'
    AND environment_values.value LIKE '%' || ? || '%'
LIMIT 1;
"""

class SplitCommaAction(Action):
    """A Custom action similar to append, but will split the input string on commas first."""
    def __call__(self, parser, namespace, values, option_string=None):
       """Command entry."""
       setattr(namespace, self.dest, getattr(namespace, self.dest, []) + values.split(','))

class CoverageReport(Report):
    """A report ingests a cobertura.xml file and organizes it by INF."""
    def report_info(self):
        """Returns the report standard information.

        Returns:
            (str, str): A tuple of (name, description)
        """
        return ("coverage", "Reorganizes an xml coverage report by INF rather than executable. Filters results based "
                "on --by-package or --by-platform flags.")

    def add_cli_options(self, parserobj: ArgumentParser):
        """Configure command line arguments for this report."""
        group = parserobj.add_mutually_exclusive_group(required=True)
        group.add_argument("--by-package", action="store_true", dest="by_package", default=False,
                           help="Filters test coverage to only files in the specified packages(s)")
        group.add_argument("--by-platform", action="store_true", dest="by_platform", default=False,
                           help="Filters test coverage to all files used to build the specified platform package.")
        parserobj.add_argument(dest="xml", action="store", help="The path to the XML file parse.")
        parserobj.add_argument("-o", "--output", "--Output", "--OUTPUT", dest="output", default="Coverage.xml",
                               help="The path to the output XML file.", action="store")
        parserobj.add_argument("-ws", "--workspace", "--Workspace", "--WORKSPACE", dest="workspace",
                               help="The Workspace root associated with the xml argument.", default=".")
        parserobj.add_argument("-p", "--package", "--Package", "--PACKAGE", dest="package_list",
                               action=SplitCommaAction, default=[],
                               help="The package to include in the report. Can be specified multiple times.")
        parserobj.add_argument("-e", "--exclude", "--Exclude", "--EXCLUDE", dest="exclude",
                               action=SplitCommaAction, default=[],
                               help="INFs (and their associated sources) to exclude from the report. Can be specified "
                               "multiple times")

    def run_report(self, db: Edk2DB, args: Namespace) -> None:
        """Generate the Coverage report."""
        self.args = args
        if args.by_package:
            logging.info("Organizing coverage report by Package.")
            return self.run_by_package(db)
        if args.by_platform:
            logging.info("Organizing coverage report by Platform.")
            return self.run_by_platform(db)

        return -1

    def run_by_platform(self, db: Edk2DB):
        """Runs the report, only adding coverage data for source files used to build the platform.

        Args:
            db (Edk2DB): The database containing the necessary data

        Returns:
            (bool): True if the report was successful, False otherwise.
        """
        # Verify valid platform package
        if len(self.args.package_list) > 1:
            logging.error("Invalid package provided. --by-platform requires a single platform package be provided.")
            logging.error("Please specify a single platform package with the -p flag.")
            return -1
        package = self.args.package_list[0]
        logging.info(f"Platform requested: {package}")

        # Get env_id
        result = db.connection.execute(ID_QUERY_BY_PACKAGE, (package,)).fetchone()
        if result is None:
            logging.error(f"Could not locate an ACTIVE_PLATFORM containing the provided package: {package}")
            return -1
        env_id, = result

        package_list = [pkg for pkg, in db.connection.execute(PACKAGE_LIST_QUERY).fetchall()]

        # Build source / coverage association dictionary
        coverage_files = self.build_source_coverage_dictionary(self.args.xml, package_list)

        # Build inf / source association dictionary
        package_files = self.build_inf_source_dictionary(db, env_id, INSTANCED_SOURCE_QUERY)

        # Build the report
        return self.build_report(db, env_id, coverage_files, package_files)

    def run_by_package(self, db: Edk2DB):
        """Runs the report, only adding coverage data for source files in the specified packages.

        Args:
            db (Edk2DB): The database containing the necessary data

        Returns:
            (bool): True if the report was successful, False otherwise.
        """
        # Get package_list
        package_list = self.args.package_list or \
            [pkg for pkg, in db.connection.execute(PACKAGE_LIST_QUERY).fetchall()]
        logging.info(f"Packages requested: {', '.join(package_list)}")

        # Get env_id
        env_id, = db.connection.execute(ID_QUERY).fetchone()

        # Build source / coverage association dictionary
        coverage_files = self.build_source_coverage_dictionary(self.args.xml, package_list)

        # Build inf / source assocation dictionary
        package_files = self.build_inf_source_dictionary(db, env_id, SOURCE_QUERY)

        # Build the report
        return self.build_report(db, env_id, coverage_files, package_files)

    def build_source_coverage_dictionary(self, xml_path: str, package_list: list) -> dict:
        """Builds a dictionary of source files and their coverage data.

        Args:
            xml_path (str): path to xml file storing coverage data
            package_list (list): list of packages that a file must be in to be included in the report

        Returns:
            dict[str, ET.Element]: A dictionary of source files and their coverage data.
        """
        tree = ET.parse(xml_path)
        regex = re.compile('|'.join(map(re.escape, package_list)))
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

    def build_inf_source_dictionary(self, db: Edk2DB, env_id: int, query: str) -> dict:
        """Builds a dictionary of INFs and the source files they use.

        Args:
            db (Edk2DB): The database containing the necessary data
            env_id (int): The environment id to query
            query (str): The query to use to get the data

        Returns:
            dict[str, list[str]]: A dictionary of INFs and the source files they use.
        """
        entry_dict = {}
        results = db.connection.execute(query, (env_id,)).fetchall()

        for inf, source in results:
            if inf not in entry_dict:
                entry_dict[inf] = [source]
            else:
                entry_dict[inf].append(source)
        return entry_dict

    def build_report(self, db: Edk2DB, env_id: int, source_coverage_dict: dict, inf_source_dict: dict):
        """Builds the report.

        For each source file in each INF in the inf_source dictionary, look to see if there is coverage data for it in
        the source_coverage dictionary. If it exists, insert it into the new report. Writes the final report to the
        specified file.
        """
        pp_list, = db.connection.execute(PACKAGE_PATH_QUERY, (env_id,)).fetchone()
        pp_list = pp_list.split(os.pathsep)

        root = ET.Element("coverage")
        sources = ET.SubElement(root, "sources")
        # Set the sources so that reports can find the right paths.
        source = ET.SubElement(sources, "source")
        source.text = self.args.workspace
        for pp in pp_list:
            source = ET.SubElement(sources, "source")
            source.text = str(Path(self.args.workspace, pp))

        packages = ET.SubElement(root, "packages")
        results = {}
        for path, source_list in inf_source_dict.items():
            if path in self.args.exclude:
                logging.debug(f"Excluding INF {path} from report due to --exclude flag.")
                continue
            if not source_list:
                continue
            inf = ET.SubElement(packages, "package", path=path, name=Path(path).name)
            classes = ET.SubElement(inf, "classes")
            found = False
            for source in source_list:
                match = next((key for key in source_coverage_dict.keys() if Path(source).is_relative_to(key)), None)
                if match is not None:
                    found = True
                    classes.append(source_coverage_dict[match])
                    results[source] = True
                else:
                    results[source] = False
            if not found:
                logging.debug(f'{path} has no coverage data.')
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
        logging.info(f"Coverage xml data written to {p}")

        p = Path(self.args.output).with_suffix(".json")
        p.unlink(missing_ok=True)
        with open(p, 'w') as f:
            json.dump(results, f, indent=4)
        logging.info(f"Covered files report written to {p}")
