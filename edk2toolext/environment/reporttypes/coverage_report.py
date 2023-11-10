# @file coverage_report.py
# A report that re-organizes a cobertura.xml by INF.
##
# Copyright (c) Microsoft Corporation
#
# SPDX-License-Identifier: BSD-2-Clause-Patent
##
"""A report that re-organizes a cobertura.xml by INF."""
import fnmatch
import logging
import re
import xml.dom.minidom as minidom
import xml.etree.ElementTree as ET
from argparse import Action, ArgumentParser, Namespace
from pathlib import Path

from edk2toollib.database import Edk2DB
from edk2toollib.uefi.edk2.path_utilities import Edk2Path

from edk2toolext.environment.reporttypes.base_report import Report

SOURCE_QUERY = """
SELECT inf.path, junction.key2 as source
FROM
    inf
    LEFT JOIN junction ON inf.path = junction.key1
WHERE
    junction.table1 = 'inf'
    AND junction.table2 = 'source'
    AND UPPER(SUBSTR(junction.key2, -2)) = '.C'
    AND junction.env = ?;
"""

INSTANCED_SOURCE_QUERY = """
WITH variable AS (
    SELECT
        ? AS env -- VARIABLE: Change this to the environment parse you care about
)
SELECT
    inf_list.path,
    junction.key2
FROM
    (
        SELECT
            DISTINCT instanced_inf.path
        FROM
            variable,
            instanced_fv
            JOIN junction ON instanced_fv.env = junction.env
                AND junction.table1 = 'instanced_fv'
                AND junction.table2 = 'inf'
            JOIN instanced_inf ON instanced_inf.env = junction.env
                AND instanced_inf.component = junction.key2
        WHERE
            instanced_fv.env = variable.env
    ) inf_list,
    variable
    JOIN junction ON junction.key1 = inf_list.path
    AND junction.table2 = 'source'
    AND UPPER(SUBSTR(junction.key2, -2)) = '.C'
    AND junction.env = variable.env
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
    AND environment_values.value = ?
ORDER BY environment.date DESC
LIMIT 1;
"""

class SplitCommaAction(Action):
    """A Custom action similar to append, but will split the input string on commas first."""
    def __call__(self, parser, namespace, values, option_string=None):
       """Command entry."""
       setattr(namespace, self.dest, getattr(namespace, self.dest, []) + values.split(','))

class CoverageReport(Report):
    """A report that re-organizes a cobertura.xml by INF.

    This report will supports two modes, by-package and by-platform. By-package will only include coverage data for
    files in the specified edk2 packages. By-platform will only include coverage data for files used to build the
    specified platform dsc.
    """
    def report_info(self):
        """Returns the report standard information.

        Returns:
            (str, str): A tuple of (name, description)
        """
        return ("coverage", "Reorganizes an xml coverage report by INF rather than executable. Filters results based "
                "on --by-package or --by-platform flags.")

    def add_cli_options(self, parserobj: ArgumentParser):
        """Configure command line arguments for this report."""
        # Group 1 - Calculate coverage only for files in a specific package
        group = parserobj.add_argument_group("Coverage by package options")
        group.add_argument("--by-package", action="store_true", dest="by_package", default=False,
                           help="Filters test coverage to only files in the specified packages(s)")
        group.add_argument("-p", "--package", "--Package", "--PACKAGE", dest="package_list",
                           action=SplitCommaAction, default=[],
                           help="The package to include in the report. Can be specified multiple times.")

        # Group 2 - Calculate coverage only on files used by a specific platform
        group = parserobj.add_argument_group("Coverage by platform options")
        group.add_argument("--by-platform", action="store_true", dest="by_platform", default=False,
                           help="Filters test coverage to all files used to build the specified platform package.")
        group.add_argument("-d", "--dsc", "--DSC", dest="dsc",
                           help="Edk2 relative path the ACTIVE_PLATFORM DSC file.")

        # Group 3 - Run either by-platform or by-package with a FULL report
        group = parserobj.add_argument_group("Full Report")
        group.add_argument("--full", action="store_true", dest="full", default=False,
                           help="Include all files in the report, not just those with coverage data. Requires pygount.")
        group.add_argument("-ws", "--workspace", "--Workspace", "--WORKSPACE", dest="workspace",
                               help="The Workspace root associated with the xml argument.", default=".")

        # Other args
        parserobj.add_argument(dest="xml", action="store", help="The path to the XML file parse.")
        parserobj.add_argument("-o", "--output", "--Output", "--OUTPUT", dest="output", default="Coverage.xml",
                               help="The path to the output XML file.", action="store")
        parserobj.add_argument("-e", "--exclude", "--Exclude", "--EXCLUDE", dest="exclude",
                               action=SplitCommaAction, default=[],
                               help="Package path relative paths or file (.txt). Globbing is supported. Can be "
                               "specified multiple times")
        parserobj.add_argument("--flatten", action="store_true", dest="flatten", default=False,
                              help="Flatten the report to only source files. This removes duplicate files that are in "
                              "multiple INFs.")

    def run_report(self, db: Edk2DB, args: Namespace) -> None:
        """Generate the Coverage report."""
        self.args = args

        if self.args.full:
            self.verify_pygount()

        self.update_excluded_files()

        if args.by_package:
            logging.info("Organizing coverage report by Package.")
            return self.run_by_package(db)
        if args.by_platform:
            logging.info("Organizing coverage report by Platform.")
            return self.run_by_platform(db)

        logging.error("No report type specified via command line or configuration file.")
        return -1

    def run_by_platform(self, db: Edk2DB):
        """Runs the report, only adding coverage data for source files used to build the platform.

        Args:
            db (Edk2DB): The database containing the necessary data

        Returns:
            (bool): True if the report was successful, False otherwise.
        """
        # Verify valid ACTIVE_PLATFORM
        dsc = self.args.dsc
        if not dsc:
            logging.error("No ACTIVE_PLATFORM dsc file specified. It should be edk2 package path relative.")
            return -1
        logging.info(f"ACTIVE_PLATFORM requested: {dsc}")

        # Get env_id
        result = db.connection.execute(ID_QUERY_BY_PACKAGE, (dsc,)).fetchone()
        if result is None:
            logging.error(f"Could not locate an ACTIVE_PLATFORM containing the provided package: {dsc}")
            return -1
        env_id, = result

        package_list = [pkg for pkg, in db.connection.execute(PACKAGE_LIST_QUERY).fetchall()]

        # Build source / coverage association dictionary
        coverage_files = self.build_source_coverage_dictionary(self.args.xml, package_list)

        # Build inf / source association dictionary
        package_files = self.build_inf_source_dictionary(db, env_id, INSTANCED_SOURCE_QUERY, package_list)

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

        # Build inf / source association dictionary
        package_files = self.build_inf_source_dictionary(db, env_id, SOURCE_QUERY, package_list)

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
                file.attrib["name"] = "\\".join(Path(path).parts)
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

    def build_inf_source_dictionary(self, db: Edk2DB, env_id: int, query: str, package_list: list) -> dict:
        """Builds a dictionary of INFs and the source files they use.

        Args:
            db (Edk2DB): The database containing the necessary data
            env_id (int): The environment id to query
            query (str): The query to use to get the data
            package_list (list): The packages to filter the results by

        Returns:
            dict[str, list[str]]: A dictionary of INFs and the source files they use.
        """
        entry_dict = {}
        results = db.connection.execute(query, (env_id,)).fetchall()

        for inf, source in results:
            if not any(inf.startswith(pkg) for pkg in package_list):
                continue
            inf
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
        pp_list = re.split(r'[:;]', pp_list)
        edk2path = Edk2Path(self.args.workspace, pp_list)

        root = ET.Element("coverage")
        sources = ET.SubElement(root, "sources")
        # Set the sources so that reports can find the right paths.
        source = ET.SubElement(sources, "source")
        source.text = self.args.workspace
        for pp in pp_list:
            source = ET.SubElement(sources, "source")
            source.text = str(Path(self.args.workspace, pp))

        packages = ET.SubElement(root, "packages")
        for path, source_list in inf_source_dict.items():
            if fnmatch.fnmatch(path, "*Test*"):
                continue
            if not source_list:
                continue
            inf = ET.SubElement(packages, "package", path=path, name=Path(path).name)
            classes = ET.SubElement(inf, "classes")

            for source in source_list:
                # Check if the file should be excluded
                exclude_file = False
                for pattern in self.args.exclude:
                    if fnmatch.fnmatch(source, pattern):
                        logging.debug(f'{source} excluded due to {pattern}')
                        exclude_file = True
                        break
                if exclude_file:
                    continue

                match = next((key for key in source_coverage_dict.keys() if Path(source).is_relative_to(key)), None)
                if match is not None:
                    classes.append(source_coverage_dict[match])
                elif self.args.full:
                    classes.append(self.create_file_xml(source, edk2path))

        # Flaten the report to only source files, removing duplicates from INFs.
        if self.args.flatten:
            root = self.flatten_report(root, edk2path)

        xml_string = ET.tostring(root, "utf-8")
        dom = minidom.parseString(xml_string)
        dt = minidom.getDOMImplementation('').createDocumentType(
            'coverage', None, "http://cobertura.sourceforge.net/xml/coverage-04.dtd")
        dom.insertBefore(dt, dom.documentElement)
        p = Path(self.args.output)
        p.unlink(missing_ok=True)
        with open(p, 'wb') as f:
            f.write(dom.toprettyxml(encoding="utf-8", indent="  "))
        logging.info(f"Coverage xml data written to {p}")

    def update_excluded_files(self):
        """Replaces any files in the exclude list with their contents."""
        temporary_list = []
        for pattern in self.args.exclude:
            if Path(pattern).exists() and Path(pattern).suffix == ".txt":
                with open(pattern, "r") as f:
                    temporary_list.extend(f.read().splitlines())
            else:
                temporary_list.append(pattern)
        self.args.exclude = temporary_list

    def create_file_xml(self, source_path: str, edk2path: Edk2Path) -> ET:
        """Parses the source file and creates a coverage 'lines' xml element for it."""
        from pygount import SourceAnalysis
        full_path = edk2path.GetAbsolutePathOnThisSystemFromEdk2RelativePath(source_path)
        code_count = SourceAnalysis.from_file(full_path, "_").code_count
        file_xml = ET.Element("class", name="\\".join(Path(source_path).parts), filename=source_path)
        lines_xml = ET.Element("lines")

        for i in range(1, code_count + 1):
            lines_xml.append(ET.Element("line", number=str(i), hits="0"))
        file_xml.append(lines_xml)
        return file_xml

    def flatten_report(self, root: ET.Element, edk2path: Edk2Path) -> ET.Element:
        """Flattens the report to only source files, removing the INF layer and duplicate source files."""
        class_list = ET.Element("classes")

        class_dict = {}
        count = 0
        for class_element in root.iter("class"):
            filename = class_element.get('filename')
            filename = filename.replace("/", "\\")
            class_element.set("name", "\\".join(Path(filename).parts))
            class_dict[filename] = class_element
            count += 1

        for class_element in class_dict.values():
            class_list.append(class_element)

        package_element = ET.Element("package", name = "All Source")
        package_element.append(class_list)

        packages = root.find('.//packages')
        packages.clear()
        packages.append(package_element)
        return root

    def verify_pygount(self):
        """Verify that pygount is installed."""
        try:
            from pygount import SourceAnalysis  # noqa: F401
        except ImportError as e:
            print(e)
            print("WARNING: This report requires pip modules not installed with edk2-pytool-extensions:")
            print("  Run the following command: `pip install pygount`")
            exit(-1)
