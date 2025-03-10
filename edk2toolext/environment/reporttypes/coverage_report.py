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
import os
import re
import xml.dom.minidom as minidom
import xml.etree.ElementTree as ET
from argparse import Action, ArgumentParser, Namespace
from pathlib import Path
from typing import Optional, Sequence, Tuple

from edk2toollib.database import Edk2DB, Environment, Fv, Inf, InstancedInf, Package, Session, Source, Value
from edk2toollib.uefi.edk2.path_utilities import Edk2Path
from sqlalchemy import func
from sqlalchemy.orm import aliased

from edk2toolext.environment.reporttypes.base_report import Report


class SplitCommaAction(Action):
    """A Custom action similar to append, but will split the input string on commas first."""

    def __call__(
        self,
        parser: ArgumentParser,
        namespace: Namespace,
        values: str | Sequence[str],
        option_string: Optional[str] = None,
    ) -> None:
        """Command entry."""
        setattr(namespace, self.dest, getattr(namespace, self.dest, []) + values.split(","))


class CoverageReport(Report):
    """A report that re-organizes a cobertura.xml by INF.

    This report will supports two modes, by-package and by-platform. By-package will only include coverage data for
    files in the specified edk2 packages. By-platform will only include coverage data for files used to build the
    specified platform dsc.
    """

    def report_info(self) -> Tuple[str, str]:
        """Returns the report standard information.

        Returns:
            (str, str): A tuple of (name, description)
        """
        return (
            "coverage",
            "Reorganizes an xml coverage report by INF rather than executable. Filters results based "
            "on --by-package or --by-platform flags.",
        )

    def add_cli_options(self, parserobj: ArgumentParser) -> None:
        """Configure command line arguments for this report."""
        # Group 2 - Calculate coverage only on files used by a specific platform
        group = parserobj.add_argument_group("Coverage by platform options")
        group.add_argument(
            "--by-platform",
            action="store_true",
            dest="by_platform",
            default=False,
            help="Filters test coverage to all files used to build the specified platform package.",
        )
        group.add_argument("-d", "--dsc", "--DSC", dest="dsc", help="Edk2 relative path the ACTIVE_PLATFORM DSC file.")

        # Group 3 - Run either by-platform or by-package with a FULL report
        group = parserobj.add_argument_group("Full Report")
        group.add_argument(
            "--full",
            action="store_true",
            dest="full",
            default=False,
            help="Include all files in the report, not just those with coverage data. Requires pygount.",
        )
        group.add_argument(
            "-ws",
            "--workspace",
            "--Workspace",
            "--WORKSPACE",
            dest="workspace",
            help="The Workspace root associated with the xml argument.",
            default=".",
        )

        # Other args
        parserobj.add_argument(dest="xml", action="store", help="The path to the XML file parse.")
        parserobj.add_argument(
            "-o",
            "--output",
            "--Output",
            "--OUTPUT",
            dest="output",
            default="Coverage.xml",
            help="The path to the output XML file.",
            action="store",
        )
        parserobj.add_argument(
            "-e",
            "--exclude",
            "--Exclude",
            "--EXCLUDE",
            dest="exclude",
            action=SplitCommaAction,
            default=[],
            help="Package path relative paths or file (.txt). Globbing is supported. Can be specified multiple times",
        )
        parserobj.add_argument(
            "-p",
            "--package",
            "--Package",
            "--PACKAGE",
            dest="package_list",
            action=SplitCommaAction,
            default=[],
            help="The package to include in the report. Can be specified multiple times.",
        )
        parserobj.add_argument(
            "--flatten",
            action="store_true",
            dest="flatten",
            default=False,
            help="Flatten the report to only source files. This removes duplicate files that are in multiple INFs.",
        )
        group = parserobj.add_argument_group("Deprecated Options")
        group.add_argument(
            "--by-package",
            action="store_true",
            dest="by_package",
            default=False,
            help="Filters test coverage to only files in the specified packages(s)",
        )

    def run_report(self, db: Edk2DB, args: Namespace) -> None:
        """Generate the Coverage report."""
        self.args = args

        if self.args.full:
            self.verify_pygount()

        self.update_excluded_files()

        with db.session() as session:
            package_list = self.args.package_list or [pkg.name for pkg in session.query(Package).all()]
            logging.info(f"Packages requested: {', '.join(package_list)}")
            if args.by_platform:
                logging.info("Organizing coverage report by Platform.")
                return self.run_by_platform(session, package_list)
            if args.by_package:
                logging.warning(
                    "The --by-package flag is deprecated and will be removed in a future release."
                    " by-package is now the default behavior and overriden with by-platform."
                )
            return self.run_by_package(session, package_list)

    def run_by_platform(self, session: Session, package_list: list) -> None:
        """Runs the report, only adding coverage data for source files used to build the platform.

        Args:
            session (Session): The session associated with the database
            package_list (list): The list of packages to filter the results by

        Returns:
            (bool): True if the report was successful, False otherwise.
        """
        # Verify valid ACTIVE_PLATFORM
        dsc = self.args.dsc
        if not dsc:
            logging.error("No ACTIVE_PLATFORM dsc file specified. It should be edk2 package path relative.")
            return -1
        logging.info(f"ACTIVE_PLATFORM requested: {dsc}")

        result = (
            session.query(Environment)
            .filter(Environment.values.any(key="ACTIVE_PLATFORM", value=dsc))
            .order_by(Environment.date.desc())
            .first()
        )

        if result is None:
            logging.error(f"Could not locate an ACTIVE_PLATFORM containing the provided package: {dsc}")
            return -1
        env_id = result.id

        # Build source / coverage association dictionary
        coverage_files = self.build_source_coverage_dictionary(self.args.xml, package_list)

        # Build inf / source association dictionary
        inf_alias = aliased(InstancedInf)
        inf_list = (
            session.query(inf_alias)
            .join(Fv.infs)
            .join(inf_alias, InstancedInf.path == inf_alias.component)
            .filter(Fv.env == env_id)
            .filter(inf_alias.env == env_id)
            .filter(InstancedInf.env == env_id)
            .group_by(inf_alias.path)
            .distinct(inf_alias.path)
            .all()
        )
        data = [
            (inf.path, source.path) for inf in inf_list for source in inf.sources if source.path.lower().endswith(".c")
        ]

        package_files = self.build_inf_source_dictionary(data, package_list)

        # Build the report
        return self.build_report(session, env_id, coverage_files, package_files)

    def run_by_package(self, session: Session, package_list: list) -> bool:
        """Runs the report, only adding coverage data for source files in the specified packages.

        Args:
            session (Session): The session associated with the database
            package_list (list): The list of packages to filter the results by

        Returns:
            (bool): True if the report was successful, False otherwise.
        """
        # Get env_id
        (env_id,) = session.query(Environment.id).order_by(Environment.date.desc()).first()

        # Build source / coverage association dictionary
        coverage_files = self.build_source_coverage_dictionary(self.args.xml, package_list)

        # Build inf / source association dictionary
        data = (
            session.query(Inf.path, Source.path)
            .join(Inf.sources)
            .filter(func.lower(Source.path).endswith(".c"))
            .group_by(Inf.path, Source.path)
            .distinct(Inf.path, Source.path)
            .all()
        )
        package_files = self.build_inf_source_dictionary(data, package_list)

        # Build the report
        return self.build_report(session, env_id, coverage_files, package_files)

    def build_source_coverage_dictionary(self, xml_path: str, package_list: list) -> dict:
        """Builds a dictionary of source files and their coverage data.

        Args:
            xml_path (str): path to xml file storing coverage data
            package_list (list): list of packages that a file must be in to be included in the report

        Returns:
            dict[str, ET.Element]: A dictionary of source files and their coverage data.
        """
        tree = ET.parse(xml_path)
        regex = re.compile("|".join(map(re.escape, package_list)))
        file_dict = {}
        for file in tree.iter("class"):
            # Add the file results if they do not exist
            filename = file.get("filename")
            match = regex.search(filename)

            # Skip the file if it is not in a package the user care about (-p)
            if not match:
                continue

            path = Path(filename[match.start() :]).as_posix()
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

    def build_inf_source_dictionary(self, data: dict, package_list: list) -> dict:
        """Builds a dictionary of INFs and the source files they use.

        Args:
            data (dict): The data to build the dictionary from
            package_list (list): The packages to filter the results by

        Returns:
            dict[str, list[str]]: A dictionary of INFs and the source files they use.
        """
        entry_dict = {}

        for inf, source in data:
            if not any(inf.startswith(pkg) for pkg in package_list):
                continue
            if inf not in entry_dict:
                entry_dict[inf] = [source]
            else:
                entry_dict[inf].append(source)
        return entry_dict

    def build_report(self, session: Session, env_id: int, source_coverage_dict: dict, inf_source_dict: dict) -> None:
        """Builds the report.

        For each source file in each INF in the inf_source dictionary, look to see if there is coverage data for it in
        the source_coverage dictionary. If it exists, insert it into the new report. Writes the final report to the
        specified file.
        """
        pp_list = session.query(Value).filter_by(env_id=env_id, key="PACKAGES_PATH").one().value
        pp_list = pp_list.split(os.pathsep)
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
                        logging.debug(f"{source} excluded due to {pattern}")
                        exclude_file = True
                        break
                if exclude_file:
                    continue

                match = next((key for key in source_coverage_dict.keys() if Path(source).is_relative_to(key)), None)
                if match is not None:
                    classes.append(source_coverage_dict[match])
                elif self.args.full:
                    xml = self.create_source_xml(source, edk2path)
                    if xml is not None:
                        classes.append(xml)

        # Flaten the report to only source files, removing duplicates from INFs.
        if self.args.flatten:
            root = self.flatten_report(root, edk2path)

        xml_string = ET.tostring(root, "utf-8")
        dom = minidom.parseString(xml_string)
        dt = minidom.getDOMImplementation("").createDocumentType(
            "coverage", None, "http://cobertura.sourceforge.net/xml/coverage-04.dtd"
        )
        dom.insertBefore(dt, dom.documentElement)
        p = Path(self.args.output)
        p.unlink(missing_ok=True)
        with open(p, "wb") as f:
            f.write(dom.toprettyxml(encoding="utf-8", indent="  "))
        logging.info(f"Coverage xml data written to {p}")

    def update_excluded_files(self) -> None:
        """Replaces any files in the exclude list with their contents."""
        temporary_list = []
        for pattern in self.args.exclude:
            if Path(pattern).exists() and Path(pattern).suffix == ".txt":
                with open(pattern, "r") as f:
                    temporary_list.extend(f.read().splitlines())
            else:
                temporary_list.append(pattern)
        self.args.exclude = temporary_list

    def create_source_xml(self, source_path: str, edk2path: Edk2Path) -> Optional[ET.Element]:
        """Parses the source file and creates a coverage 'lines' xml element for it."""
        from pygount import SourceAnalysis

        full_path = edk2path.GetAbsolutePathOnThisSystemFromEdk2RelativePath(source_path, log_errors=False)
        if full_path is None:
            logging.warning(f"Could not find {source_path} in the workspace. Skipping...")
            return None
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
        for class_element in root.iter("class"):
            filename = class_element.get("filename")
            filename = "\\".join(Path(filename).parts)
            class_element.set("name", filename)
            class_dict[filename] = class_element

        for class_element in class_dict.values():
            class_list.append(class_element)

        package_element = ET.Element("package", name="All Source")
        package_element.append(class_list)

        packages = root.find(".//packages")
        packages.clear()
        packages.append(package_element)
        return root

    def verify_pygount(self) -> None:
        """Verify that pygount is installed."""
        try:
            from pygount import SourceAnalysis  # noqa: F401
        except ImportError as e:
            print(e)
            print("WARNING: This report requires pip modules not installed with edk2-pytool-extensions:")
            print("  Run the following command: `pip install pygount`")
            exit(-1)
