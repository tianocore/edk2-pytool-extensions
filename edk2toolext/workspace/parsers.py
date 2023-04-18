# @file parsers.py
# A file containing the database parsers used by edk2_report.py
##
# Copyright (c) Microsoft Corporation
#
# SPDX-License-Identifier: BSD-2-Clause-Patent
##
"""This file provides classes that are responsible for parsing the workspace for edk2report.

The parsers are also responsible for placing this information into the database
and providing clear documentation on the table schema.
"""

import logging
import re
from pathlib import Path
import time
from joblib import Parallel, delayed

from edk2toollib.uefi.edk2.path_utilities import Edk2Path
from edk2toollib.uefi.edk2.parsers.inf_parser import InfParser as InfP
from edk2toollib.uefi.edk2.parsers.dsc_parser import DscParser as DscP
from edk2toollib.uefi.edk2.parsers.fdf_parser import FdfParser
from edk2toolext.environment.var_dict import VarDict

from tinydb import TinyDB
from tinyrecord import transaction


class _InfParser(InfP):
    """A subclass of the InfParser that takes into account the architecture."""
    SECTION_REGEX = re.compile(r"\[(.*)\]")
    SECTION_LIBRARY = "LibraryClasses"

    def __init__(self):
        super().__init__()
        self.ScopedLibraryDict = {}

    def ParseFile(self, filepath):
        super().ParseFile(filepath)
        self._parse_libraries()

    def _parse_libraries(self):

        current_section = ""
        arch = ""

        for line in self.Lines:
            match = self.SECTION_REGEX.match(line)

            if line.strip() == "":
                continue

            if line.strip().startswith("#"):
                continue

            # Match the current section we are in
            if match:
                section = match.group(1)

                # A Library section
                if section.startswith(self.SECTION_LIBRARY):
                    if section.count(".") == 1:
                        current_section, arch = tuple(section.split("."))
                    else:
                        current_section, arch = (section, "common")
                # Some other section
                else:
                    current_section = ""
                    arch = ""
                continue

            # Handle lines when we are in a library section
            if current_section == self.SECTION_LIBRARY:
                if arch in self.ScopedLibraryDict:
                    self.ScopedLibraryDict[arch].append(line.split()[0].strip())
                else:
                    self.ScopedLibraryDict[arch] = [line.split()[0].strip()]

    def get_libraries(self, archs: list[str]):
        libraries = self.ScopedLibraryDict.get("common", []).copy()

        for arch in archs:
            libraries + self.ScopedLibraryDict.get(arch, []).copy()
        return list(set(libraries))


class _DscParser(DscP):
    """A subclass of the Dsc Parser that takes into account the architecture."""
    SECTION_LIBRARY = "LibraryClasses"
    SECTION_COMPONENT = "Components"
    SECTION_REGEX = re.compile(r"\[(.*)\]")
    OVERRIDE_REGEX = re.compile(r"\<(.*)\>")

    def __init__(self):
        super().__init__()
        self.Components = []
        self.ScopedLibraryDict = {}

    def ParseFile(self, filepath):
        super().ParseFile(filepath)
        self._parse_libraries()
        self._parse_components()

    def _parse_libraries(self):
        """Builds a lookup table of all possible library instances depending on scope.

        The following is the key/value pair:
        key: The library class name with the scope appended. Examples below:
            $(LIB_NAME).$(ARCH).$(MODULE_TYPE)
            $(LIB_NAME).common.$(MODULE_TYPE)
            $(LIB_NAME).$(ARCH)
            $(LIB_NAME).common
        """
        current_scope = []
        lines = iter(self.Lines)

        try:
            while True:
                line = next(lines)
                current_scope = self._get_current_scope(current_scope, line, self.SECTION_LIBRARY)

                # The current section is not SECTION_LIBRARY, so we have no valid scopes. continue to next line.
                if not current_scope:
                    continue

                # This line is starting a new section with a new scope. Start reading the new line
                if self.SECTION_REGEX.match(line):
                    continue

                # We are in a valid section, so lets parse the line and add it to our dictionary.
                lib, instance = tuple(line.split("|"))
                for scope in current_scope:
                    key = f"{scope.strip()}.{lib.strip()}"
                    value = instance.strip()
                    self.ScopedLibraryDict[key] = value
        except StopIteration:
            return

    def _parse_components(self):
        current_scope = []
        lines = iter(self.Lines)

        try:
            while True:
                line = next(lines)

                current_scope = self._get_current_scope(current_scope, line, self.SECTION_COMPONENT)
                library_override_dict = {"NULL": []}

                # The current section is not SECTION_COMPONENT, so we have no valid scopes. continue to next line.
                if not current_scope:
                    continue

                # This line is starting a new section with a new scope. Start reading the new line
                if self.SECTION_REGEX.match(line):
                    continue

                # This component has overrides we need to handle
                if line.strip().endswith("{"):
                    line = str(line)
                    library_override_dict = self._build_library_override_dictionary(lines)
                self.Components.append((line.strip(" {"), current_scope[0], library_override_dict))

        except StopIteration:
            return

    def _get_current_scope(self, scope_list: list[str], line, section_type: str) -> list[str]:
        """Returns the list of scopes that this line is in, as long as the section_type is correct.

        Scopes can be different depending on the section type. Component sections can only
        contain a single scope, but library sections can contain multiple scopes.

        !!! warning
            The returned list of scopes does not include the section type.
        """
        match = self.SECTION_REGEX.match(line)

        # If the line is not a section header, return the old section
        if not match:
            return scope_list

        # If the line is a section header, but not the correct section type, return []
        elif not match.group().startswith(f"[{section_type}"):
            return []

        # The line must be a section header and of the correct section type. Return it
        current_section = []
        section_list = match.group().strip("[]").split(",")

        for section in section_list:
            # Remove the section type and strip the leftover '.'. If it's empty after that, then it is actually "common"
            current_section.append(section.replace(section_type, "").strip().lstrip(".") or "common")
        return current_section

    def _build_library_override_dictionary(self, lines):
        library_override_dictionary = {"NULL": []}
        section = ""

        line = next(lines)
        while line.strip() != "}":
            if self.OVERRIDE_REGEX.match(line) and line == f"<{self.SECTION_LIBRARY}>":
                section = self.SECTION_LIBRARY
                line = next(lines)
                continue
            if self.OVERRIDE_REGEX.match(line) and line != f"<{self.SECTION_LIBRARY}>":
                # TODO: Let the section be something else like PCD overrides
                section = ""
                line = next(lines)
                continue
            if section == self.SECTION_LIBRARY:
                lib, instance = tuple(line.split("|"))

                if lib.strip() == "NULL":
                    library_override_dictionary["NULL"].append(instance.strip())
                else:
                    library_override_dictionary[lib.strip()] = instance.strip()

            line = next(lines)
        return library_override_dictionary


class WorkspaceParser:
    """An interface for a workspace parser."""

    def is_dsc_scoped(self) -> bool:
        """Return if this parser relies on a DSC with the environment set."""
        return False

    def parse_workspace(self, db: TinyDB, pathobj: Edk2Path, env: VarDict) -> None:
        """Parse the workspace and update the database."""
        raise NotImplementedError


class CParser(WorkspaceParser):
    """A Workspace parser that parses all c and h files in the workspace.

    Generates a table with the following schema:

    table_name: "source"
    |-------------------------------------------------------------------------| # noqa: E501
    | PATH | LICENSE | TOTAL_LINES | CODE_LINES | COMMENT_LINES | BLANK_LINES | # noqa: E501
    |-------------------------------------------------------------------------| # noqa: E501
    """

    def parse_workspace(self, db: TinyDB, pathobj: Edk2Path, env: VarDict) -> None:
        """Parse the workspace and update the database."""
        ws = Path(pathobj.WorkspacePath)
        src_table = db.table("source", cache_size=None)

        start = time.time()
        files = list(ws.rglob("*.c")) + list(ws.rglob("*.h"))
        src_entries = Parallel(n_jobs=-1)(delayed(self._parse_file)(ws, filename) for filename in files)
        logging.debug(
            f"{self.__class__.__name__}: Parsed {len(src_entries)} .c/h files; "
            f"took {round(time.time() - start, 2)} seconds.")

        with transaction(src_table) as tr:
            tr.insert_multiple(src_entries)

    def _parse_file(self, ws, filename: Path) -> dict:
        """Parse a C file and return the results."""
        license = ""
        with open(filename, 'r', encoding='cp850') as f:
            for line in f.readlines():
                match = re.search(r"SPDX-License-Identifier:\s*(.*)$", line)  # TODO: This is not a standard format.
                if match:
                    license = match.group(1)
                    break

        return {
            "PATH": filename.relative_to(ws).as_posix(),
            "LICENSE": license,
            "TOTAL_LINES": 0,
            "CODE_LINES": 0,
            "COMMENT_LINES": 0,
            "BLANK_LINES": 0,
        }


class IParser(WorkspaceParser):
    """A Workspace parser that parses all INF files in the workspace.

    Generates a table with the following schema:

    table_name: "inf"
    |----------------------------------------------------------------------------------------------------------------------------| # noqa: E501
    | GUID | LIBRARY_CLASS | PATH | PHASES | SOURCES_USED | LIBRARIES_USED | PROTOCOLS_USED | GUIDS_USED | PPIS_USED | PCDS_USED | # noqa: E501
    |----------------------------------------------------------------------------------------------------------------------------| # noqa: E501
    """

    def parse_workspace(self, db: TinyDB, pathobj: Edk2Path, env: VarDict) -> None:
        """Parse the workspace and update the database."""
        ws = Path(pathobj.WorkspacePath)
        inf_table = db.table("inf", cache_size=None)
        inf_entries = []

        start = time.time()
        files = list(ws.glob("**/*.inf"))
        inf_entries = Parallel(n_jobs=-1)(delayed(self._parse_file)(ws, filename, pathobj) for filename in files)
        logging.debug(
            f"{self.__class__.__name__}: Parsed {len(inf_entries)} .inf files took; "
            f"{round(time.time() - start, 2)} seconds.")

        with transaction(inf_table) as tr:
            tr.insert_multiple(inf_entries)

    def _parse_file(self, ws, filename, pathobj) -> dict:
        inf_parser = InfP().SetEdk2Path(pathobj)
        inf_parser.ParseFile(filename)

        pkg = pathobj.GetContainingPackage(inf_parser.Path)
        path = str(inf_parser.Path)
        if pkg:
            path = path[path.find(pkg):]
        data = {}
        data["GUID"] = inf_parser.Dict.get("FILE_GUID", "")
        data["LIBRARY_CLASS"] = inf_parser.LibraryClass
        data["PATH"] = path
        data["PHASES"] = inf_parser.SupportedPhases
        data["SOURCES_USED"] = inf_parser.Sources
        data["BINARIES_USED"] = inf_parser.Binaries
        data["LIBRARIES_USED"] = inf_parser.LibrariesUsed
        data["PROTOCOLS_USED"] = inf_parser.ProtocolsUsed
        data["GUIDS_USED"] = inf_parser.GuidsUsed
        data["PPIS_USED"] = inf_parser.PpisUsed
        data["PCDS_USED"] = inf_parser.PcdsUsed

        return data


class DParser(WorkspaceParser):
    """A Workspace parser that parses a single DSC file.

    Generates a table with the following schema:

    table_name: "<PKGNAME>_inf"
    |----------------------------------------------------------------------------------------------------------------------------------| # noqa: E501
    | DSC | GUID | LIBRARY_CLASS | PATH | PHASES | SOURCES_USED | LIBRARIES_USED | PROTOCOLS_USED | GUIDS_USED | PPIS_USED | PCDS_USED | # noqa: E501
    |----------------------------------------------------------------------------------------------------------------------------------| # noqa: E501
    """
    SECTION_LIBRARY = "LibraryClasses"
    SECTION_COMPONENT = "Components"
    SECTION_REGEX = re.compile(r"\[(.*)\]")
    OVERRIDE_REGEX = re.compile(r"\<(.*)\>")

    def is_dsc_scoped(self) -> bool:
        """Return if this parser relies on a DSC with the environment set."""
        return True

    def parse_workspace(self, db: TinyDB, pathobj: Edk2Path, env: VarDict) -> None:
        """Parse the workspace and update the database."""
        self.pathobj = pathobj
        self.ws = Path(pathobj.WorkspacePath)
        self.dsc = env.GetValue("ACTIVE_PLATFORM")
        self.fdf = env.GetValue("FLASH_DEFINITION")
        self.arch = env.GetValue("TARGET_ARCH").split(" ")
        self.target = env.GetValue("TARGET")

        if not self.dsc:
            logging.debug("No Active Platform Set, Skipping DSC Parser")
            return

        # Our DscParser subclass can now parse components, their scope, and their overrides
        dscp = _DscParser().SetEdk2Path(pathobj)
        dscp.SetInputVars(env.GetAllBuildKeyValues() | env.GetAllNonBuildKeyValues())
        dscp.ParseFile(self.dsc)

        # Create the instanced inf entries, including components and libraries. multiple entries
        # of the same library will exist if multiple components use it.
        #
        # This is where we merge DSC parser information with INF parser information.
        inf_entries = self._build_inf_table(dscp)

        table_name = f'{str(Path(self.dsc).parent)}_{self.target}_dsc'
        table = db.table(table_name, cache_size=None)
        with transaction(table) as tr:
            tr.insert_multiple(inf_entries)

    def _build_inf_table(self, dscp: _DscParser):

        inf_entries = []
        for (inf, scope, overrides) in dscp.Components:
            logging.debug(f"Parsing Component: [{inf}]")
            infp = _InfParser().SetEdk2Path(self.pathobj)
            infp.ParseFile(inf)

            # Libraries marked as a component only have source compiled and do not link against other libraries
            if "LIBRARY_CLASS" in infp.Dict:
                continue

            # scope for libraries need to contain the MODULE_TYPE also, so we will append it, if it exists
            if "MODULE_TYPE" in infp.Dict:
                scope += f".{infp.Dict['MODULE_TYPE']}"

            inf_entries += self._parse_inf_recursively(inf, inf, dscp.ScopedLibraryDict, overrides, scope, [])

        # Move entries to correct table
        for entry in inf_entries:
            if entry["PATH"] == entry["COMPONENT"]:
                del entry["COMPONENT"]

        return inf_entries

    def _parse_inf_recursively(
            self, inf: str, component: str, library_dict: dict, override_dict: dict, scope: str, visited):
        """Recurses down all libraries starting from a single INF.

        Will immediately return if the INF has already been visited.
        """
        logging.debug(f"  Parsing Library: [{inf}]")
        visited.append(inf)
        library_instances = []

        #
        # 0. Use the existing parser to parse the INF file. This parser parses an INF as an independent file
        #    and does not take into account the context of a DSC.
        #
        infp = _InfParser().SetEdk2Path(self.pathobj)
        infp.ParseFile(inf)

        #
        # 1. Convert all libraries to their actual instances for this component. This takes into account
        #    any overrides for this component
        #
        for lib in infp.get_libraries(self.arch):
            lib = lib.split(" ")[0]
            library_instances.append(self._lib_to_instance(lib, scope, library_dict, override_dict))
        # Append all NULL library instances
        for null_lib in override_dict["NULL"]:
            library_instances.append(null_lib)

        # Time to visit in libraries that we have not visited yet.
        to_return = []
        for library in filter(lambda lib: lib not in visited, library_instances):
            to_return += self._parse_inf_recursively(library, component,
                                                     library_dict, override_dict, scope, visited)

        to_return.append({
            "DSC": self.dsc,
            "PATH": inf,
            "NAME": infp.Dict["BASE_NAME"],
            "COMPONENT": component,
            "MODULE_TYPE": infp.Dict["MODULE_TYPE"],
            "SOURCES_USED": infp.Sources,
            "LIBRARIES_USED": library_instances,
            "PROTOCOLS_USED": [],  # TODO
            "GUIDS_USED": [],  # TODO
            "PPIS_USED": [],  # TODO
            "PCDS_USED": infp.PcdsUsed,
        })
        return to_return

    def _lib_to_instance(self, library_class_name, scope, library_dict, override_dict):
        """Converts a library name to the actual instance of the library.

        This conversion is based off the library section definitions in the DSC.
        """
        arch, module = tuple(scope.split("."))

        # https://edk2-docs.gitbook.io/edk-ii-dsc-specification/3_edk_ii_dsc_file_format/38_-libraryclasses-_sections#summary

        # 1. If a Library class instance (INF) is specified in the Edk2 II [Components] section (an override),
        #    then it will be used
        if library_class_name in override_dict:
            return override_dict[library_class_name]

        # 2/3. If the Library Class instance (INF) is defined in the [LibraryClasses.$(ARCH).$(MODULE_TYPE)] section,
        #    then it will be used.
        lookup = f'{arch}.{module}.{library_class_name}'
        if lookup in library_dict:
            return library_dict[lookup]

        # 3. If the Library Class instance (INF) is defined in the [LibraryClasses.common.$(MODULE_TYPE)] section,
        #   then it will be used.
        lookup = f'common.{module}.{library_class_name}'
        if lookup in library_dict:
            return library_dict[lookup]

        # 4/5. If the Library Class instance (INF) is defined in the [LibraryClasses.$(ARCH)] section,
        #    then it will be used.
        lookup = f'{arch}.{library_class_name}'
        if lookup in library_dict:
            return library_dict[lookup]

        # 5. If the Library Class Instance (INF) is defined in the [LibraryClasses] section,
        #    then it will be used.
        lookup = f'common.{library_class_name}'
        if lookup in library_dict:
            return library_dict[lookup]

        logging.error(f"{lookup} is missing from dict.")


class FParser(WorkspaceParser):
    """A Workspace parser that parses a single FDF file.

    Generates a table with the following schema:

    table_name: "<PKGNAME>_fdf"
    |------------------------------------------------------| # noqa: E501
    | FDF | PATH | TARGET | FV_NAME | INF_LIST | FILE_LIST | # noqa: E501
    |------------------------------------------------------| # noqa: E501
    """

    def is_dsc_scoped(self) -> bool:
        """Return if this parser relies on a DSC with the environment set."""
        return True

    def parse_workspace(self, db: TinyDB, pathobj: Edk2Path, env: VarDict) -> None:
        """Parse the workspace and update the database."""
        self.pathobj = pathobj
        self.ws = Path(pathobj.WorkspacePath)
        self.dsc = env.GetValue("ACTIVE_PLATFORM")
        self.fdf = env.GetValue("FLASH_DEFINITION")
        self.arch = env.GetValue("TARGET_ARCH").split(" ")
        self.target = env.GetValue("TARGET")

        # Our DscParser subclass can now parse components, their scope, and their overrides
        fdfp = FdfParser().SetEdk2Path(pathobj)
        fdfp.SetInputVars(env.GetAllBuildKeyValues() | env.GetAllNonBuildKeyValues())
        fdfp.ParseFile(self.fdf)

        table_name = f'{str(Path(self.fdf).parent)}_{self.target}_fdf'
        table = db.table(table_name, cache_size=None)

        entry_list = []
        for fv in fdfp.FVs:

            inf_list = []  # Some INF's start with RuleOverride. We only need the INF
            for inf in fdfp.FVs[fv]["Infs"]:
                inf_list.append(inf.split(" ")[-1])

            entry_list.append({
                "FDF": Path(self.fdf).name,
                "PATH": self.fdf,
                "TARGET": env.GetValue("TARGET"),
                "FV_NAME": fv,
                "INF_LIST": inf_list,
                "FILE_LIST": fdfp.FVs[fv]["Files"]
            })

        with transaction(table) as tr:
            tr.insert_multiple(entry_list)
