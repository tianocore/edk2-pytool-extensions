##
# Copyright (c) Microsoft Corporation
#
# SPDX-License-Identifier: BSD-2-Clause-Patent
##
"""This file provides classes that are responsible for parsing the workspace for edk2report.

The parsers are also responsible for placing this information into the database
and providing clear documentation on the table schema."""

import logging
import re
from pathlib import Path
import time
from joblib import Parallel, delayed

from edk2toollib.uefi.edk2.path_utilities import Edk2Path
from edk2toollib.uefi.edk2.parsers.inf_parser import InfParser
from edk2toollib.uefi.edk2.parsers.dsc_parser import DscParser
from edk2toolext.environment.var_dict import VarDict

from tinydb.table import Table
from tinyrecord import transaction

# logger = logging.getLogger(__name__)

class WorkspaceParser:
    """An interface for a workspace parser."""

    def parse_workspace(self, tables: dict[str, Table], pathobj: Edk2Path, env: VarDict) -> None:
        """Parse the workspace and update the database."""
        raise NotImplementedError
    
    def get_tables(self) -> list[str]:
        """Return a list of tables that should be provided to the parser."""
        raise NotImplementedError
    
class CParser(WorkspaceParser):
    """A Workspace parser that parses all c and h files in the workspace and generates a table with the following schema:
    
    table_name: "source"
    |-------------------------------------------------------------------------|
    | PATH | LICENSE | TOTAL_LINES | CODE_LINES | COMMENT_LINES | BLANK_LINES |
    |-------------------------------------------------------------------------|
    """
    def parse_workspace(self, tables: dict[str, Table], pathobj: Edk2Path, env: VarDict) -> None:
        """Parse the workspace and update the database."""

        ws = Path(pathobj.WorkspacePath)
        src_table = tables["source"]
        
        start = time.time()
        files = list(ws.rglob("*.c")) + list(ws.rglob("*.h"))
        src_entries = Parallel(n_jobs=-1)(delayed(self._parse_file)(ws, filename) for filename in files)
        logging.debug(f"{self.__class__.__name__}: Parsed {len(src_entries)} .c/h files took {round(time.time() - start, 2)} seconds.")

        start = time.time()
        with transaction(src_table) as tr:
            tr.insert_multiple(src_entries)
        logging.debug(f"{self.__class__.__name__}: Adding files to database took {round(time.time() - start, 2)} seconds.")
    
    def get_tables(self) -> list[str]:
        """Return a list of tables that should be provided to the parser."""
        return ["source"]
    
    def _parse_file(self, ws, filename: Path) -> dict:
        """Parse a C file and return the results."""
        license = ""
        with open (filename, 'r', encoding='cp850') as f:
            for line in f.readlines():
                match = re.search(r"SPDX-License-Identifier:\s*(.*)$", line) # TODO: This is not a standard format.
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
    """A Workspace parser that parses all INF files in the workspace and generates a table with the following schema:
    
    table_name: "inf"
    |----------------------------------------------------------------------------------------------------------------------------|
    | GUID | LIBRARY_CLASS | PATH | PHASES | SOURCES_USED | LIBRARIES_USED | PROTOCOLS_USED | GUIDS_USED | PPIS_USED | PCDS_USED |
    |----------------------------------------------------------------------------------------------------------------------------|
    """
    def get_tables(self) -> list[str]:
        return ["inf"]

    def parse_workspace(self, tables: dict[str, Table], pathobj: Edk2Path, env: VarDict) -> None:
        ws = Path(pathobj.WorkspacePath)
        inf_table = tables["inf"]
        inf_entries = []
        
        start = time.time()
        files = list(ws.glob("**/*.inf"))
        inf_entries = Parallel(n_jobs=-1)(delayed(self._parse_file)(ws, filename, pathobj) for filename in files)

        logging.debug(f"{self.__class__.__name__}: Parsed {len(inf_entries)} .inf files took {round(time.time() - start, 2)} seconds.")
        with transaction(inf_table) as tr:
            tr.insert_multiple(inf_entries)
        logging.debug(f"{self.__class__.__name__}: Adding files to database took {round(time.time() - start, 2)} seconds.")
    
    def _parse_file(self, ws, filename, pathobj) -> dict:
        inf_parser = InfParser().SetEdk2Path(pathobj)
        inf_parser.ParseFile(filename)
        
        data = {}
        data["GUID"] = inf_parser.Dict.get("FILE_GUID", "")
        data["LIBRARY_CLASS"] = inf_parser.LibraryClass
        data["PATH"] = inf_parser.Path.relative_to(ws).as_posix()
        data["PHASES"] = inf_parser.SupportedPhases
        data["SOURCES_USED"] = inf_parser.Sources
        data["BINARIES_USED"] = inf_parser.Binaries
        data["LIBRARIES_USED"] = inf_parser.LibrariesUsed
        data["PROTOCOLS_USED"] = inf_parser.ProtocolsUsed
        data["GUIDS_USED"] = inf_parser.GuidsUsed
        data["PPIS_USED"] = inf_parser.PpisUsed
        data["PCDS_USED"] = inf_parser.PcdsUsed
        
        return data

# This is for specifics
class DParser(WorkspaceParser):
    """A Workspace parser that parses all dsc files in the workspace and generates a table with the following schema:
    
    table_name: "dsc"
    |-------------------------------|
    | PATH | COMPONENTS | LIBRARIES |
    |-------------------------------|
    """

    def get_tables(self) -> list[str]:
        return ["dsc"]
    
    def parse_workspace(self, tables: dict[str, Table], pathobj: Edk2Path, env: VarDict) -> None:
        ws = Path(pathobj.WorkspacePath)
        dsc_table = tables["dsc"]
        dsc_entries = []

        start = time.time()
        count = 0
        for filename in ws.glob("**/*.dsc"):
            dsc_parser = DscParser().SetEdk2Path(pathobj)
            try:
                dsc_parser.ParseFile(filename)
            except RuntimeError as e:
                logging.warning(f"Failed to parse {filename}: {e}")
                continue
            count += 1

            data = {}
            data["PATH"] = filename.relative_to(ws).as_posix()
            data["COMPONENTS"] = dsc_parser.GetMods() + dsc_parser.OtherMods
            data["LIBRARIES"] = dsc_parser.GetLibs()
            
            dsc_entries.append(data)
        logging.debug(f"{self.__class__.__name__}: Parsed {count} .dsc files took {round(time.time() - start, 2)} seconds.")

        start = time.time()
        with transaction(dsc_table) as tr:
            tr.insert_multiple(dsc_entries)
        logging.debug(f"{self.__class__.__name__}: Adding files to database took {round(time.time() - start, 2)} seconds.") 
