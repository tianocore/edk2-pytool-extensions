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

from edk2toollib.uefi.edk2.path_utilities import Edk2Path
from edk2toollib.uefi.edk2.parsers.inf_parser import InfParser
from edk2toollib.uefi.edk2.parsers.dsc_parser import DscParser
from edk2toolext.environment.var_dict import VarDict

from tinydb.table import Table
from tinyrecord import transaction

# logger = logging.getLogger(__name__)

class WorkspaceParser:
    """An interface for a workspace parser."""

    def parse_workspace(self, tables: dict[str, Table], package: str, pathobj: Edk2Path, env: VarDict) -> None:
        """Parse the workspace and update the database."""
        raise NotImplementedError
    
    def get_tables(self) -> list[str]:
        """Return a list of tables that should be provided to the parser."""
        raise NotImplementedError
    
class CParser(WorkspaceParser):
    """An interface for a C code parser."""
    def parse_workspace(self, tables: dict[str, Table], package: list[str], pathobj: Edk2Path, env: VarDict) -> None:
        """Parse the workspace and update the database."""

        ws = Path(pathobj.WorkspacePath)
        src_table = tables["source"]
        src_entries = []
        
        start = time.time()
        count = 0
        for filename in ws.rglob("*.c"):
            src_entries.append(self._parse_file(ws, filename))
            count+= 1
        logging.debug(f"{self.__class__.__name__}: Parsed {count} .c files took {round(time.time() - start, 2)} seconds.")
        
        start = time.time()
        count = 0
        for filename in ws.rglob("*.h"):
            src_entries.append(self._parse_file(ws, filename))
            count+= 1
        logging.debug(f"{self.__class__.__name__}: Parsed {count} .h files took {round(time.time() - start, 2)} seconds.")
        
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
            "path": filename.relative_to(ws).as_posix(),
            "license": license,
            "total_lines": 0,
            "code_lines": 0,
            "comment_lines": 0,
            "blank_lines": 0,
        }

class IParser(WorkspaceParser):
    """An interface for a INF parser.
    
    |
    | GUID | LIBRARY_CLASS | PATH | LIBRARIES_USED |
    |
    
    
    """
    def get_tables(self) -> list[str]:
        return ["inf"]

    def parse_workspace(self, tables: dict[str, Table], package: str, pathobj: Edk2Path, env: VarDict) -> None:
        ws = Path(pathobj.WorkspacePath)
        inf_table = tables["inf"]
        inf_entries = []
        
        start = time.time()
        count = 0
        for filename in ws.glob("**/*.inf"):
            inf_parser = InfParser().SetEdk2Path(pathobj)
            inf_parser.ParseFile(filename)
            count += 1
            
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

            inf_entries.append(data)

        logging.debug(f"{self.__class__.__name__}: Parsed {count} .h files took {round(time.time() - start, 2)} seconds.")
        with transaction(inf_table) as tr:
            tr.insert_multiple(inf_entries)
        logging.debug(f"{self.__class__.__name__}: Adding files to database took {round(time.time() - start, 2)} seconds.")


class DParser(WorkspaceParser):
    """An interface for a DSC parser."""

    def get_tables(self) -> list[str]:
        return ["dsc"]
    
    def parse_workspace(self, tables: dict[str, Table], package: str, pathobj: Edk2Path, env: VarDict) -> None:
        ws = Path(pathobj.WorkspacePath)
        dsc_table = tables["dsc"]
        dsc_entries = []

        start = time.time()
        count = 0
        for filename in ws.glob("**/*.dsc"):
            dsc_parser = DscParser().SetEdk2Path(pathobj)
            dsc_parser.ParseFile(filename)
            count += 1

            data = {}
            data["PATH"] = filename.relative_to(ws).as_posix()
            data["COMPONENTS"] = dsc_parser.GetMods() + dsc_parser.OtherMods
            data["LIBRARIES"] = dsc_parser.GetLibs()
            
            import pprint
            pprint.pprint(data)
            #pprint.pprint(dsc_parser.GetMods())
            #pprint.pprint(dsc_parser.OtherMods)

            #print(dsc_parser.GetMods())

            exit()




