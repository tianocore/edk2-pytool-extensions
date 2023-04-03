import re
import logging
import time
from textwrap import wrap
from typing import Union
from tinydb import TinyDB, Query, where
from tinydb.operations import add
from tinydb.storages import JSONStorage
from tinydb.middlewares import CachingMiddleware
from edk2toolext.invocables.edk2_multipkg_aware_invocable import Edk2MultiPkgAwareInvocable
from edk2toolext.invocables.edk2_ci_build import CiBuildSettingsManager
from edk2toolext import edk2_logging
from pathlib import Path
from edk2toollib.uefi.edk2.parsers.inf_parser import InfParser
from edk2toollib.uefi.edk2.parsers.dsc_parser import DscParser
from tinyrecord import transaction
from edk2toolext.environment import shell_environment
from edk2toolext.environment.var_dict import VarDict
from edk2toollib.uefi.edk2.path_utilities import Edk2Path

from edk2toolext.workspace.parsers import CParser, IParser
from edk2toolext.workspace.reports import LicenseReport, LibraryInfReport


class Dsc:
    """An object which parses a DSC file and generates a database from it.
    
    Generates the following tables with the following document structures:

    Component:
        Path: Path to the component
        Name: Name of the component
        ModuleType: Type of the component (i.e. "BASE", "SEC", "PEIM", etc.)
        SourceFiles: List of source files used by the component
        LibraryInstances: List of library instances defined in the INF
        Pcd: List of Pcds used by the component (Type, Name, Value)
    
    -------------------------------------------------------------------
    | Path* | Name | ModuleType | SourceFiles | LibraryInstances | Pcd | 
    --------------------------------------------------------------------

    Library:
        ParentComponent: Path to the component that uses this library
        Path: Path to the library
        LibraryClass: class of the library
        SourceFiles: List of source files used by the library
        Libraries: List of libraries used by the library
        UsedBy: List of other Libraries used by this library

    -----------------------------------------------------------------------------
    | ParentComponent* | Path | LibraryClass | SourceFiles | Libraries | UsedBy |
    -----------------------------------------------------------------------------

    Source:
    --------------------------------
    | Path* | Name | LibraryClass |
    --------------------------------
    
    * denotes the primary key
    """
    SECTION_REGEX = re.compile(r"\[(.*)\]")
    OVERRIDE_REGEX = re.compile(r"\<(.*)\>")

    def parse_workspace(self, ws: Path, db: TinyDB, env: VarDict, edk2path: Edk2Path, pkg: str):
        self.edk2path = edk2path

        for dsc in Path(self.edk2path.GetAbsolutePathOnThisSystemFromEdk2RelativePath(pkg)).glob("*.dsc"):
            dsc_parser = DscParser()
            dsc_parser.SetBaseAbsPath(ws).SetPackagePaths(self.edk2path.PackagePathList)
            dsc_parser.SetInputVars(env.GetAllNonBuildKeyValues() | env.GetAllBuildKeyValues()).ParseFile(str(dsc))
            libraries = self.build_library_dict(dsc_parser)
            components = self.build_component_dict(dsc_parser, libraries)

            # Create the component Table
            c_table = db.table('component_table')
            c_table.insert_multiple(components)

    def build_library_dict(self, dsc):
        """Builds a dict that contains all library classes in the FDF.
        
        key: The Library Name with one of the following append:
            [LibraryClasses.$(ARCH).$(MODULE_TYPE)], [LibraryClasses.$(ARCH)], or [LibraryClasses]
        value: The path to the library instance (INF)

        Examples:
            key: LibraryClasses.common.SEC.TimerLib, LibraryClasses.CpuLib
            value: MdePkg/Library/BaseCpuLib/BaseCpuLib.inf
        """
        libraries = {}
        current_section = []
        lines = iter(dsc.Lines)

        try:
            while True:
                line = next(lines)
                current_section = self._get_current_section(current_section, line, "LibraryClasses")

                # Not in a section we care about, so skip this line
                if not current_section:
                    continue
                
                # Just matched a new section, so skip this line
                if self.SECTION_REGEX.match(line):
                    continue
                
                lib, instance = tuple(line.split("|"))

                for section in current_section:
                    key = f"{section.strip()}.{lib.strip()}"
                    value = instance.strip()
                    libraries[key] = value
        except StopIteration:
            return libraries

    def build_component_dict(self, dsc, libraries):
        components = []
        current_section = []
        lines = iter(dsc.Lines)
        
        try:
            line = next(lines)
            for line in lines:
                current_section = self._get_current_section(current_section, line, "Components")
                override = {"NULL": []}

                # not in a section we care about, so skip this line
                if not current_section:
                    continue
                    
                # Just matched a new section, so skip this line
                if self.SECTION_REGEX.match(line):
                    continue
                
                # Handle the INFs when overrides are present
                if line.strip().endswith("{"):
                    line = str(line)
                    override = self._build_library_override_dict(lines)
                
                (component, libs) = self.parse_component_inf(line.strip(" {"), libraries, override, current_section)

                components.append(component)

        except StopIteration:
            pass
        return components 

    def parse_component_inf(self, file: str, libraries: dict, overrides: dict, sections: str) -> Union[dict, list[dict]]:
        """Parses a component INF file to generate documents for the document and library tables.
    
        Returns:
            (dict): A component document for the parsed file
            list[dict]: A list of library documents containing the instanced libraries used to build the component
        """
        file = Path(self.edk2path.GetAbsolutePathOnThisSystemFromEdk2RelativePath(file))
        lib_instances = []
        #
        # 0. Use the existing parser to parse the INF file. This parser parses an INF as an independent file
        #    and does not take into account the context of a DSC file. 
        #
        inf = InfParser()
        inf.ParseFile(file)

        #
        # 1. Convert Libraries classes to the actual Library Instance. The information to do this is defined
        #    in the DSC file that is using this INF. NULL library instances as defined in the DSC are included
        #    in the libraries used by this INF.
        #
        section = self._reduce_component_section(inf.Dict["MODULE_TYPE"], sections)
        section = section.replace("Components", "LibraryClasses")
        for lib in inf.LibrariesUsed:
            lib = lib.split(" ")[0]
            instance = self._get_library_instance(lib, section, libraries, overrides)
            if instance is not None:
                lib_instances.append(instance)

        # Append all NULL library instances 
        for null_lib in overrides["NULL"]:
            if null_lib not in lib_instances:
                lib_instances.append(null_lib)
        
        # Recurse to generate a list of libraries used by this component
        all_lib_instances = lib_instances
        for lib in lib_instances:
            all_lib_instances.extend(self._parse_library_inf(lib, libraries, overrides, sections))

        return ({
            "Path": inf.Path.as_posix(),
            "Name": inf.Dict["BASE_NAME"],
            "ModuleType": inf.Dict["MODULE_TYPE"],
            "SourceFiles": inf.Sources,
            "LibraryInstances": lib_instances,
            "Pcds": inf.PcdsUsed # TODO: This needs to have the actual value of the PCDS
        }, [])
    
    def _parse_library_inf(self, file: str, libraries: dict, overrides: dict, sections: str, lib_instance_list = {}) -> list[dict]:
        return []

    def _get_library_instance(self, lib_class_name: str, section: str, all_libraries: dict, overrides: dict):
        """Converts a library name to the actual instance of the library.

        This conversion is based off the library section definitions in the DSC. 
        
        Args:
            lib_class_name: The name of the library class to lookup
            section: The section scope for this library
            all_libraries: A dict of all section scoped libraries found in the DSC
            overrides: A dict of library overrides
        """
        
        arch = ""
        module = ""
        if section.count(".") == 2:
            _, arch, module = tuple(section.split("."))
        elif section.count(".") == 1:
            _, arch = tuple(section.split("."))
        else:
            arch = "common"

        # https://edk2-docs.gitbook.io/edk-ii-dsc-specification/3_edk_ii_dsc_file_format/38_-libraryclasses-_sections#summary

        # 1. If a Library class instance (INF) is specified in the Edk2 II [Components] section (an override),
        #    then it will be used.
        if lib_class_name in overrides:
            return overrides[lib_class_name]

        # 2. If the Library Class instance (INF) is defined in the [LibraryClasses.$(ARCH).$(MODULE_TYPE)] section,
        #    then it will be used.
        if module and arch != "common":
            lookup = f'LibraryClasses.{arch}.{module}.{lib_class_name}'
            if lookup in all_libraries:
                return all_libraries[lookup]
            
        # 3. If the Library Class instance (INF) is defined in the [LibraryClasses.common.$(MODULE_TYPE)] section,
        #   then it will be used.
        if module:
            lookup = f'LibraryClasses.common.{module}.{lib_class_name}'
            if lookup in all_libraries:
                return all_libraries[lookup]

        # 4. If the Library Class instance (INF) is defined in the [LibraryClasses.$(ARCH)] section,
        #    then it will be used.
        if arch != "common":
            lookup = f'LibraryClasses.{arch}.{lib_class_name}'
            if lookup in all_libraries:
                return all_libraries[lookup]

        # 5. If the Library Class Instance (INF) is defined in the [LibraryClasses] section,
        #    then it will be used.
        lookup = f'LibraryClasses.{lib_class_name}'
        if lookup in all_libraries:
            return all_libraries[lookup]

        # 6. It is an error if it has not been specified in any of the above sections.
        # TODO: Any Lib that makes it here is from an architecture that is not used by the package
        # The INF parser does not keep that information to verify it 100% during parsing. Maybe update?
        return None
     
    def _get_current_section(self, old_section, line, section_name)-> list[str]:
        current_section = []
        match = self.SECTION_REGEX.match(line)

        # If we don't match on a new section, return the old section
        if not match:
            return old_section
        
        # If we match on a new section, but its not a Library class section, return empty handed
        elif match and not match.group().startswith(f"[{section_name}"):
            return []
        
        # Otherwise, we have matched on a new Library class section, update the current section
        else:
            current_section = []
            lib_class_list = match.group().strip("[]").split(",")
            for lib_class in lib_class_list:
                current_section.append(lib_class.strip())
            return current_section
    
    def _build_library_override_dict(self, lines) -> dict:
        """Builds a dict that contains library overrides for a component."""
        override_dict = {"NULL": []}
        section = ""
        line = next(lines)
        while line.strip() != "}":
            if self.OVERRIDE_REGEX.match(line) and line == "<LibraryClasses>":
                section = "LibraryClasses"
                line = next(lines)
                continue
            if self.OVERRIDE_REGEX.match(line) and line != "LibraryClasses":
                section = ""
                line = next(lines)
                continue
            if section != "LibraryClasses":
                line = next(lines)
                continue

            lib, instance = tuple(line.split("|"))
            
            if lib.strip() == "NULL":
                override_dict["NULL"].append(instance.strip())
            else:
                override_dict[lib.strip()] = instance.strip()
            line = next(lines)
        return override_dict
        
    def _reduce_component_section(self, module_type, possible_sections) -> str:
        """Reduces a comma separated list of component sections to a single section.
        
        This reduction is based off of the module_type provided.
        """
        for section in possible_sections:
            if section.endswith(module_type):
                return section
        
        for section in possible_sections:
            if section.count(".") == 1:
                return f'{section}.{module_type}'
            return f'{section}.{"common"}.{module_type}'

class Edk2Report(Edk2MultiPkgAwareInvocable):

    def get_parsers(self) -> list:
        "Returns a list of un-instantiated DbDocument subclass parsers."
        # TODO: Parse plugins to grab any additional parsing that should be done.
        return [
            CParser(),
            IParser(),
        ]
    
    def get_reports(self) -> list:
        """Returns a list of report generators."""
        return [
            LicenseReport(),
            LibraryInfReport(),
        ]

    def GetSettingsClass(self):
        return CiBuildSettingsManager
    
    def GetLoggingFolderRelativeToRoot(self):
        return "Build"
    
    def GetLoggingFileName(self, loggerType):
        return "REPORT"

    def GetActiveScopes(self):
        return ()
    
    def AddParserEpilog(self):
        """Adds an epilog to the end of the argument parser when displaying help information.

        Returns:
            (str): The string to be added to the end of the argument parser.
        """
        custom_epilog = ""

        variables = []
        for report in self.get_reports():
            variables.extend(report.report_cli_args())

        max_name_len = max(len(var.name) for var in variables)
        max_desc_len = min(max(len(var.description) for var in variables), 55)
        
        custom_epilog += "Report CLI Variables:\n\n"
        for report in self.get_reports():
            custom_epilog += f"Report: [{report.report_name()}]"
            for r in report.report_cli_args():
                # Setup wrap and print first portion of description
                desc = wrap(r.description, max_desc_len,
                            drop_whitespace=True, break_on_hyphens=True, break_long_words=True)
                custom_epilog += f"\n  {r.name:<{max_name_len}} - {desc[0]:<{max_desc_len}}"
                
                # If the line actually wrapped, we can print the rest of the lines here
                for d in desc[1:]:
                    custom_epilog += f"\n  {'':<{max_name_len}}   {d:{max_desc_len}}"
            custom_epilog += '\n\n'

        return custom_epilog

    def Go(self):
        ws = Path(self.GetWorkspaceRoot())
        env = shell_environment.GetBuildVars()
        pathobj = Edk2Path(self.GetWorkspaceRoot(), self.GetPackagesPath())
        parsers = self.get_parsers()
        reports = self.get_reports()
        db_path = env.GetValue("DB_PATH", None)
        report = env.GetValue("REPORT", None)
        
        if db_path:
            db = TinyDB(db_path, access_mode='r+', storage=CachingMiddleware(JSONStorage))
        else:
            db_path = ws / "Build" / f"DATABASE.db"
            db_path.unlink(missing_ok=True)
            db = self.generate_database(db_path, parsers, pathobj, env)

        if report:
            self.generate_report(report, db, env, reports)

        db.close()
        return 0
    
    def generate_database(self, db_path, parsers, pathobj, env):
        
        db = TinyDB(db_path, access_mode='r+', storage=CachingMiddleware(JSONStorage))
        for parser in parsers:
            tables = {}
            for table in parser.get_tables():
                tables[table] = db.table(table)
            
            logging.log(edk2_logging.SECTION, f"Starting parser: [{parser.__class__.__name__}]")
            start = time.time()
            parser.parse_workspace(tables, self.requested_package_list, pathobj, env)
            logging.log(edk2_logging.SECTION, f"Finished in {round(time.time() - start, 2)} seconds.")

        return db
    
    def generate_report(self, report, db, env, reports):
        if report:
            for r in reports:
                if r.report_name() == report:
                    r.generate_report(db, env)
                    return

    def AssociateFilesWithModules(self, db):
        start_time = time.time()

        module_table = db.table('modules')
        file_table = db.table('files')

        with transaction(file_table) as tr:
            for doc_list in module_table.search(Query().SourceFiles.exists()):
                module_dir = Path(doc_list["Path"]).parent
                module_name = doc_list["Name"]
                
                for source in doc_list["SourceFiles"]:
                    src_file = module_dir / source
                    tr.update(add("Modules", [module_name]), where('Path') == str(src_file))
        
        logging.info(f"Associated Source Files with Modules in {round(time.time() - start_time, 2)} seconds.")

def main():
    Edk2Report().Invoke()
