# @file conf_mgmt.py
# Handle Edk2 Conf management
# Customized for edk2-pytools-extensions based build and supports dynamic Visual studio support 2017++
##
# Copyright (c) Microsoft Corporation
#
# SPDX-License-Identifier: BSD-2-Clause-Patent
##

import os
import logging
import shutil
import time
from edk2toolext.environment import shell_environment
from edk2toollib.windows.locate_tools import FindWithVsWhere
from edk2toolext.environment import version_aggregator


class ConfMgmt():

    def __init__(self, OverrideConf, AdditionalTemplateConfDir):
        self.Logger = logging.getLogger("ConfMgmt")
        self.env = shell_environment.GetBuildVars()
        if (self.env.GetValue("WORKSPACE") is None) or \
                (self.env.GetValue("EDK2_BASE_TOOLS_DIR") is None):
            raise Exception("WORKSPACE and EDK2_BASE_TOOLS_DIR must be set prior to running ConfMgmt")
        self.__PopulateConf(OverrideConf, AdditionalTemplateConfDir)

    #
    # Get the version of a conf file
    #
    def __GetVersion(self, confFile):
        version = "Unknown"
        f = open(confFile, "r")
        for l in f.readlines():
            if(l.startswith("#!VERSION=")):
                version = str(float(l.split("=")[1].split()[0].strip()))
                break

        f.close()
        return version

    #
    # Compare the version of the existing conf file to the template file
    #
    def __OlderVersion(self, confFile, confTemplateFile):
        conf = 0
        template = 0

        f = open(confFile, "r")
        for l in f.readlines():
            if(l.startswith("#!VERSION=")):
                conf = float(l.split("=")[1].split()[0].strip())
                logging.debug("Conf version: %s", str(conf))
                break

        f.close()
        f = open(confTemplateFile, "r")
        for l in f.readlines():
            if(l.startswith("#!VERSION=")):
                template = float(l.split("=")[1].split()[0].strip())
                logging.debug("Template Version: %s", str(template))
                break
        f.close()

        return (conf < template)

    def __PopulateConf(self, OverrideConf, AdditionalTemplateConfDir):
        ws = self.env.GetValue("WORKSPACE")
        # Copy Conf template files to conf if not present
        target = os.path.join(ws, "Conf", "target.txt")
        buildrules = os.path.join(ws, "Conf", "build_rule.txt")
        toolsdef = os.path.join(ws, "Conf", "tools_def.txt")

        # BaseTools Template files
        target_template = os.path.join("Conf", "target.template")
        tools_def_template = os.path.join("Conf", "tools_def.template")
        build_rules_template = os.path.join("Conf", "build_rule.template")

        outfiles = [target, toolsdef, buildrules]
        tfiles = [target_template, tools_def_template, build_rules_template]

        # check if conf exists
        if(not os.path.isdir(os.path.join(ws, "Conf"))):
            os.mkdir(os.path.join(ws, "Conf"))

        x = 0
        while(x < len(outfiles)):
            # check if the conf file already exists
            # don't overwrite if exists.  Popup if version is older in conf
            TemplateFilePath = ""
            Tag = self.env.GetValue("TOOL_CHAIN_TAG")

            if Tag is None:
                self.Logger.warn("Can't use ToolChain specific template files since Tag is not defined")
                Tag = ""

            #
            # Get the Override template if it exist
            #
            if(AdditionalTemplateConfDir is not None):
                fp = os.path.join(AdditionalTemplateConfDir, tfiles[x] + ".ms")
                if os.path.isfile(fp):
                    TemplateFilePath = fp

            #
            # If not found, try toolchain specific templates
            #
            if(TemplateFilePath == "" and Tag.upper().startswith("VS")):
                fp = os.path.join(self.env.GetValue(
                    "EDK2_BASE_TOOLS_DIR"), tfiles[x] + ".vs")
                if os.path.isfile(fp):
                    TemplateFilePath = fp

            if(TemplateFilePath == "" and Tag.upper().startswith("GCC")):
                fp = os.path.join(self.env.GetValue(
                    "EDK2_BASE_TOOLS_DIR"), tfiles[x] + ".gcc")
                if os.path.isfile(fp):
                    TemplateFilePath = fp

            #
            # If not found above try MS templates
            #
            if(TemplateFilePath == ""):
                fp = os.path.join(self.env.GetValue(
                    "EDK2_BASE_TOOLS_DIR"), tfiles[x] + ".ms")
                if os.path.isfile(fp):
                    TemplateFilePath = fp

            #
            # If not found above try TianoCore Template
            #
            if(TemplateFilePath == ""):
                fp = os.path.join(self.env.GetValue(
                    "EDK2_BASE_TOOLS_DIR"), tfiles[x])
                if TemplateFilePath == "" and os.path.isfile(fp):
                    TemplateFilePath = fp

            #
            # Check to see if found yet -- No more options so now we are broken
            #
            if(TemplateFilePath == ""):
                self.Logger.critical(
                    "Failed to find Template file for %s" % outfiles[x])
                raise Exception("Template File Missing", outfiles[x])
            else:
                self.Logger.debug("Conf file template: [%s]", TemplateFilePath)

            # Check to see if we need the template
            if(not os.path.isfile(outfiles[x])):
                # file doesn't exist.  copy template
                self.Logger.debug("%s file not found.  Creating from Template file %s" % (
                    outfiles[x], TemplateFilePath))
                shutil.copy2(TemplateFilePath, outfiles[x])

            elif(OverrideConf):
                self.Logger.debug(
                    "%s file replaced as requested" % outfiles[x])
                shutil.copy2(TemplateFilePath, outfiles[x])
            else:
                # Both file exists.  Do a quick version check
                if(self.__OlderVersion(outfiles[x], TemplateFilePath)):
                    # Conf dir is older.  Warn user.
                    self.Logger.critical(
                        "Conf file [%s] out-of-date.  Please update your conf files!  "
                        "Sleeping 30 seconds to encourage update....", outfiles[x])
                    time.sleep(30)
                else:
                    self.Logger.debug("Conf file [%s] up-to-date", outfiles[x])
            version_aggregator.GetVersionAggregator().ReportVersion(outfiles[x], self.__GetVersion(outfiles[x]),
                                                                    version_aggregator.VersionTypes.INFO)
            x = x + 1
        # end of while loop

    def ToolsDefConfigure(self):
        Tag = self.env.GetValue("TOOL_CHAIN_TAG")
        version_aggregator.GetVersionAggregator().ReportVersion(
            "TOOL_CHAIN_TAG", Tag, version_aggregator.VersionTypes.TOOL)
        if (Tag is not None) and (Tag.upper().startswith("VS")):
            if (not self.VisualStudioSpecificVersions(Tag)):
                self.Logger.warning("Potential Toolchain issue.  VS specific operation failed.")
        return 0

    def VisualStudioSpecificVersions(self, ToolChainTag: str):
        ''' Support VS specific operations for dynmaically setting
        the vs tool paths and logging the critical version information.
        returns True for success otherwise False
        '''

        # internal functions
        def GetVsInstallPath(vsversion, varname):
            # check if already specified
            path = shell_environment.GetEnvironment().get_shell_var(varname)
            if(path is None):
                # Not specified...find latest
                (rc, path) = FindWithVsWhere(vs_version=vsversion)
                if rc == 0 and path is not None:
                    self.Logger.debug("Found VS instance for %s", vsversion)
                    shell_environment.GetEnvironment().set_shell_var(varname, path)
                else:
                    self.Logger.error("Failed to find VS instance with VsWhere (%d)" % rc)
            return path

        def GetVcVersion(path, varname):
            # check if already specified
            vc_ver = shell_environment.GetEnvironment().get_shell_var(varname)
            if(vc_ver is None):
                # Not specified...find latest
                p2 = os.path.join(path, "VC", "Tools", "MSVC")
                if not os.path.isdir(p2):
                    self.Logger.critical(
                        "Failed to find VC tools.  Might need to check for VS install")
                    return vc_ver
                vc_ver = os.listdir(p2)[-1].strip()  # get last in list
                self.Logger.debug("Found VC Tool version is %s" % vc_ver)
                shell_environment.GetEnvironment().set_shell_var(varname, vc_ver)

            if(vc_ver):
                version_aggregator.GetVersionAggregator().ReportVersion(
                    "VC Version", vc_ver, version_aggregator.VersionTypes.TOOL)
            return vc_ver

        if ToolChainTag.lower() == "vs2019":
            ipath = GetVsInstallPath(ToolChainTag.lower(), "VS160INSTALLPATH")
            iver = GetVcVersion(ipath, "VS160TOOLVER")
            return (ipath is not None) and (iver is not None)

        elif ToolChainTag.lower() == "vs2017":
            ipath = GetVsInstallPath(ToolChainTag.lower(), "VS150INSTALLPATH")
            iver = GetVcVersion(ipath, "VS150TOOLVER")
            return (ipath is not None) and (iver is not None)

        else:
            logging.warning("No dynameic support for this VS toolchain")
            return False
