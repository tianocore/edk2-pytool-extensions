# @file conf_mgmt.py
# Handle Edk2 Conf management
# Customized for edk2-pytools-extensions based build and supports dynamic Visual studio support 2017++
##
# Copyright (c) Microsoft Corporation
#
# SPDX-License-Identifier: BSD-2-Clause-Patent
##
"""Handle Edk2 Conf Management.

Customized for edk2-pytool-extensions based build and support dynamic Visual studio support 2017++
"""

import logging
import os
import shutil
import time

from edk2toolext.environment import version_aggregator


class ConfMgmt:
    """Handles Edk2 Conf Management."""

    def __init__(self) -> None:
        """Init an empty ConfMgmt object."""
        self.Logger = logging.getLogger("ConfMgmt")
        self.delay_time_in_seconds = 30

    def _set_delay_time(self, time_in_seconds: int) -> None:
        """Allow changing the warning time for out of date templates."""
        self.delay_time_in_seconds = time_in_seconds

    def populate_conf_dir(self, conf_folder_path: str, override_conf: bool, conf_template_src_list: list) -> None:
        """Compare the conf dir files to the template files.

        Copy files if they are not present in the conf dir or the override parameter is set.

        Args:
            conf_folder_path (str): folder path to output conf location (absolute path)
            override_conf (bool):  boolean to indicate if templates files should replace conf files
                regardless of existence or version.
            conf_template_src_list (list): priority list of folder path that might contain a "Conf"
                older with template files to use

        Note: When complete the conf_folder_path dir must be setup for edk2 builds
        """
        #  make folder to conf path if needed
        os.makedirs(conf_folder_path, exist_ok=True)

        files = ["target.txt", "tools_def.txt", "build_rule.txt"]  # add more files here

        # make output conf files list based on files
        outfiles = [os.path.join(conf_folder_path, f) for f in files]

        # make template list based on files
        templatefiles = [os.path.join("Conf", os.path.splitext(f)[0] + ".template") for f in files]

        # loop thru each Conf file needed
        for x in range(len(outfiles)):
            template_file_path = None

            # find template file given multiple root locations
            for r in conf_template_src_list:
                p = os.path.join(r, templatefiles[x])
                if os.path.isfile(p):
                    template_file_path = p
                    break

            if template_file_path is None:
                self.Logger.critical("Failed to find Template file for %s" % outfiles[x])
                raise Exception("Template File Missing", outfiles[x])
            else:
                self.Logger.debug(f"Conf file template: {template_file_path}")

            # have template now - now copy if needed
            self._copy_conf_file_if_necessary(outfiles[x], template_file_path, override_conf)

            # Log Version for reporting
            version_aggregator.GetVersionAggregator().ReportVersion(
                outfiles[x], self._get_version(outfiles[x]), version_aggregator.VersionTypes.INFO
            )

    def _get_version(self, conf_file: str) -> str:
        """Parse the version from the conf_file.

        version should be in #!VERSION={value} format

        !!! note
            "0.0" is returned if no version is found
        """
        version = "0.0"
        with open(conf_file, "r") as f:
            for line in f.readlines():
                if line.startswith("#!VERSION="):
                    try:
                        version = str(float(line.split("=")[1].split()[0].strip()))
                        break
                    except Exception:
                        pass
        return version

    def _is_older_version(self, conf_file: str, template_file: str) -> bool:
        """Determines whether the conf or template file is older.

        Given a conf_file and a template_file file determine if
        the conf_file has an older version than the template.

        Args:
            conf_file (str): path to current conf_file
            template_file (str): path to template file that is basis
                for the the conf_file.
        """
        conf = 0
        template = 0

        try:
            conf = float(self._get_version(conf_file))
            logging.debug("Conf version: %s", str(conf))
            template = float(self._get_version(template_file))
            logging.debug("Template Version: %s", str(template))
        except Exception:
            logging.error("Failed to get version from file")
        finally:
            return conf < template

    def _copy_conf_file_if_necessary(self, conf_file: str, template_file: str, override_conf: bool) -> None:
        """Copy template_file to conf_file if policy applies.

        Args:
            conf_file (str): path to final conf file location
            template_file (str): template file to copy if policy applies
            override_conf (bool): flag indication to override regardless of policy
        """
        if not os.path.isfile(conf_file):
            # file doesn't exist.  copy template
            self.Logger.debug(f"{conf_file} file not found.  Creating from Template file {template_file}")
            shutil.copy2(template_file, conf_file)

        elif override_conf:
            # caller requested override even for existing file
            self.Logger.debug(f"{conf_file} file replaced as requested")
            shutil.copy2(template_file, conf_file)

        else:
            # Both file exists.  Do a quick version check
            if self._is_older_version(conf_file, template_file):
                # Conf dir file is older.  Warn user.
                self.Logger.critical(f"{conf_file} file is out-of-date.  Please update your conf files!")
                self.Logger.critical("Sleeping 30 seconds to encourage update....")
                time.sleep(self.delay_time_in_seconds)
            else:
                self.Logger.debug(f"Conf file {conf_file} up-to-date")
