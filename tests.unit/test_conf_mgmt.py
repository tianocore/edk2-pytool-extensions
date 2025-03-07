# @file test_conf_mgmt.py
# Unit test suite for the ConfMgmt class.
#
##
# Copyright (c) Microsoft Corporation
#
# SPDX-License-Identifier: BSD-2-Clause-Patent
##
"""Unit test suite for the ConfMgmt class."""

import logging
import os
import shutil
import tempfile
import unittest

from edk2toolext.environment import conf_mgmt

test_file_text = """#
#  Copyright (c) 2006 - 2018, Intel Corporation. All rights reserved.<BR>
#  Portions copyright (c) 2008 - 2009, Apple Inc. All rights reserved.<BR>
#  Portions copyright (c) 2011 - 2014, ARM Ltd. All rights reserved.<BR>
#  Copyright (c) 2015, Hewlett-Packard Development Company, L.P.<BR>
#  (C) Copyright 2016 Hewlett Packard Enterprise Development LP<BR>
#  Copyright (c) Microsoft Corporation
#
#  SPDX-License-Identifier: BSD-2-Clause-Patent
#
#
# Increase this version tag any time you want user to get warning about updating this
# file in the Conf dir.  By default it does not do update existing conf dirs.
#
# 2.00 - Initial version with changes for CI
#      - Change VS2019 and VS2017 to use PyTool Values for path
#      - Change RC path to use plugin
#      - Change GCC5 for AARCH64 to use ENV instead of DEF
#      - Add path sep for nasm prefix
#


IDENTIFIER = Default TOOL_CHAIN_CONF

# common path macros
DEFINE VS2008_BIN      = ENV(VS2008_PREFIX)
"""


class TestConfMgmt(unittest.TestCase):
    """Unit test suite for the ConfMgmt class."""

    def __init__(self, *args, **kwargs) -> None:  # noqa: ANN002, ANN003
        """Initialize the test class."""
        self.test_dir = None
        super().__init__(*args, **kwargs)

    def prep_workspace(self) -> None:
        """Prepare the workspace."""
        self.clean_workspace()
        self.test_dir = tempfile.mkdtemp()

    def clean_workspace(self) -> None:
        """Clean up the workspace."""
        if self.test_dir is None:
            return
        if os.path.isdir(self.test_dir):
            shutil.rmtree(self.test_dir)
            self.test_dir = None

    def make_one_file(self, filepath: str, version: str) -> None:
        """Make a file with the given version."""
        with open(filepath, "w") as f:
            f.write(test_file_text)
            f.write(f"#!VERSION={version}")
            logging.debug(f"Made file {filepath} with version {version}")

    def make_edk2_files_dir(
        self, rootfolderpath: str, target_ver: str, tools_def_ver: str, build_rules_ver: str, is_template: bool
    ) -> None:
        """Make the EDK2 files in the given directory."""
        file_names = ["target", "tools_def", "build_rule"]
        versions = [target_ver, tools_def_ver, build_rules_ver]
        if is_template:
            file_names = [x + ".template" for x in file_names]
            rootfolderpath = os.path.join(rootfolderpath, "Conf")
        else:
            file_names = [x + ".txt" for x in file_names]

        os.makedirs(rootfolderpath, exist_ok=True)
        for i in range(len(file_names)):
            self.make_one_file(os.path.join(rootfolderpath, file_names[i]), versions[i])

    def get_target_version(self, conf_folder_path: str) -> str:
        """Get the version of the target file."""
        p = os.path.join(conf_folder_path, "target.txt")
        return conf_mgmt.ConfMgmt()._get_version(p)

    def get_toolsdef_version(self, conf_folder_path: str) -> str:
        """Get the version of the tools def file."""
        p = os.path.join(conf_folder_path, "tools_def.txt")
        return conf_mgmt.ConfMgmt()._get_version(p)

    def get_buildrules_version(self, conf_folder_path: str) -> str:
        """Get the version of the build rules file."""
        p = os.path.join(conf_folder_path, "build_rule.txt")
        return conf_mgmt.ConfMgmt()._get_version(p)

    def setUp(self) -> None:
        """Prepare the workspace."""
        self.prep_workspace()

    def tearDown(self) -> None:
        """Clean up the workspace."""
        self.clean_workspace()

    def test_init(self) -> None:
        """Test that the ConfMgmt class can be initialized."""
        conf_mgmt.ConfMgmt()

    def test_no_version_tag(self) -> None:
        """Test that the _get_version function works when the file has no version tag."""
        p = os.path.join(self.test_dir, "test.txt")
        with open(p, "w") as f:
            f.write(test_file_text)
        c = conf_mgmt.ConfMgmt()._get_version(p)
        self.assertEqual(c, "0.0")

    def test_invalid_version(self) -> None:
        """Test that the _get_version function works when the version is invalid."""
        invalid_versions = ["1.2.3.4", "1.2.3", "Hello.1", "1.jk", "", "Wow", "Unknown"]

        p = os.path.join(self.test_dir, "test.txt")
        for a in invalid_versions:
            self.make_one_file(p, a)
            c = conf_mgmt.ConfMgmt()._get_version(p)
            self.assertEqual(c, "0.0")

    def test_valid_version(self) -> None:
        """Test that the _get_version function works when the version is valid."""
        valid_versions = ["1.2", "2.02", "0.1", "22.345", "69594.39939494"]

        p = os.path.join(self.test_dir, "test.txt")
        for a in valid_versions:
            self.make_one_file(p, a)
            c = conf_mgmt.ConfMgmt()._get_version(p)
            self.assertEqual(c, a)

    def test_zero_extend_version(self) -> None:
        """Test that the _get_version function works when the version is zero extended."""
        p = os.path.join(self.test_dir, "test.txt")
        self.make_one_file(p, "2")
        c = conf_mgmt.ConfMgmt()._get_version(p)
        self.assertEqual(c, "2.0")

    def test_is_older_version_true(self) -> None:
        """Test that the _is_older_version function works when the conf is older than the template."""
        # first member is conf
        # second member is temp
        # make second member larger
        versions = [("1.2", "1.3"), ("0.1", "0.11"), ("1", "1.000001")]
        conf = os.path.join(self.test_dir, "conf.txt")
        temp = os.path.join(self.test_dir, "temp.txt")
        for a in versions:
            self.make_one_file(conf, a[0])
            self.make_one_file(temp, a[1])
            c = conf_mgmt.ConfMgmt()._is_older_version(conf, temp)
            self.assertTrue(c)

    def test_is_older_version_false(self) -> None:
        """Test that the _is_older_version function works when the conf is newer than the template."""
        # first member is conf
        # second member is temp
        # make second member larger
        versions = [("1.2", "1.2"), ("0.1", "0.09"), ("1", ".99999")]
        conf = os.path.join(self.test_dir, "conf.txt")
        temp = os.path.join(self.test_dir, "temp.txt")
        for a in versions:
            self.make_one_file(conf, a[0])
            self.make_one_file(temp, a[1])
            c = conf_mgmt.ConfMgmt()._is_older_version(conf, temp)
            self.assertFalse(c)

    def test_is_older_no_version_tag_conf(self) -> None:
        """Test that the _is_older_version function works when the conf file has no version tag."""
        conf = os.path.join(self.test_dir, "conf.txt")
        temp = os.path.join(self.test_dir, "temp.txt")
        # make file with no version tag
        with open(conf, "w") as f:
            f.write(test_file_text)
        self.make_one_file(temp, "1.0")
        c = conf_mgmt.ConfMgmt()._is_older_version(conf, temp)
        self.assertTrue(c)

    def test_is_older_no_version_tag_template(self) -> None:
        """Test that the _is_older_version function works when the template has no version tag."""
        conf = os.path.join(self.test_dir, "conf.txt")
        temp = os.path.join(self.test_dir, "temp.txt")
        # make file with no version tag
        with open(temp, "w") as f:
            f.write(test_file_text)
        self.make_one_file(conf, "1.0")
        c = conf_mgmt.ConfMgmt()._is_older_version(conf, temp)
        self.assertFalse(c)

    def test_is_older_no_version_no_template(self) -> None:
        """Test that the _is_older_version function works when the template has no version tag."""
        conf = os.path.join(self.test_dir, "conf.txt")
        temp = os.path.join(self.test_dir, "temp.txt")
        # make file with no version tag
        self.make_one_file(conf, "1.0")
        c = conf_mgmt.ConfMgmt()._is_older_version(conf, temp)
        self.assertFalse(c)

    def test_populate_when_conf_empty(self) -> None:
        """Test that the populate_conf_dir function works when the conf directory is empty."""
        conf = os.path.join(self.test_dir, "Conf")
        temp = os.path.join(self.test_dir, "templates")

        self.make_edk2_files_dir(temp, "1.0", "2.0", "3.0", True)
        conf_mgmt.ConfMgmt().populate_conf_dir(conf, False, [temp])

        self.assertEqual("1.0", self.get_target_version(conf))
        self.assertEqual("2.0", self.get_toolsdef_version(conf))
        self.assertEqual("3.0", self.get_buildrules_version(conf))

    def test_no_populate_when_conf_fully_populated(self) -> None:
        """Test that the populate_conf_dir function does not overwrite existing files."""
        conf = os.path.join(self.test_dir, "Conf")
        temp = os.path.join(self.test_dir, "Templates")

        self.make_edk2_files_dir(temp, "1.0", "2.0", "3.0", True)
        self.make_edk2_files_dir(conf, "1.1", "2.1", "3.1", False)
        conf_mgmt.ConfMgmt().populate_conf_dir(conf, False, [temp])

        self.assertEqual("1.1", self.get_target_version(conf))
        self.assertEqual("2.1", self.get_toolsdef_version(conf))
        self.assertEqual("3.1", self.get_buildrules_version(conf))

    def test_populate_override_fully_populated(self) -> None:
        """Test that the populate_conf_dir function works when the override flag is set."""
        conf = os.path.join(self.test_dir, "Conf")
        temp = os.path.join(self.test_dir, "Templates")

        self.make_edk2_files_dir(temp, "1.0", "2.0", "3.0", True)
        self.make_edk2_files_dir(conf, "1.1", "2.1", "3.1", False)
        conf_mgmt.ConfMgmt().populate_conf_dir(conf, True, [temp])

        self.assertEqual("1.0", self.get_target_version(conf))
        self.assertEqual("2.0", self.get_toolsdef_version(conf))
        self.assertEqual("3.0", self.get_buildrules_version(conf))

    def test_conf_older_warn_fully_populated(self) -> None:
        """Test that the populate_conf_dir function works when the conf is older than the templates."""
        conf = os.path.join(self.test_dir, "Conf")
        temp = os.path.join(self.test_dir, "Templates")

        self.make_edk2_files_dir(temp, "1.2", "2.2", "3.2", True)
        self.make_edk2_files_dir(conf, "1.1", "2.1", "3.1", False)
        c = conf_mgmt.ConfMgmt()
        c._set_delay_time(0)
        c.populate_conf_dir(conf, False, [temp])

        self.assertEqual("1.1", self.get_target_version(conf))
        self.assertEqual("2.1", self.get_toolsdef_version(conf))
        self.assertEqual("3.1", self.get_buildrules_version(conf))

    def test_plat_template_fully_populated(self) -> None:
        """Test that the populate_conf_dir function works when a platform template is provided."""
        conf = os.path.join(self.test_dir, "Conf")
        temp = os.path.join(self.test_dir, "Templates")
        plattemp = os.path.join(self.test_dir, "TemplatesPlat")

        self.make_edk2_files_dir(temp, "1.0", "2.0", "3.0", True)
        self.make_edk2_files_dir(plattemp, "1.2", "2.2", "3.2", True)
        conf_mgmt.ConfMgmt().populate_conf_dir(conf, False, [plattemp, temp])

        self.assertEqual("1.2", self.get_target_version(conf))
        self.assertEqual("2.2", self.get_toolsdef_version(conf))
        self.assertEqual("3.2", self.get_buildrules_version(conf))

    def test_no_templates(self) -> None:
        """Test that the populate_conf_dir function works when no templates are provided."""
        conf = os.path.join(self.test_dir, "Conf")
        temp = os.path.join(self.test_dir, "Templates")

        with self.assertRaises(Exception):
            conf_mgmt.ConfMgmt().populate_conf_dir(conf, False, [temp])


if __name__ == "__main__":
    unittest.main()
