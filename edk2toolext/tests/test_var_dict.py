## @file test_git_dependency.py
# Unit test suite for the GitDependency class.
#
##
# Copyright (c) Microsoft Corporation
#
# SPDX-License-Identifier: BSD-2-Clause-Patent
##
import unittest
from edk2toolext.environment import var_dict


class TestVarDict(unittest.TestCase):
    def setUp(self):
        pass

    def tearDown(self):
        pass

    @classmethod
    def setUpClass(cls):
        pass

    @classmethod
    def tearDownClass(cls):
        pass

    def test_var_dict_basic_set_get(self):
        v = var_dict.VarDict()
        v.SetValue("test1", "value1", "test 1 comment")
        ## confirm basic get
        vv = v.GetValue("test1")
        self.assertEqual("value1", vv)

    def test_var_dict_get_key_is_none(self):
        v = var_dict.VarDict()
        self.assertIsNone(v.GetValue(None))

    def test_var_dict_get_key_unknown_return_value(self):
        v = var_dict.VarDict()
        self.assertIsNone(v.GetValue("invalidkey"))
        self.assertEqual("test1", v.GetValue("invalidkey", "test1"))

    def test_var_dict_cant_override(self):
        v = var_dict.VarDict()
        v.SetValue("test1", "value1", "test 1 comment")
        ## confirm override == false
        v.SetValue("test1", "value2", "test for override")
        vv = v.GetValue("test1")
        self.assertEqual("value1", vv)

        v.SetValue("test1", "value1", "set same")  # to get coverage
        vv = v.GetValue("test1")
        self.assertEqual("value1", vv)

    def test_var_dict_can_override(self):
        v = var_dict.VarDict()
        v.SetValue("test1", "value1", "test 1 comment", True)
        ## confirm override == true
        v.SetValue("test1", "value2", "test for override")
        vv = v.GetValue("test1")
        self.assertEqual("value2", vv)

    def test_var_dict_key_not_case_sensitive(self):
        v = var_dict.VarDict()
        v.SetValue("test1", "value1", "test 1 comment")
        ## confirm case sensitivity
        vv = v.GetValue("TEST1")
        self.assertEqual("value1", vv)

    def test_var_dict_key_not_case_sensitive2(self):
        v = var_dict.VarDict()
        v.SetValue("TEST1", "value1", "test 1 comment")
        ## confirm case sensitivity
        vv = v.GetValue("test1")
        self.assertEqual("value1", vv)

    def test_var_dict_key_not_case_sensitive3(self):
        v = var_dict.VarDict()
        v.SetValue("TeSt1", "value1", "test 1 comment")
        ## confirm case sensitivity
        vv = v.GetValue("tEsT1")
        self.assertEqual("value1", vv)

    def test_var_dict_build_value_when_type_para_used(self):
        v = var_dict.VarDict()
        v.SetValue("bld_debug_test1", "builddvalue1", "build dtest 1 comment")
        v.SetValue("bld_release_test1", "buildrvalue1", "build rtest 1 comment")
        ## confirm with correct build type debug
        vv = v.GetBuildValue("TEST1", "DEBUG")
        self.assertEqual("builddvalue1", vv)
        ## confirm with correct build type release
        vv = v.GetBuildValue("TEST1", "release")
        self.assertEqual("buildrvalue1", vv)

    def test_var_dict_build_value_none_for_key(self):
        v = var_dict.VarDict()
        v.SetValue("bld_debug_test1", "builddvalue1", "build test 1 comment")
        self.assertIsNone(v.GetBuildValue(None, "DEBUG"))

    def test_var_dict_build_value_when_type_para_used_wc(self):
        v = var_dict.VarDict()
        v.SetValue("bld_*_test1", "buildvalue1", "build test 1 comment")
        ## confirm wildcard support build type fail back to *
        vv = v.GetBuildValue("TEST1", "DEBUG")
        self.assertEqual("buildvalue1", vv)
        vv = v.GetBuildValue("TEST1", "RELEASE")
        self.assertEqual("buildvalue1", vv)

        ## confirm match has higher priority
        v.SetValue("bld_debug_test1", "builddvalue1", "build test 1 comment")
        vv = v.GetBuildValue("TEST1", "DEBUG")
        self.assertEqual("builddvalue1", vv)

        v.SetValue("bld_release_test1", "buildrvalue1", "build test 1 comment")
        vv = v.GetBuildValue("TEST1", "release")
        self.assertEqual("buildrvalue1", vv)

        vv = v.GetBuildValue("TEST1", "NOOPT")
        self.assertEqual("buildvalue1", vv)

    def test_var_dict_build_value_when_target_set(self):
        v = var_dict.VarDict()
        v.SetValue("bld_*_test1", "buildvalue1", "build test 1 comment")
        v.SetValue("TARGET", "DEBUG", "Set to Debug")
        ## confirm can get it with target set
        vv = v.GetBuildValue("TEST1")
        self.assertEqual("buildvalue1", vv)

    def test_var_dict_build_value_when_no_build_type(self):
        v = var_dict.VarDict()
        v.SetValue("bld_*_test1", "buildvalue1", "build test 1 comment")
        ## confirm can't get it without build type or target set
        vv = v.GetBuildValue("TEST1")
        self.assertEqual(None, vv)

    def test_var_dict_get_all_with_no_entires(self):
        v = var_dict.VarDict()
        v.SetValue("test1", "buildvalue1", "build test 1 comment")
        v.SetValue("test2", "test", "non build value")
        ## confirm result only has 1 value
        vlist = v.GetAllBuildKeyValues("DEBUG")
        self.assertEqual(len(vlist), 0)

    def test_var_dict_get_all_with_no_target(self):
        v = var_dict.VarDict()
        v.SetValue("test1", "buildvalue1", "build test 1 comment")
        v.SetValue("test2", "test", "non build value")
        ## confirm result only has 1 value
        vlist = v.GetAllBuildKeyValues()
        self.assertEqual(len(vlist), 0)

    def test_var_dict_get_all_build_key_values_and_not_other_values(self):
        v = var_dict.VarDict()
        v.SetValue("bld_*_test1", "buildvalue1", "build test 1 comment")
        v.SetValue("test2", "test", "non build value")
        ## confirm result only has 1 value
        vlist = v.GetAllBuildKeyValues("DEBUG")
        self.assertEqual(len(vlist), 1)

        ## confirm override behavior
        v.SetValue("Target", "DEBUG", "Set target to debug")
        v.SetValue("bld_release_test1", "buildvalue1", "build test 1 comment")
        vlist = v.GetAllBuildKeyValues()
        self.assertEqual(len(vlist), 1)
        ## override using parameter for build type
        vlist = v.GetAllBuildKeyValues("RELEASE")
        self.assertEqual(len(vlist), 1)

    def test_var_dict_print_all(self):
        v = var_dict.VarDict()
        v.SetValue("bld_*_test1", "buildvalue1", "build test 1 comment")
        v.SetValue("test2", "value1", "test 1 comment overrideable", True)
        v.PrintAll()


if __name__ == '__main__':
    unittest.main()
