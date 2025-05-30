## @file test_git_dependency.py
# Unit test suite for the GitDependency class.
#
##
# Copyright (c) Microsoft Corporation
#
# SPDX-License-Identifier: BSD-2-Clause-Patent
##
"""Unit test suite for the var_dict module."""

import unittest

from edk2toolext.environment import var_dict


class TestVarDict(unittest.TestCase):
    """Unit test for the VarDict class."""

    def test_var_dict_basic_set_get(self) -> None:
        """Test that the SetValue and GetValue functions work."""
        v = var_dict.VarDict()
        v.SetValue("test1", "value1", "test 1 comment")
        ## confirm basic get
        vv = v.GetValue("test1")
        self.assertEqual("value1", vv)

    def test_var_dict_get_key_is_none(self) -> None:
        """Test that the GetValue function works with a None key."""
        v = var_dict.VarDict()
        self.assertIsNone(v.GetValue(None))

    def test_var_dict_get_key_unknown_return_value(self) -> None:
        """Test that the GetValue function returns the default value when the key is unknown."""
        v = var_dict.VarDict()
        self.assertIsNone(v.GetValue("invalidkey"))
        self.assertEqual("test1", v.GetValue("invalidkey", "test1"))

    def test_var_dict_cant_override(self) -> None:
        """Test that the override state is respected."""
        v = var_dict.VarDict()
        v.SetValue("test1", "value1", "test 1 comment")
        ## confirm override == false
        v.SetValue("test1", "value2", "test for override")
        vv = v.GetValue("test1")
        self.assertEqual("value1", vv)

        v.SetValue("test1", "value1", "set same")  # to get coverage
        vv = v.GetValue("test1")
        self.assertEqual("value1", vv)

    def test_var_dict_can_override(self) -> None:
        """Test that the override state can be changed."""
        v = var_dict.VarDict()
        v.SetValue("test1", "value1", "test 1 comment", True)
        ## confirm override == true
        v.SetValue("test1", "value2", "test for override")
        vv = v.GetValue("test1")
        self.assertEqual("value2", vv)

    def test_var_dict_can_change_override_state_with_same_set(self) -> None:
        """Test that the override state can be changed with the same value set."""
        v = var_dict.VarDict()
        v.SetValue("test1", "value1", "test 1 comment", True)
        v.SetValue("test1", "value1", "Change override to false", False)
        v.SetValue("test1", "value2", "this should fail", False)
        self.assertNotEqual(v.GetValue("test1"), "value2")

    def test_var_dict_can_change_override_state_with_allow_override(self) -> None:
        """Test that the override state can be changed with the AllowOverride function."""
        v = var_dict.VarDict()
        v.SetValue("test1", "value1", "test 1 comment", False)
        v.AllowOverride("test1")
        v.SetValue("test1", "value2", "this should be allowed", False)
        self.assertEqual(v.GetValue("test1"), "value2")
        ## since override was set to False should not change again
        v.SetValue("test1", "value3", "this should not be allowed", False)
        self.assertEqual(v.GetValue("test1"), "value2")

    def test_var_dict_key_not_case_sensitive(self) -> None:
        """Test that the key is not case sensitive."""
        v = var_dict.VarDict()
        v.SetValue("test1", "value1", "test 1 comment")
        ## confirm case sensitivity
        vv = v.GetValue("TEST1")
        self.assertEqual("value1", vv)

    def test_var_dict_key_not_case_sensitive2(self) -> None:
        """Test that the key is not case sensitive."""
        v = var_dict.VarDict()
        v.SetValue("TEST1", "value1", "test 1 comment")
        ## confirm case sensitivity
        vv = v.GetValue("test1")
        self.assertEqual("value1", vv)

    def test_var_dict_key_not_case_sensitive3(self) -> None:
        """Test that the key is not case sensitive."""
        v = var_dict.VarDict()
        v.SetValue("TeSt1", "value1", "test 1 comment")
        ## confirm case sensitivity
        vv = v.GetValue("tEsT1")
        self.assertEqual("value1", vv)

    def test_var_dict_build_value_when_type_para_used(self) -> None:
        """Test that the GetBuildValue function works with a build type parameter."""
        v = var_dict.VarDict()
        v.SetValue("bld_debug_test1", "build_d_value1", "build debug test 1 comment")
        v.SetValue("bld_release_test1", "build_r_value1", "build release test 1 comment")
        ## confirm with correct build type debug
        vv = v.GetBuildValue("TEST1", "DEBUG")
        self.assertEqual("build_d_value1", vv)
        ## confirm with correct build type release
        vv = v.GetBuildValue("TEST1", "release")
        self.assertEqual("build_r_value1", vv)

    def test_var_dict_build_value_none_for_key(self) -> None:
        """Test that the GetBuildValue function works with a None key."""
        v = var_dict.VarDict()
        v.SetValue("bld_debug_test1", "build_d_value1", "build test 1 comment")
        self.assertIsNone(v.GetBuildValue(None, "DEBUG"))

    def test_var_dict_build_value_when_type_para_used_wc(self) -> None:
        """Test that the GetBuildValue function works with wildcard build types."""
        v = var_dict.VarDict()
        v.SetValue("bld_*_test1", "build_value1", "build test 1 comment")
        ## confirm wildcard support build type fail back to *
        vv = v.GetBuildValue("TEST1", "DEBUG")
        self.assertEqual("build_value1", vv)
        vv = v.GetBuildValue("TEST1", "RELEASE")
        self.assertEqual("build_value1", vv)

        ## confirm match has higher priority
        v.SetValue("bld_debug_test1", "build_d_value1", "build test 1 comment")
        vv = v.GetBuildValue("TEST1", "DEBUG")
        self.assertEqual("build_d_value1", vv)

        v.SetValue("bld_release_test1", "build_r_value1", "build test 1 comment")
        vv = v.GetBuildValue("TEST1", "release")
        self.assertEqual("build_r_value1", vv)

        vv = v.GetBuildValue("TEST1", "NOOPT")
        self.assertEqual("build_value1", vv)

    def test_var_dict_build_value_when_target_set(self) -> None:
        """Test that the GetBuildValue function works with target set."""
        v = var_dict.VarDict()
        v.SetValue("bld_*_test1", "build_value1", "build test 1 comment")
        v.SetValue("TARGET", "DEBUG", "Set to Debug")
        ## confirm can get it with target set
        vv = v.GetBuildValue("TEST1")
        self.assertEqual("build_value1", vv)

    def test_var_dict_build_value_when_no_build_type(self) -> None:
        """Test that the GetBuildValue function works with no build type set."""
        v = var_dict.VarDict()
        v.SetValue("bld_*_test1", "build_value1", "build test 1 comment")
        ## confirm can't get it without build type or target set
        vv = v.GetBuildValue("TEST1")
        self.assertEqual(None, vv)

    def test_var_dict_get_all_with_no_entires(self) -> None:
        """Test that the GetAll function works with no entries."""
        v = var_dict.VarDict()
        v.SetValue("test1", "build_value1", "build test 1 comment")
        v.SetValue("test2", "test", "non build value")
        ## confirm result only has 1 value
        vlist = v.GetAllBuildKeyValues("DEBUG")
        self.assertEqual(len(vlist), 0)

    def test_var_dict_get_all_with_no_target(self) -> None:
        """Test that the GetAllBuildKeyValues function works."""
        v = var_dict.VarDict()
        v.SetValue("test1", "build_value1", "build test 1 comment")
        v.SetValue("test2", "test", "non build value")
        ## confirm result only has 1 value
        vlist = v.GetAllBuildKeyValues()
        self.assertEqual(len(vlist), 0)

    def test_var_dict_get_all_build_key_values_and_not_other_values(self) -> None:
        """Test that the GetAllBuildKeyValues function works."""
        v = var_dict.VarDict()
        v.SetValue("bld_*_test1", "build_value1", "build test 1 comment")
        v.SetValue("test2", "test", "non build value")
        ## confirm result only has 1 value
        vlist = v.GetAllBuildKeyValues("DEBUG")
        self.assertEqual(len(vlist), 1)
        self.assertIn("TEST1", vlist.keys())

        ## confirm override behavior
        v.SetValue("Target", "DEBUG", "Set target to debug")
        v.SetValue("bld_release_test1", "build_value1", "build test 1 comment")
        vlist = v.GetAllBuildKeyValues()
        self.assertEqual(len(vlist), 1)
        ## override using parameter for build type
        vlist = v.GetAllBuildKeyValues("RELEASE")
        self.assertEqual(len(vlist), 1)
        self.assertIn("TEST1", vlist.keys())

    def test_var_dict_get_all_nonbuild_key_values(self) -> None:
        """Test that the GetAllNonBuildKeyValues function works."""
        v = var_dict.VarDict()
        v.SetValue("bld_*_test1", "build_value1", "build test 1 comment")
        v.SetValue("test2", "test", "non build value")
        ## confirm result only has 1 value
        vlist = v.GetAllNonBuildKeyValues()
        self.assertEqual(len(vlist), 1)
        self.assertIn("TEST2", vlist.keys())

    def test_var_dict_print_all(self) -> None:
        """Test that the PrintAll function works."""
        v = var_dict.VarDict()
        v.SetValue("bld_*_test1", "build_value1", "build test 1 comment")
        v.SetValue("test2", "value1", "test 1 comment overrideable", True)
        v.PrintAll()

    def test_var_dict_non_valued_var(self) -> None:
        """Test that a var can be set with a value of None."""
        v = var_dict.VarDict()
        v.SetValue("var1", "", "Test Comment")
        self.assertEqual(v.GetValue("var1"), "")
        v.SetValue("var2", None, "Test Comment")
        self.assertNotEqual(v.GetValue("var2"), None)
        self.assertTrue(v.GetValue("var2"), "Should return True")


if __name__ == "__main__":
    unittest.main()
