# @file test_shell_environment.py
# Unit test suite for the ShellEnvironment class.
#
##
# Copyright (c) Microsoft Corporation
#
# SPDX-License-Identifier: BSD-2-Clause-Patent
##
"""Unit test suite for the ShellEnvironment class."""

import os
import sys
import unittest

import edk2toolext.environment.shell_environment as SE


class TestShellEnvironmentAssumptions(unittest.TestCase):
    """Unit test suite for the basic assumptions of the ShellEnvironment class."""

    def test_shell_should_be_a_singleton(self) -> None:
        """ShellEnvironment should be a singleton."""
        shell_a = SE.ShellEnvironment()
        shell_b = SE.ShellEnvironment()
        self.assertIs(shell_a, shell_b, "two instances of ShellEnvironment should be identical")

    def test_shell_tests_need_to_be_able_to_clear_singleton(self) -> None:
        """ShellEnvironment singleton should be clearable for testing purposes."""
        # This is not currently achievable, and may never be achievable.

    def test_shell_should_always_have_an_initial_checkpoint(self) -> None:
        """A new instance of ShellEnvironment should always have an initial checkpoint."""
        shell_env = SE.ShellEnvironment()
        self.assertTrue(
            (len(shell_env.checkpoints) > 0), "a new instance of ShellEnvironment should have at least one checkpoint"
        )


class TestBasicEnvironmentManipulation(unittest.TestCase):
    """Unit test suite for basic environment manipulation in the ShellEnvironment class."""

    def test_can_set_os_vars(self) -> None:
        """OS vars should be settable."""
        shell_env = SE.ShellEnvironment()
        # Remove the test var, if it exists.
        os.environ.pop("SE-TEST-VAR-1", None)
        # Set a new value and get it directly from the environment.
        new_value = "Dummy"
        shell_env.set_shell_var("SE-TEST-VAR-1", new_value)
        self.assertEqual(os.environ["SE-TEST-VAR-1"], new_value)

        with self.assertRaises(ValueError):
            shell_env.set_shell_var("SE-TEST-VAR-FAIL", None)

    def test_can_get_os_vars(self) -> None:
        """OS vars should be retrievable."""
        shell_env = SE.ShellEnvironment()
        new_value = "Dummy2"
        shell_env.set_shell_var("SE-TEST-VAR-2", new_value)
        self.assertEqual(shell_env.get_shell_var("SE-TEST-VAR-2"), new_value)

    def test_set_path_string(self) -> None:
        """Set PATH with a string."""
        shell_env = SE.ShellEnvironment()

        # Test pass 1.
        testpath_elems = ["MY_PATH"]
        testpath_string = os.pathsep.join(testpath_elems)
        shell_env.set_path(testpath_string)
        self.assertEqual(os.environ["PATH"], testpath_string, "the final string should be correct")
        for elem in testpath_elems:
            self.assertIn(elem, shell_env.active_path, "the active path should contain all elements")

        # Test pass 2.
        testpath_elems = ["/bin/bash", "new_path", "/root"]
        testpath_string = os.pathsep.join(testpath_elems)
        shell_env.set_path(testpath_string)
        self.assertEqual(os.environ["PATH"], testpath_string, "the final string should be correct")
        for elem in testpath_elems:
            self.assertIn(elem, shell_env.active_path, "the active path should contain all elements")

    def test_set_path_elements(self) -> None:
        """Set PATH with a list of elements."""
        shell_env = SE.ShellEnvironment()

        # Test pass 1.
        testpath_elems = ["MY_PATH"]
        testpath_string = os.pathsep.join(testpath_elems)
        shell_env.set_path(testpath_elems)
        self.assertEqual(os.environ["PATH"], testpath_string, "the final string should be correct")
        for elem in testpath_elems:
            self.assertIn(elem, shell_env.active_path, "the active path should contain all elements")

        # Test pass 2.
        testpath_elems = ["/bin/bash", "new_path", "/root"]
        testpath_string = os.pathsep.join(testpath_elems)
        shell_env.set_path(testpath_elems)
        self.assertEqual(os.environ["PATH"], testpath_string, "the final string should be correct")
        for elem in testpath_elems:
            self.assertIn(elem, shell_env.active_path, "the active path should contain all elements")

    def test_set_pypath_string(self) -> None:
        """Set PYTHONPATH with a string."""
        shell_env = SE.ShellEnvironment()

        # Test pass 1.
        testpath_elems = ["MY_PATH"]
        testpath_string = os.pathsep.join(testpath_elems)
        shell_env.set_pypath(testpath_string)
        self.assertEqual(os.environ["PYTHONPATH"], testpath_string, "the final string should be correct")
        for elem in testpath_elems:
            self.assertIn(elem, shell_env.active_pypath, "the active path should contain all elements")
            self.assertIn(elem, sys.path, "the sys path should contain all elements")

        # Test pass 2.
        testpath_elems = ["/bin/bash", "new_path", "/root"]
        testpath_string = os.pathsep.join(testpath_elems)
        shell_env.set_pypath(testpath_string)
        self.assertEqual(os.environ["PYTHONPATH"], testpath_string, "the final string should be correct")
        for elem in testpath_elems:
            self.assertIn(elem, shell_env.active_pypath, "the active path should contain all elements")
            self.assertIn(elem, sys.path, "the sys path should contain all elements")

    def test_set_pypath_elements(self) -> None:
        """Set PYTHONPATH with a list of elements."""
        shell_env = SE.ShellEnvironment()

        # Test pass 1.
        testpath_elems = ["MY_PATH"]
        testpath_string = os.pathsep.join(testpath_elems)
        shell_env.set_pypath(testpath_elems)
        self.assertEqual(os.environ["PYTHONPATH"], testpath_string, "the final string should be correct")
        for elem in testpath_elems:
            self.assertIn(elem, shell_env.active_pypath, "the active path should contain all elements")
            self.assertIn(elem, sys.path, "the sys path should contain all elements")

        # Test pass 2.
        testpath_elems = ["/bin/bash", "new_path", "/root"]
        testpath_string = os.pathsep.join(testpath_elems)
        shell_env.set_pypath(testpath_elems)
        self.assertEqual(os.environ["PYTHONPATH"], testpath_string, "the final string should be correct")
        for elem in testpath_elems:
            self.assertIn(elem, shell_env.active_pypath, "the active path should contain all elements")
            self.assertIn(elem, sys.path, "the sys path should contain all elements")

    def test_insert_append_remove_replace_path(self) -> None:
        """Insert, append, remove, and replace tests for the PATH."""
        shell_env = SE.ShellEnvironment()

        # Start with a known PATH
        mid_elem = "MIDDLEPATH"
        shell_env.set_path(mid_elem)
        self.assertEqual(1, len(shell_env.active_path))
        self.assertIn(mid_elem, shell_env.active_path)
        # Add an element to the end.
        end_elem = "ENDPATH"
        shell_env.append_path(end_elem)
        # Add an element to the beginning.
        start_elem = "STARTPATH"
        shell_env.insert_path(start_elem)

        # Test for the realities.
        self.assertEqual(3, len(shell_env.active_path))
        self.assertEqual(shell_env.active_path[0], start_elem)
        self.assertEqual(shell_env.active_path[1], mid_elem)
        self.assertEqual(shell_env.active_path[2], end_elem)
        for elem in (start_elem, mid_elem, end_elem):
            self.assertIn(elem, os.environ["PATH"])

        # Test inserting existing elements as a method to move them front
        shell_env.insert_path(end_elem)
        self.assertEqual(3, len(shell_env.active_path))
        self.assertEqual(shell_env.active_path[0], end_elem)
        self.assertEqual(shell_env.active_path[1], start_elem)
        self.assertEqual(shell_env.active_path[2], mid_elem)

        # Test appending existing elements as a method to move to end
        shell_env.append_path(end_elem)
        self.assertEqual(3, len(shell_env.active_path))
        self.assertEqual(shell_env.active_path[0], start_elem)
        self.assertEqual(shell_env.active_path[1], mid_elem)
        self.assertEqual(shell_env.active_path[2], end_elem)

        # Test replacing an element on the path
        new_mid_elem = "NEWMIDDLEPATH"
        shell_env.replace_path_element(mid_elem, new_mid_elem)
        self.assertEqual(shell_env.active_path[1], new_mid_elem)

        # Test replacing an element that doesn't exist
        old_path = shell_env.active_path
        shell_env.replace_path_element("PATH1", "PATH2")
        self.assertEqual(old_path, shell_env.active_path)

        # Test that removing an element works as expected
        shell_env.remove_path_element(new_mid_elem)
        self.assertNotIn(new_mid_elem, shell_env.active_path)

        # Test that calling Set Var can replace the path
        shell_env.set_shell_var("PATH", "a" + os.pathsep + "b")
        self.assertEqual(len(os.environ["PATH"].split(os.pathsep)), 2)

        # Test that calling Set Var can replace the path and is case insensitive
        shell_env.set_shell_var("pAtH", "c" + os.pathsep + "d" + os.pathsep + "e")
        self.assertEqual(len(os.environ["PATH"].split(os.pathsep)), 3)

    def test_insert_append_remove_replace_pypath(self) -> None:
        """Insert, append, remove, and replace tests for the PYTHONPATH."""
        shell_env = SE.ShellEnvironment()

        # Start with a known PATH
        mid_elem = "MIDDLEPATH"
        shell_env.set_pypath(mid_elem)
        self.assertEqual(1, len(shell_env.active_pypath))
        self.assertIn(mid_elem, shell_env.active_pypath)
        # Add an element to the end.
        end_elem = "ENDPATH"
        shell_env.append_pypath(end_elem)
        # Add an element to the beginning.
        start_elem = "STARTPATH"
        shell_env.insert_pypath(start_elem)

        # Test for the realities.
        self.assertEqual(3, len(shell_env.active_pypath))
        self.assertEqual(shell_env.active_pypath[0], start_elem)
        self.assertEqual(shell_env.active_pypath[1], mid_elem)
        self.assertEqual(shell_env.active_pypath[2], end_elem)
        for elem in (start_elem, mid_elem, end_elem):
            self.assertIn(elem, os.environ["PYTHONPATH"])
            self.assertIn(elem, sys.path)

        # Test replacing an element on the pypath
        new_mid_elem = "NEWMIDDLEPATH"
        shell_env.replace_pypath_element(mid_elem, new_mid_elem)
        self.assertEqual(shell_env.active_pypath[1], new_mid_elem)

        # Test replacing an element that doesn't exist
        old_pypath = shell_env.active_pypath
        shell_env.replace_pypath_element("PATH1", "PATH2")
        self.assertEqual(old_pypath, shell_env.active_pypath)

        # Test that removing an element works as expected
        shell_env.remove_pypath_element(new_mid_elem)
        self.assertNotIn(new_mid_elem, shell_env.active_pypath)

    def test_can_set_and_get_build_vars(self) -> None:
        """Build vars should be settable and retrievable."""
        shell_env = SE.ShellEnvironment()

        var_name = "SE-TEST-VAR-3"
        var_data = "Dummy3"
        # Make sure it doesn't exist beforehand.
        self.assertIs(shell_env.get_build_var(var_name), None, "test var should not exist before creation")
        shell_env.set_build_var(var_name, var_data)
        self.assertEqual(shell_env.get_build_var(var_name), var_data, "get var data should match set var data")

    def test_set_build_vars_should_default_overrideable(self) -> None:
        """Build vars should default to overrideable."""
        shell_env = SE.ShellEnvironment()

        var_name = "SE_TEST_VAR_4"
        var_data = "NewData1"
        var_data2 = "NewerData1"

        self.assertIs(shell_env.get_build_var(var_name), None, "test var should not exist before creation")
        shell_env.set_build_var(var_name, var_data)
        shell_env.set_build_var(var_name, var_data2)

        self.assertEqual(shell_env.get_build_var(var_name), var_data2)


class TestShellEnvironmenCheckpoints(unittest.TestCase):
    """Unit test suite for the checkpointing system in the ShellEnvironment class."""

    def setUp(self) -> None:
        """Set up the test environment."""
        # Grab the singleton and restore the initial checkpoint.
        shell_env = SE.ShellEnvironment()
        shell_env.restore_initial_checkpoint()
        # For testing, purge all checkpoints each time.
        shell_env.checkpoints = [shell_env.checkpoints[SE.ShellEnvironment.INITIAL_CHECKPOINT]]

    def test_restore_initial_checkpoint_should_erase_changes(self) -> None:
        """Restoring the initial checkpoint should erase all changes."""
        shell_env = SE.ShellEnvironment()

        # Check to make sure the change doesn't exist.
        test_path_change = "/SE/TEST/PATH/1"
        self.assertNotIn(test_path_change, shell_env.active_path, "starting condition should not have the test change")

        # Make the change and verify.
        shell_env.append_path(test_path_change)
        self.assertIn(test_path_change, shell_env.active_path)

        # Add a shell_var while we're at it.
        self.assertEqual(shell_env.get_shell_var("i_should_not_exist"), None)
        shell_env.set_shell_var("i_should_not_exist", "a_value")
        self.assertEqual(shell_env.get_shell_var("i_should_not_exist"), "a_value")

        # Restore initial checkpoint and verify change is gone.
        shell_env.restore_initial_checkpoint()
        self.assertNotIn(test_path_change, shell_env.active_path, "restoring checkpoint should remove test change")
        self.assertEqual(shell_env.get_shell_var("i_should_not_exist"), None)

    def test_checkpoint_indices_should_be_unique(self) -> None:
        """Checkpoint indices should be unique."""
        shell_env = SE.ShellEnvironment()
        shell_env.append_path("/SE/TEST/PATH/1")
        check_point1 = shell_env.checkpoint()
        shell_env.append_path("/SE/TEST/PATH/2")
        check_point2 = shell_env.checkpoint()

        self.assertNotEqual(check_point1, SE.ShellEnvironment.INITIAL_CHECKPOINT)
        self.assertNotEqual(check_point2, SE.ShellEnvironment.INITIAL_CHECKPOINT)
        self.assertNotEqual(check_point1, check_point2)

    def test_restore_new_checkpoint_should_contain_new_changes(self) -> None:
        """Restoring a new checkpoint should contain the changes made after the checkpoint."""
        shell_env = SE.ShellEnvironment()

        # Check to make sure the change doesn't exist.
        test_path_change = "/SE/TEST/PATH/3"
        self.assertNotIn(test_path_change, shell_env.active_path, "starting condition should not have the test change")

        # Make the change and checkpoint.
        shell_env.append_path(test_path_change)
        self.assertIn(test_path_change, shell_env.active_path)
        check_point1 = shell_env.checkpoint()

        # Restore initial checkpoint and verify change is gone.
        shell_env.restore_initial_checkpoint()
        self.assertNotIn(
            test_path_change, shell_env.active_path, "restoring initial checkpoint should remove test change"
        )

        # Restore new checkpoint and verify change is back.
        shell_env.restore_checkpoint(check_point1)
        self.assertIn(test_path_change, shell_env.active_path, "restoring new checkpoint should restore test change")

    def test_checkpointed_objects_should_behave_correctly(self) -> None:
        """Checkpointed objects should behave correctly."""
        shell_env = SE.ShellEnvironment()

        # This test is to make sure that pass-by-reference elements don't persist unexpectedly.

        test_var1_name = "SE_TEST_VAR_3"
        test_var1_data = "MyData1"
        test_var1_data2 = "RevisedData1"
        test_var1_data3 = "MoreRevisedData1"

        test_var2_name = "SE_TEST_VAR_4"
        test_var2_data = "MyData2"

        # Set the first data and make a checkpoint.
        shell_env.set_build_var(test_var1_name, test_var1_data)
        check_point1 = shell_env.checkpoint()

        # Update previous value and set second data. Then checkpoint.
        shell_env.set_build_var(test_var1_name, test_var1_data2)
        shell_env.set_build_var(test_var2_name, test_var2_data)
        check_point2 = shell_env.checkpoint()

        # Restore the first checkpoint and verify values.
        shell_env.restore_checkpoint(check_point1)
        self.assertEqual(shell_env.get_build_var(test_var1_name), test_var1_data)
        self.assertIs(shell_env.get_build_var(test_var2_name), None)

        # Make a change to be tested later.
        shell_env.set_build_var(test_var1_name, test_var1_data3)

        # Restore the second checkpoint and verify values.
        shell_env.restore_checkpoint(check_point2)
        self.assertEqual(shell_env.get_build_var(test_var1_name), test_var1_data2)
        self.assertEqual(shell_env.get_build_var(test_var2_name), test_var2_data)

        # Restore the first checkpoint again and make sure original value still stands.
        shell_env.restore_checkpoint(check_point1)
        self.assertEqual(shell_env.get_build_var(test_var1_name), test_var1_data)


class TestShellEnvironmenSpecialBuildVars(unittest.TestCase):
    """Unit test suite for the special build vars in the ShellEnvironment class."""

    def setUp(self) -> None:
        """Set up the test environment."""
        # Grab the singleton and restore the initial checkpoint.
        shell_env = SE.ShellEnvironment()
        shell_env.restore_initial_checkpoint()
        # For testing, purge all checkpoints each time.
        shell_env.checkpoints = [shell_env.checkpoints[SE.ShellEnvironment.INITIAL_CHECKPOINT]]

    def test_get_build_vars_should_update_vars(self) -> None:
        """Special build vars should be updated when queried."""
        shell_env = SE.ShellEnvironment()
        build_vars = SE.GetBuildVars()

        test_var_name = "SE_TEST_VAR_4"
        test_var_data = "NewData1"

        build_vars.SetValue(test_var_name, test_var_data, "random set")

        self.assertEqual(shell_env.get_build_var(test_var_name), test_var_data)

    def test_special_build_vars_should_default_non_overrideable(self) -> None:
        """Special build vars should default to non-overrideable."""
        shell_env = SE.ShellEnvironment()
        build_vars = SE.GetBuildVars()

        test_var_name = "SE_TEST_VAR_4"
        test_var_data = "NewData1"
        test_var_data2 = "NewerData1"

        build_vars.SetValue(test_var_name, test_var_data, "random set")
        build_vars.SetValue(test_var_name, test_var_data2, "another random set")

        self.assertEqual(shell_env.get_build_var(test_var_name), test_var_data)

    def test_special_build_vars_should_always_update_current(self) -> None:
        """Special build vars should always update the current value, even after restoring a checkpoint."""
        shell_env = SE.ShellEnvironment()
        build_vars = SE.GetBuildVars()

        test_var1_name = "SE_TEST_VAR_update_current1"
        test_var1_data = "NewData1"
        test_var1_data2 = "NewerData1"

        test_var2_name = "SE_TEST_VAR_update_current2"
        test_var2_data = "NewData2"

        # Make a change and checkpoint.
        build_vars.SetValue(test_var1_name, test_var1_data, "var1 set", overridable=True)
        shell_env.checkpoint()

        # Make a couple more changes.
        build_vars.SetValue(test_var1_name, test_var1_data2, "var1 set", overridable=True)
        build_vars.SetValue(test_var2_name, test_var2_data, "var2 set", overridable=True)

        # Make sure that the newer changes are valid.
        self.assertEqual(shell_env.get_build_var(test_var1_name), test_var1_data2)
        self.assertEqual(shell_env.get_build_var(test_var2_name), test_var2_data)

    def test_special_build_vars_should_be_checkpointable(self) -> None:
        """Special build vars should be checkpointed and restored correctly."""
        shell_env = SE.ShellEnvironment()
        build_vars = SE.GetBuildVars()

        # This test is basically a rehash of the object checkpointing test,
        # but this time with the special vars.

        test_var1_name = "SE_TEST_VAR_3"
        test_var1_data = "MyData1"
        test_var1_data2 = "RevisedData1"
        test_var1_data3 = "MoreRevisedData1"

        test_var2_name = "SE_TEST_VAR_4"
        test_var2_data = "MyData2"

        # Set the first data and make a checkpoint.
        build_vars.SetValue(test_var1_name, test_var1_data, "var1 set", overridable=True)
        check_point1 = shell_env.checkpoint()

        # Update previous value and set second data. Then checkpoint.
        build_vars.SetValue(test_var1_name, test_var1_data2, "var1 set", overridable=True)
        build_vars.SetValue(test_var2_name, test_var2_data, "var2 set", overridable=True)
        check_point2 = shell_env.checkpoint()

        # Restore the first checkpoint and verify values.
        shell_env.restore_checkpoint(check_point1)
        self.assertEqual(shell_env.get_build_var(test_var1_name), test_var1_data)
        self.assertIs(shell_env.get_build_var(test_var2_name), None)

        # Make a change to be tested later.
        build_vars.SetValue(test_var1_name, test_var1_data3, "var1 set", overridable=True)
        self.assertEqual(
            shell_env.get_build_var(test_var1_name),
            test_var1_data3,
            "even after restore, special build vars should always update current",
        )

        # Restore the second checkpoint and verify values.
        shell_env.restore_checkpoint(check_point2)
        self.assertEqual(shell_env.get_build_var(test_var1_name), test_var1_data2)
        self.assertEqual(shell_env.get_build_var(test_var2_name), test_var2_data)

        # Restore the first checkpoint again and make sure original value still stands.
        shell_env.restore_checkpoint(check_point1)
        self.assertEqual(shell_env.get_build_var(test_var1_name), test_var1_data)


if __name__ == "__main__":
    unittest.main()
