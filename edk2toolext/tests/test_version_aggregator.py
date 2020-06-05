# @file test_version_aggregator.py
# Unit test suite for the version_aggregator class.
#
##
# Copyright (c) Microsoft Corporation
#
# SPDX-License-Identifier: BSD-2-Clause-Patent
##
import unittest
from edk2toolext.environment import version_aggregator


class TestVersionAggregator(unittest.TestCase):
    def setUp(self):
        version_aggregator.ResetVersionAggregator()
        pass

    def tearDown(self):
        pass

    @classmethod
    def setUpClass(cls):
        pass

    @classmethod
    def tearDownClass(cls):
        pass

    def test_Singelton(self):
        version1 = version_aggregator.GetVersionAggregator()
        version2 = version_aggregator.GetVersionAggregator()
        self.assertEqual(version1, version2)
        self.assertIsNotNone(version1)
        version3 = version_aggregator.version_aggregator()
        version4 = version_aggregator.version_aggregator()
        self.assertNotEqual(version3, version4)

    def test_ReportVersions(self):
        version1 = version_aggregator.version_aggregator()
        version1.ReportVersion("test", "test", version_aggregator.VersionTypes.TOOL)
        self.assertEqual(len(version1.GetAggregatedVersionInformation()), 1)
        pass

    def test_ReportVersions_collision(self):
        version1 = version_aggregator.version_aggregator()
        version1.ReportVersion("test", "test", version_aggregator.VersionTypes.TOOL)
        # if keys don't collide we are good
        version1.ReportVersion("test2", "test", version_aggregator.VersionTypes.COMMIT)
        version1.ReportVersion("test3", "test", version_aggregator.VersionTypes.BINARY)
        version1.ReportVersion("test4", "test", version_aggregator.VersionTypes.INFO)
        # we're good to report the same thing twice as long as it matches
        version1.ReportVersion("test", "test", version_aggregator.VersionTypes.TOOL)
        with self.assertRaises(ValueError):
            version1.ReportVersion("test", "test2", version_aggregator.VersionTypes.INFO)

    def test_GetInformation(self):
        version1 = version_aggregator.version_aggregator()
        test_ver = ["I think", "I exist"]
        version1.ReportVersion("I think", "therefore", version_aggregator.VersionTypes.INFO)
        version1.ReportVersion("I exist", "proof", version_aggregator.VersionTypes.INFO)
        test2_ver = list(version1.GetAggregatedVersionInformation().keys())
        self.assertListEqual(test_ver, test2_ver)
        version1.ReportVersion("test", "test", version_aggregator.VersionTypes.TOOL)
        self.assertEqual(len(test2_ver), 2)
        test2_ver = list(version1.GetAggregatedVersionInformation().keys())
        self.assertEqual(len(test2_ver), 3)

    def test_reset(self):
        version1 = version_aggregator.version_aggregator()
        version1.ReportVersion("test", "I exist", version_aggregator.VersionTypes.INFO)
        self.assertEqual(len(version1.GetAggregatedVersionInformation()), 1)
        version1.Reset()
        self.assertEqual(len(version1.GetAggregatedVersionInformation()), 0)

    def test_global_reset(self):
        version1 = version_aggregator.version_aggregator()
        version1.ReportVersion("test", "I exist", version_aggregator.VersionTypes.INFO)
        self.assertEqual(len(version1.GetAggregatedVersionInformation()), 1)
        version1 = version_aggregator.version_aggregator()
        version_aggregator.ResetVersionAggregator()
        self.assertEqual(len(version1.GetAggregatedVersionInformation()), 0)


if __name__ == '__main__':
    unittest.main()
