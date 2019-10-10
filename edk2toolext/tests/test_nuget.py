# @file test_nuget.py
# This contains unit tests for the nuget binary wrapper
##
# Copyright (c) Microsoft Corporation
#
# SPDX-License-Identifier: BSD-2-Clause-Patent
##
import os
import tempfile
import unittest
from edk2toolext.bin import nuget


class Test_nuget(unittest.TestCase):

    def test_can_download_nuget(self):
        test_dir = tempfile.mkdtemp()
        nuget_path = os.path.join(test_dir, "NuGet.exe")
        self.assertFalse(os.path.exists(nuget_path))
        nuget.DownloadNuget(test_dir)
        self.assertTrue(os.path.exists(nuget_path))

    def test_checks_nuget_sha(self):
        test_dir = tempfile.mkdtemp()
        nuget_path = os.path.join(test_dir, "NuGet.exe")
        file = open(nuget_path, "w")
        file.write("This is not the nuget that you are looking for\n. :)")
        file.close()
        with self.assertRaises(RuntimeError):
            nuget.DownloadNuget(test_dir)
