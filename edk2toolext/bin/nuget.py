# @file NuGet.py
# This module contains code that knows how to download nuget
##
# Copyright (c) Microsoft Corporation
#
# SPDX-License-Identifier: BSD-2-Clause-Patent
##
import os
import urllib.error
import urllib.request
import logging

# Update this when you want a new version of NuGet
VERSION = "5.3.1"
URL = "https://dist.nuget.org/win-x86-commandline/v{}/nuget.exe".format(VERSION)
SHA256 = "e3e46eb415561c778a7fdec7194bca9811c6e7f4066cc8cc85244c391b969c11"


def DownloadNuget(unpack_folder: str = None) -> list:
    '''
     Downloads a version of NuGet to the specific folder as NuGet.exe
     If the file already exists, it won't be redownloaded.
     The file will be checked against a SHA256 hash for accuracy
    '''
    if unpack_folder is None:
        unpack_folder = os.path.dirname(__file__)

    out_file_name = os.path.join(unpack_folder, "NuGet.exe")
    # check if we have the nuget file already downloaded
    if not os.path.isfile(out_file_name):
        try:
            # Download the file and save it locally under `temp_file_name`
            with urllib.request.urlopen(URL) as response, open(out_file_name, 'wb') as out_file:
                out_file.write(response.read())
        except urllib.error.HTTPError as e:
            logging.error(f"We ran into an issue when getting NuGet")
            raise e

    # do the hash to make sure the file is good
    with open(out_file_name, "rb") as file:
        import hashlib
        temp_file_sha256 = hashlib.sha256(file.read()).hexdigest()
    if temp_file_sha256 != SHA256:
        os.remove(out_file_name)
        raise RuntimeError(f"Nuget.exe download - sha256 does not match\n\tdownloaded:\t{temp_file_sha256}\n\t")
