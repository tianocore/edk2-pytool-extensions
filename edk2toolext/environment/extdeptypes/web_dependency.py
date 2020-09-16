# @file web_dependency.py
# This module implements ExternalDependency for files that are available for download online.
#
##
# Copyright (c) Microsoft Corporation
#
# SPDX-License-Identifier: BSD-2-Clause-Patent
##

import os
import logging
import shutil
import tarfile
import zipfile
import tempfile
import urllib.error
import urllib.request
from edk2toolext.environment.external_dependency import ExternalDependency


class WebDependency(ExternalDependency):
    '''
    ext_dep fields:
    - internal_path: Describes layout of what we're downloading. Include / at the beginning
                     if the ext_dep is a directory. Item located at internal_path will
                     unpacked into the ext_dep folder and this is what the path/shell vars
                     will point to when compute_published_path is run.
    - compression_type: optional. supports zip and tar. If the file isn't compressed, do not include this field.
    - sha256: optional. hash of downloaded file to be checked against.
    '''

    TypeString = "web"

    def __init__(self, descriptor):
        super().__init__(descriptor)
        self.internal_path = os.path.normpath(descriptor['internal_path'])
        self.compression_type = descriptor.get('compression_type', None)
        self.sha256 = descriptor.get('sha256', None)

        # If the internal path starts with a / that means we are downloading a directory
        self.download_is_directory = self.internal_path.startswith(os.path.sep)

        # Now we can get rid of the leading /
        self.internal_path = self.internal_path.strip(os.path.sep)

    def __str__(self):
        """ return a string representation of this """
        return f"WebDependecy: {self.source}@{self.version}"

    def linuxize_path(path):
        '''
        path: path that uses os.sep, to be replaced with / for compatibility with zipfile
        '''
        return "/".join(path.split("\\"))

    def unpack(compressed_file_path, destination, internal_path, compression_type):
        '''
        compressed_file_path: name of compressed file to unpack.
        destination: directory you would like it unpacked into.
        internal_path: internal structure of the compressed volume that you would like extracted.
        compression_type: type of compression. tar and zip supported.
        '''

        # First, we will open the file depending on the type of compression we're dealing with.

        # tarfile and zipfile both use the Linux path seperator / instead of using os.sep
        linux_internal_path = WebDependency.linuxize_path(internal_path)

        if compression_type == "zip":
            logging.info(f"{compressed_file_path} is a zip file, trying to unpack it.")
            _ref = zipfile.ZipFile(compressed_file_path, 'r')
            files_in_volume = _ref.namelist()

        elif compression_type and "tar" in compression_type:
            logging.info(f"{compressed_file_path} is a tar file, trying to unpack it.")
            # r:* tells tarfile to look at the header and figure out how to extract it
            _ref = tarfile.open(compressed_file_path, "r:*")
            files_in_volume = _ref.getnames()

        else:
            raise RuntimeError(f"{compressed_file_path} was labeled as {compression_type}, which is not supported.")

        # Filter the files inside to only the ones that are inside the important folder
        files_to_extract = [name for name in files_in_volume if linux_internal_path in name]

        for file in files_to_extract:
            _ref.extract(member=file, path=destination)
        _ref.close()

    def get_internal_path_root(outer_dir, internal_path):
        temp_path_root = internal_path.split(os.sep)[0] if os.sep in internal_path else internal_path
        unzip_root = os.path.join(outer_dir, temp_path_root)
        return unzip_root

    def fetch(self):
        url = self.source
        temp_folder = tempfile.mkdtemp()
        temp_file_path = os.path.join(temp_folder, f"{self.name}_{self.version}")

        try:
            # Download the file and save it locally under `temp_file_path`
            with urllib.request.urlopen(url) as response, open(temp_file_path, 'wb') as out_file:
                out_file.write(response.read())
        except urllib.error.HTTPError as e:
            logging.error(f"ran into an issue when resolving ext_dep {self.name} at {self.source}")
            raise e

        # check if file hash is as expected, if it was provided in the ext_dep.json
        if self.sha256:
            with open(temp_file_path, "rb") as file:
                import hashlib
                temp_file_sha256 = hashlib.sha256(file.read()).hexdigest()

            # compare sha256 hexdigests as lowercase to make case insensitive
            if temp_file_sha256.lower() != self.sha256.lower():
                raise RuntimeError(f"{self.name} - sha256 does not match\n\tdownloaded:"
                                   f"\t{temp_file_sha256}\n\tin json:\t{self.sha256}")

        if os.path.isfile(temp_file_path) is False:
            raise RuntimeError(f"{self.name} did not download")

        # Next, we will look at what's inside it and pull out the parts we need.
        if self.compression_type:
            WebDependency.unpack(temp_file_path, temp_folder, self.internal_path, self.compression_type)

        # internal_path points to the "important" part of the ext_dep we're unpacking
        complete_internal_path = os.path.join(temp_folder, self.internal_path)

        # # If we're unpacking a directory, we can copy the important parts into
        # # a directory named self.contents_dir
        if self.download_is_directory:
            logging.info(f"Copying directory from {complete_internal_path} to {self.contents_dir}")
            if os.path.isdir(complete_internal_path) is False:
                # internal_path was not accurate, exit
                raise RuntimeError(f"{self.name} was expecting {complete_internal_path} to exist after unpacking")

            # Move the important folder out and rename it to contents_dir
            shutil.move(complete_internal_path, self.contents_dir)

            # If the unzipped directory still exists, delete it.
            if os.path.isdir(temp_folder):
                logging.debug(f"Cleaning up {temp_folder}")
                shutil.rmtree(temp_folder)

        # If we just downloaded a file, we need to create a directory named self.contents_dir,
        # copy the file inside, and name it self.internal_path
        else:
            os.makedirs(self.contents_dir, exist_ok=True)
            complete_internal_path = os.path.join(self.contents_dir, self.internal_path)
            logging.info(f"Copying file to {complete_internal_path}")
            shutil.move(temp_file_path, complete_internal_path)

        # Add a file to track the state of the dependency.
        self.update_state_file()

        # The published path may change now that the package has been unpacked.
        self.published_path = self.compute_published_path()
