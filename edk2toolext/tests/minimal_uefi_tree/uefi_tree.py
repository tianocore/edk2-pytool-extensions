# this is for creating a minimal uefi tree for testing
##
# Copyright (c) Microsoft Corporation
#
# SPDX-License-Identifier: BSD-2-Clause-Patent

import os
import tempfile
import shutil


class uefi_tree:
    ''' 
    This class represents a minimal UEFI tree that you can setup
    It is configurable and offers options to modify the tree for
    '''

    def __init__(self, workspace=None):
        ''' copy the minimal tree to a folder, if one is not provided we will create a new temporary folder for you '''
        if workspace == None:
            workspace = os.path.abspath(tempfile.mkdtemp())
        uefi_tree._copytree(uefi_tree._get_src_folder(), workspace, ignore=uefi_tree._copyfilter)
        self.workspace = workspace

    @staticmethod
    def _get_src_folder():
        return os.path.dirname(os.path.abspath(__file__))

    @staticmethod
    def _get_optional_folder():
        return os.path.join(uefi_tree._get_src_folder(), "optional")

    def get_workspace(self):
        return self.workspace

    @staticmethod
    def _copyfilter(src, names):
        ''' make sure we don't copy anything we don't want '''
        names = [x for x in names if x != "__pycache__"]
        names = [x for x in names if x != os.path.basename(__file__)]  # don't copy ourselves
        names = [x for x in names if x != "optional"]  # don't copy
        return names

    @staticmethod
    def _copytree(src, dst, symlinks=False, ignore=None):
        # https://stackoverflow.com/questions/1868714/how-do-i-copy-an-entire-directory-of-files-into-an-existing-directory-using-pyth
        items = os.listdir(src)
        if ignore is not None:
            items = ignore(src, items)
        for item in items:
            s = os.path.join(src, item)
            d = os.path.join(dst, item)
            if os.path.isdir(s):
                shutil.copytree(s, d, symlinks, ignore)
            else:
                shutil.copy2(s, d)

    @staticmethod
    def write_to_file(path, contents, close=True):
        f = open(path, "w")
        f.writelines(contents)
        if close:
            f.close()

    def get_settings_provider_path(self):
        ''' gets the settings provider in the workspace '''
        return os.path.join(self.workspace, "settings.py")

    def get_optional_file(self, file):
        ''' gets the path of an optional file '''
        optional_path = os.path.join(uefi_tree._get_optional_folder(), file)
        if os.path.exists(optional_path):
            return os.path.abspath(optional_path)
        raise ValueError(f"Optional file not found {file}")

    def create_ext_dep(self, dep_type, name, version, source=None, scope="global", dir_path=""):
        ''' creates an ext dep in your workspace '''
        dep_type = dep_type.lower()
        if source == None and dep_type == "nuget":
            source = "https://api.nuget.org/v3/index.json"
        if source == None:
            raise ValueError("Source was not provided")
        text = f'''
        {{
            "scope": "{scope}",
            "type": "{dep_type}",
            "name": "{name}",
            "version": "{version}",
            "source": "{source}",
            "flags": []        
        }}'''
        ext_dep_name = name.replace(" ", "_")
        file_name = f"{ext_dep_name}_ext_dep.json"
        output_dir = os.path.join(self.workspace, dir_path)
        os.makedirs(output_dir, exist_ok=True)
        output_path = os.path.join(output_dir, file_name)
        uefi_tree.write_to_file(output_path, text)
