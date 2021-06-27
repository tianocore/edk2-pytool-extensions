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
import yaml
import sys
import hashlib

from edk2toolext.environment.external_dependency import ExternalDependency

class LocalFileDependency(ExternalDependency):
    '''
    The sample of the external dependency description file for source.
    
    Tool1.yaml
    ---------------------------------------------
        [
            {
              "name": "XXX",
              "version": "1234",
              "OS": "win",
              "filelist": [
                   "win\\file1.bat",
                   "win\\file2.py"
               ],
               SHA-1: f31848b6dbaa736aff006bab36243a86c26ea1af
            },
            {
              "name": "XXX",
              "version": "1234",
              "OS": "linux",
              "filelist": [
                   "linux\\file1.sh",
                   "linux\\file2.py"
               ],
               SHA-1: 6b97ed211ecae3cc2378380471d40fd27246cbde
            }
        ]
    ---------------------------------------------
    
    The sample of the _ext_dep.yaml file for destination.
        {
          "scope": "Tool1",
          "type": "LocalFile",
          "name": "Tool1",
          "source": "<abs path>Tool1.yaml",
          "version": "1234",
          "flags": ["set_path"]
        }
    
    '''

    TypeString = "LocalFile"

    def __init__(self, descriptor):
        super().__init__(descriptor)
        self.source = os.path.normpath(descriptor['source'])
        self.req_ver = descriptor.get('version')
        self.source_filelist = []

        self.deps_hash =''
        self.dest_filelist = []

    def __str__(self):
        """ return a string representation of this """
        return f"LocalFileDependecy: {self.source}"
        
    def GetOs(self):
        if sys.platform == 'win32':
            return 'win'
        elif sys.platform == 'linux':
            return 'linux'
        else:
            return sys.platform

    def query(self):
        if os.path.exists(self.source):
            with open(self.source,"r") as fd:
                contents = yaml.load(fd,Loader = yaml.SafeLoader)
            for conf in contents:
                if conf.get('OS','') == self.GetOs() and conf.get('version','') == self.req_ver:
                    break
            else:
                conf = contents[0]
                
            self.source_filelist = conf.get('filelist', '')
            self.deps_hash = conf.get('SHA-1')
        
        toolroot = os.path.dirname(self.source)
        
        for i in range(len(self.source_filelist)):
            if os.path.isabs(self.source_filelist[i]):
                continue
            self.source_filelist[i] = os.path.join(toolroot,self.source_filelist[i])
 
        return self.source_filelist, self.deps_hash
    
    def checksum(self):
        sha1 = hashlib.sha1()
        for f in self.source_filelist:
            try:
                with open(f,"rb") as fd:
                    sha1.update(fd.read())
            except:
                logging.debug("Can't access file %s that is listed in % " % (f, self.source))
                return False
        
        if sha1.hexdigest() != self.deps_hash:
            logging.debug("The information in %s is invalid " %  self.source)
            return False

        return True
    
    def update_state_file(self):
        with open(self.state_file_path, 'w+') as file:
            yaml.dump({ 'filelist': self.dest_filelist,'SHA-1': self.deps_hash}, file)
    
    def fetch(self):
        try:
            self.query()
            if not self.checksum():
                return
            
            if not os.path.exists(self.contents_dir):
                os.makedirs(self.contents_dir)

            for f in self.source_filelist:
                shutil.copy2(f, self.contents_dir)
                self.dest_filelist.append(os.path.join(self.contents_dir, os.path.basename(f)))

            self.update_state_file()
            
            self.published_path = os.path.join(self.contents_dir)

        except Exception as e:
            logging.error(f"ran into an issue when resolving ext_dep {f} at {self.source}")
            raise e
        
    def verify(self):
        if not os.path.exists(self.state_file_path):
            return False
        
        _, s_deps_hash = self.query()

        try:
            sha1 = hashlib.sha1()
            with open(self.state_file_path, "r") as fd:
                state = yaml.load(fd, Loader=yaml.SafeLoader)
            
            # Check if hash value for dest_filelist and source_filelist are the same
            deps_hash = state.get('SHA-1','')
            if deps_hash != s_deps_hash:
                return False

            
            for f in state.get('filelist',[]):
                with open(f,"rb") as fd:
                    sha1.update(fd.read())

            # check if extdep files are changed
            if deps_hash != sha1.hexdigest():
                return False
        except:
            logging.debug("Can't access file %s that is listed in %s " % (f, self.state_file_path))
            return False
        
        return True
