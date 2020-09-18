##
# Quick script to check that python code in the package
# aligns with pep8 and file encoding.  I have not found
# a way to enforce that with tools like flake8
#
# There must be a better way.  :)
#
# Copyright (c) Microsoft Corporation
#
# SPDX-License-Identifier: BSD-2-Clause-Patent
##

import glob
import os
import sys
import logging
import re


def TestEncodingOk(apath, encodingValue):
    try:
        with open(apath, "rb") as f_obj:
            f_obj.read().decode(encodingValue)
    except Exception as exp:
        logging.critical("Encoding failure: file: {0} type: {1}".format(apath, encodingValue))
        logging.error("EXCEPTION: while processing {1} - {0}".format(exp, apath))
        return False
    return True


def TestFilenameLowercase(apath):
    if apath != apath.lower():
        logging.critical(f"Lowercase failure: file {apath} not lower case path")
        logging.error(f"\n\tLOWERCASE: {apath.lower()}\n\tINPUTPATH: {apath}")
        return False
    return True


def PackageAndModuleValidCharacters(apath):
    ''' check pep8 recommendations for package and module names'''

    match = re.match('^[a-z0-9_/.]+$', apath.replace("\\", "/"))
    if match is None:
        logging.critical(
            f"PackageAndModuleValidCharacters failure: package or module name {apath} has something invalid")
        return False
    return True


def TestNoSpaces(apath):
    if " " in apath:
        logging.critical(f"NoSpaces failure: file {apath} has spaces in path")
        return False
    return True


def TestRequiredLicense(apath):
    licenses = ["SPDX-License-Identifier: BSD-2-Clause-Patent", ]
    try:
        with open(apath, "rb") as f_obj:
            contents = f_obj.read().decode()
            found = False
            for lic in licenses:
                if lic in contents:
                    found = True
                    break
            if not found:
                logging.critical(f"License failure: file {apath} has incorrect, invalid, or unsupported license")
                return False
    except Exception as exp:
        logging.critical(f"License failure: Exception trying to read file: {apath}")
        logging.error("EXCEPTION: while processing {1} - {0}".format(exp, apath))
        return False
    return True


p = os.path.join(os.getcwd(), "edk2toolext")
py_files = glob.glob(os.path.join(p, "**", "*.py"), recursive=True)
error = 0
for a in py_files:
    aRelativePath = os.path.relpath(a, os.getcwd())
    if(not TestEncodingOk(a, "ascii")):
        error += 1
    if(not TestFilenameLowercase(aRelativePath)):
        error += 1
    if(not TestNoSpaces(aRelativePath)):
        error += 1
    if(not TestRequiredLicense(a)):
        error += 1
    if(not PackageAndModuleValidCharacters(aRelativePath)):  # use relative path so only test within package
        error += 1

logging.critical(f"Found {error} error(s) in {len(py_files)} file(s)")
sys.exit(error)
