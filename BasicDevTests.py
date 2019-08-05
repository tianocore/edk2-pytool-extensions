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


def TestEncodingOk(apath, encodingValue):
    try:
        with open(apath, "rb") as fobj:
            fobj.read().decode(encodingValue)
    except Exception as exp:
        logging.critical("Encoding failure: file: {0} type: {1}".format(apath, encodingValue))
        logging.error("EXCEPTION: while processing {1} - {0}".format(exp, apath))
        return False
    return True


def TestLineEndingsOk(apath, Windows: bool):
    WIN_EOL = b'\r\n'
    UNIX_EOL = b'\n'

    with open(apath, "rb") as fobj:
        content_uni = fobj.read()

    if(not Windows):
        if(WIN_EOL in content_uni):
            logging.critical("Windows EOL in use file: {0}".format(apath))
            return False
        return True

    else:
        # windows
        # since UNIX EOL is substring of WIN EOL replace WIN with something
        # else and then look for UNIX
        content_no_nl = content_uni.replace(WIN_EOL, b"  ")
        if UNIX_EOL in content_no_nl:
            logging.critical("UNIX EOL in use file: {0}".format(apath))
            return False
        return True


def TestFilenameLowercase(apath):
    if apath != apath.lower():
        logging.critical(f"Lowercase failure: file {apath} not lower case path")
        logging.error(f"\n\tLOWERCASE: {apath.lower()}\n\tINPUTPATH: {apath}")
        return False
    return True


def TestNoSpaces(apath):
    if " " in apath:
        logging.critical(f"NoSpaces failure: file {apath} has spaces in path")
        return False
    return True


def TestRequiredLicense(apath):
    lic = ["SPDX-License-Identifier: BSD-2-Clause-Patent"]
    try:
        with open(apath, "rb") as fobj:
            contents = fobj.read().decode()
            found = False
            for l in lic:
                if l in contents:
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
pyfiles = glob.glob(os.path.join(p, "**", "*.py"), recursive=True)
error = 0
for a in pyfiles:
    aRelativePath = os.path.relpath(a, os.getcwd())
    if(not TestEncodingOk(a, "ascii")):
        error += 1
    if(not TestFilenameLowercase(aRelativePath)):
        error += 1
    if(not TestNoSpaces(aRelativePath)):
        error += 1
    if(not TestRequiredLicense(a)):
        error += 1

    # Don't check EOL.  Use .gitattributes
    # if(not TestLineEndingsOk(a, True)):
    #    error += 1

logging.critical(f"Found {error} error(s) in {len(pyfiles)} file(s)")
sys.exit(error)
