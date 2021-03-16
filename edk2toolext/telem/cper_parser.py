# @file
# # TODO: Fill in
#
# Copyright (c) Microsoft Corporation
#
# SPDX-License-Identifier: BSD-2-Clause-Patent
##

import argparse
import logging
from edk2toollib.windows.telem import cper_parser_tool as cper

cperlist = [] 

def CreateCPERFromFile(file_name: str) -> None:
    "Basic printing of CPERs seperated by newlines"
    try:
        with open(file_name, 'rb') as f:
            for line in f:
                cper.CPER(line).PrettyPrint()

    except FileNotFoundError:
        logging.error('File not found: "{0}"'.format(file_name))

def main():
    parser = argparse.ArgumentParser(description='CPER Parser')

    parser.add_argument('-f', '--Friendly', action='store_true',help ='Specify if guids names be substituted with friendly names if found')
    parser.add_argument('-p', '--Print', action='store_true', help='If true, the parsed data blobs will be printed to stdout')
    parser.add_argument('-s', '--Source', default='', help='Specify a file of newline-separated raw blobs or an .evtx file to be parsed')
    parser.add_argument('-o', '--Output', default='', help='Specify the name of the produced file containing parsed data')

    args = parser.parse_args()

    cper.main(args.Friendly, args.Source, args.Output, args.Print)
