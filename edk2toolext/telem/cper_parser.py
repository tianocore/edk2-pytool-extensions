# @file
# Command Line Interface for parsing CPERs
#
# Copyright (c) Microsoft Corporation
#
# SPDX-License-Identifier: BSD-2-Clause-Patent
##

import argparse
import logging
import os
from pathlib import Path
import struct
import Evtx.Evtx as evtx
from edk2toollib.windows.telem import cper_parsers as cper

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

    parser.add_argument('-f', '--Friendly', action='store_true', help='Specify if guids names be substituted with friendly names if found')
    parser.add_argument('-p', '--Print', action='store_true', help='If true, the parsed data blobs will be printed to stdout')
    parser.add_argument('-s', '--Source', default='', help='Specify a file of newline-separated raw blobs or an .evtx file to be parsed')
    parser.add_argument('-o', '--Output', default='', help='Specify the name of the produced file containing parsed data')

    args = parser.parse_args()
    # cper.main(args.Friendly, args.Source, args.Output, args.Print)

    Source = args.Source
    Friendly = args.Friendly
    Output = args.Output
    Print = args.Print
    
    cper.ValidateFriendlyNames()

    hex_list = []

    if Source != '':
        if Source.endswith(".txt"):
            if not os.path.isabs(Source):
                Source = os.path.join(str(Path(__file__).parents[3]), Source)
            try:
                with open(Source, "r") as f:
                    for line in f:
                        hex_list.append(line)
            except:
                print("Unable to open txt source file:")
                print(Source)
                return

        elif Source.endswith(".evtx"):
            if not os.path.isabs(Source):
                Source = os.path.join(str(Path(__file__).parents[3]), Source)
            try:
                with evtx.Evtx(Source) as log:
                    for rec in log.records():
                        start_of_cper = rec.data().index("CPER".encode(encoding='utf_8'))
                        x = struct.unpack("<I", rec.data()[start_of_cper + 20:start_of_cper + 20 + 4])
                        y = rec.data()[start_of_cper:start_of_cper + x[0]]
                        hex_list.append(y.hex())
            except:
                print("Unable to open evtx source file:")
                print(Source)
                return

        if Output != '':
            if not os.path.isabs(Output):
                Output = os.path.join(str(Path(__file__).parents[3]), Output)
            try:
                with open(Output, "w") as w:
                    for line in hex_list:
                        p = cper.CPER(line).PrettyPrint(Friendly)
                        w.write(p)
                        w.write("\n")
                    w.close()
            except:
                print("Unable to write to output file:")
                print(Output)
                return

        if Print:
            for line in hex_list:
                print(cper.CPER(line).PrettyPrint(Friendly))
            
        if not Print and Output == '':
            print("Must specify --Print or a file via --Output followed by a file name")
            return
    else:
        print("Must specify a source file via --Source followed by a file name which can be either .txt or .evtx")
