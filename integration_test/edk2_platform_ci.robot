*** Settings ***
Documentation     A test suite to test Platform CI on edk2 repo
#
# Copyright (c), Microsoft Corporation
# SPDX-License-Identifier: BSD-2-Clause-Patent

Library  Process
Library  OperatingSystem
Library  String

Resource  Shared_Keywords.robot

Suite Setup  One time setup  ${repo_url}  ${ws_dir}

# Suite Setup

*** Variables ***
${repo_url}           https://github.com/tianocore/edk2.git
${master_branch}      master
${ws_dir}             edk2
${ws_root}            ${TEST_OUTPUT}${/}${ws_dir}
${tool_chain}         VS2019


*** Keywords ***
One time setup
    [Arguments]  ${url}  ${folder}
    ## Dump pip versions
    ${result}=   Run Process    python  -m  pip   list  shell=True
    Log  ${result.stdout}

    ## Make output directory if doesn't already exist
    Create Directory  ${TEST_OUTPUT}

    ## Clone repo
    Run Keyword  Clone the git repo  ${url}  ${folder}

*** Test Cases ***
Run Edk2 Ovmf PlatformCI
    [Documentation]  This Test will run Platform CI on the OvmfPkg X64
    [Tags]           PlatformCI  OVMF  X64  VS2019  Windows  QEMU  Edk2
    ${arch}=             Set Variable    X64
    ${target}=           Set Variable    DEBUG
    ${package}=          Set Variable    OvmfPkg
    ${ci_file}=          Set Variable    ${package}${/}PlatformCI${/}PlatformBuild.py

    # make sure on master
    Reset git repo to main branch  ${ws_root}  ${master_branch}

    Stuart setup           ${ci_file}  ${arch}  ${target}  ${package}  ${tool_chain}  ${ws_root}
    Stuart update          ${ci_file}  ${arch}  ${target}  ${package}  ${tool_chain}  ${ws_root}
    Build BaseTools        ${tool_chain}  ${ws_root}
    Stuart platform build  ${ci_file}  ${arch}  ${target}  ${tool_chain}  ${ws_root}
    Stuart platform run    ${ci_file}  ${arch}  ${target}  ${tool_chain}  MAKE_STARTUP_NSH\=TRUE  ${ws_root}

Run Edk2 EmulatorPkg PlatformCI
    [Documentation]  This Test will run Platform CI on the EmulatorPkg X64
    [Tags]           PlatformCI  X64  VS2019  Windows  EmulatorPkg  Edk2
    ${arch}=             Set Variable    X64
    ${target}=           Set Variable    NOOPT
    ${package}=          Set Variable    EmulatorPkg
    ${ci_file}=          Set Variable    ${package}${/}PlatformCI${/}PlatformBuild.py

    # make sure on master
    Reset git repo to main branch  ${ws_root}  ${master_branch}

    Stuart setup           ${ci_file}  ${arch}  ${target}  ${package}  ${tool_chain}  ${ws_root}
    Stuart update          ${ci_file}  ${arch}  ${target}  ${package}  ${tool_chain}  ${ws_root}
    Build BaseTools        ${tool_chain}  ${ws_root}
    Stuart platform build  ${ci_file}  ${arch}  ${target}  ${tool_chain}  ${ws_root}
    Stuart platform run    ${ci_file}  ${arch}  ${target}  ${tool_chain}  MAKE_STARTUP_NSH\=TRUE  ${ws_root}
