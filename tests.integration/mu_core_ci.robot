*** Settings ***
Documentation     A test suite to test Core CI on edk2 repo
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
${repo_url}           https://github.com/microsoft/mu_basecore
${default_branch}     not_yet_set
${ws_dir}             mu_basecore
${ci_file}            .pytool/CISettings.py
${ws_root}            ${TEST_OUTPUT}${/}${ws_dir}
${tool_chain}         ${TOOL_CHAIN_TAG}


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

    ## Figure out default branch
    ${branch}=  Get default branch from remote  ${ws_root}
    Set Suite Variable  ${default_branch}  ${branch}

*** Test Cases ***

Run ProjectMu MdePkg CoreCI Debug
    [Documentation]  This Test will run X64 DEBUG build of Core CI on the MdePkg
    [Tags]           CoreCI  Windows  VS2022  Compile  ProjectMu

    ${archs}=            Set Variable    X64
    ${targets}=          Set Variable    DEBUG
    ${packages}=         Set Variable    MdePkg

    # make sure on default branch
    Reset git repo to default branch  ${ws_root}  ${default_branch}

    Stuart setup           ${ci_file}  ${archs}  ${targets}  ${packages}  ${tool_chain}  ${ws_root}
    Stuart update          ${ci_file}  ${archs}  ${targets}  ${packages}  ${tool_chain}  ${ws_root}
    Build BaseTools        ${tool_chain}  ${ws_root}
    Stuart CI build        ${ci_file}  ${archs}  ${targets}  ${packages}  ${tool_chain}  ${ws_root}

Run ProjectMu MdeModulePkg CoreCI Release
    [Documentation]  This Test will run IA32 RELEASE build of Core CI on the MdeModulePkg
    [Tags]           CoreCI  Windows  VS2022  Compile  ProjectMu

    ${archs}=            Set Variable    IA32
    ${targets}=          Set Variable    RELEASE
    ${packages}=         Set Variable    MdeModulePkg

    # make sure on default branch
    Reset git repo to default branch  ${ws_root}  ${default_branch}

    Stuart setup           ${ci_file}  ${archs}  ${targets}  ${packages}  ${tool_chain}  ${ws_root}
    Stuart update          ${ci_file}  ${archs}  ${targets}  ${packages}  ${tool_chain}  ${ws_root}
    Build BaseTools        ${tool_chain}  ${ws_root}
    Stuart CI build        ${ci_file}  ${archs}  ${targets}  ${packages}  ${tool_chain}  ${ws_root}

Run ProjectMu UefiCpuPkg CoreCI for No-Target
    [Documentation]  This Test will run NO-TARGET Core CI test on the UefiCpuPkg
    [Tags]           CoreCI  Windows  VS2022  NO-TARGET  ProjectMu

    ${archs}=            Set Variable    X64,IA32,AARCH64,ARM
    ${targets}=          Set Variable    NO-TARGET
    ${packages}=         Set Variable    UefiCpuPkg

    # make sure on default branch
    Reset git repo to default branch  ${ws_root}  ${default_branch}

    Stuart setup           ${ci_file}  ${archs}  ${targets}  ${packages}  ${tool_chain}  ${ws_root}
    Stuart update          ${ci_file}  ${archs}  ${targets}  ${packages}  ${tool_chain}  ${ws_root}
    Build BaseTools        ${tool_chain}  ${ws_root}
    Stuart CI build        ${ci_file}  ${archs}  ${targets}  ${packages}  ${tool_chain}  ${ws_root}

Run ProjectMu MdeModulePkg CoreCI for NOOPT and HostTest
    [Documentation]  This Test will run NOOPT Core CI which includes Host-Tests on the MdeModulePkg
    [Tags]           CoreCI  Windows  VS2022  NOOPT  HOST-TEST  ProjectMu

    ${archs}=            Set Variable    X64
    ${targets}=          Set Variable    NOOPT
    ${packages}=         Set Variable    MdeModulePkg

    # make sure on default branch
    Reset git repo to default branch  ${ws_root}  ${default_branch}

    Stuart setup           ${ci_file}  ${archs}  ${targets}  ${packages}  ${tool_chain}  ${ws_root}
    Stuart update          ${ci_file}  ${archs}  ${targets}  ${packages}  ${tool_chain}  ${ws_root}
    Build BaseTools        ${tool_chain}  ${ws_root}
    Stuart CI build        ${ci_file}  ${archs}  ${targets}  ${packages}  ${tool_chain}  ${ws_root}
