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
${master_branch}      release/202002
${ws_dir}             mu_basecore
${ci_file}            .pytool/CISettings.py
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

Run ProjectMu MdePkg CoreCI Debug
    [Documentation]  This Test will run X64 DEBUG build of Core CI on the MdePkg
    [Tags]           CoreCI  Windows  VS2019  Compile  ProjectMu

    ${archs}=            Set Variable    X64
    ${targets}=          Set Variable    DEBUG
    ${packages}=         Set Variable    MdePkg

    # make sure on master
    Reset git repo to main branch  ${ws_root}  ${master_branch}

    Stuart setup           ${ci_file}  ${archs}  ${targets}  ${packages}  ${tool_chain}  ${ws_root}
    Stuart ci setup        ${ci_file}  ${archs}  ${targets}  ${packages}  ${tool_chain}  ${ws_root}
    Stuart update          ${ci_file}  ${archs}  ${targets}  ${packages}  ${tool_chain}  ${ws_root}
    Build BaseTools        ${tool_chain}  ${ws_root}
    Stuart CI build        ${ci_file}  ${archs}  ${targets}  ${packages}  ${tool_chain}  ${ws_root}

Run ProjectMu SecurityPkg CoreCI Release
    [Documentation]  This Test will run IA32 RELEASE build of Core CI on the SecurityPkg
    [Tags]           CoreCI  Windows  VS2019  Compile  ProjectMu

    ${archs}=            Set Variable    IA32
    ${targets}=          Set Variable    RELEASE
    ${packages}=         Set Variable    SecurityPkg

    # make sure on master
    Reset git repo to main branch  ${ws_root}  ${master_branch}

    Stuart setup           ${ci_file}  ${archs}  ${targets}  ${packages}  ${tool_chain}  ${ws_root}
    Stuart ci setup        ${ci_file}  ${archs}  ${targets}  ${packages}  ${tool_chain}  ${ws_root}
    Stuart update          ${ci_file}  ${archs}  ${targets}  ${packages}  ${tool_chain}  ${ws_root}
    Build BaseTools        ${tool_chain}  ${ws_root}
    Stuart CI build        ${ci_file}  ${archs}  ${targets}  ${packages}  ${tool_chain}  ${ws_root}

Run ProjectMu UefiCpuPkg CoreCI for No-Target
    [Documentation]  This Test will run NO-TARGET Core CI test on the UefiCpuPkg
    [Tags]           CoreCI  Windows  VS2019  NO-TARGET  ProjectMu

    ${archs}=            Set Variable    X64,IA32,AARCH64,ARM
    ${targets}=          Set Variable    NO-TARGET
    ${packages}=         Set Variable    UefiCpuPkg

    # make sure on master
    Reset git repo to main branch  ${ws_root}  ${master_branch}

    Stuart setup           ${ci_file}  ${archs}  ${targets}  ${packages}  ${tool_chain}  ${ws_root}
    Stuart ci setup        ${ci_file}  ${archs}  ${targets}  ${packages}  ${tool_chain}  ${ws_root}
    Stuart update          ${ci_file}  ${archs}  ${targets}  ${packages}  ${tool_chain}  ${ws_root}
    Build BaseTools        ${tool_chain}  ${ws_root}
    Stuart CI build        ${ci_file}  ${archs}  ${targets}  ${packages}  ${tool_chain}  ${ws_root}

Run ProjectMu MdeModulePkg CoreCI for NOOPT and HostTest
    [Documentation]  This Test will run NOOPT Core CI which includes Host-Tests on the MdeModulePkg
    [Tags]           CoreCI  Windows  VS2019  NOOPT  HOST-TEST  ProjectMu

    ${archs}=            Set Variable    X64
    ${targets}=          Set Variable    NOOPT
    ${packages}=         Set Variable    MdeModulePkg

    # make sure on master
    Reset git repo to main branch  ${ws_root}  ${master_branch}

    Stuart setup           ${ci_file}  ${archs}  ${targets}  ${packages}  ${tool_chain}  ${ws_root}
    Stuart ci setup        ${ci_file}  ${archs}  ${targets}  ${packages}  ${tool_chain}  ${ws_root}
    Stuart update          ${ci_file}  ${archs}  ${targets}  ${packages}  ${tool_chain}  ${ws_root}
    Build BaseTools        ${tool_chain}  ${ws_root}
    Stuart CI build        ${ci_file}  ${archs}  ${targets}  ${packages}  ${tool_chain}  ${ws_root}

