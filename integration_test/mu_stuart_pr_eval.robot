*** Settings ***
Documentation     A test suite to test Stuart Pr Eval
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
${core_ci_file}       .pytool/CISettings.py

${ws_root}            ${TEST_OUTPUT}${/}${ws_dir}


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

    ## clean the repo of all dependencies including additional repos
    ## Project Mu test cases are most useful for multi-repository testing
    ## but for that to be useful the other repositories must not be
    ## populated in the file system
    #
    # clean all files quietly to avoid robot log overflow
    ${result}=  Run Process  git  clean  -qxfd  -f  cwd=${ws_root}
    Log Many  stdout: ${result.stdout}  stderr: ${result.stderr}
    Should Be Equal As Integers  ${result.rc}  0

*** Test Cases ***

Test Stuart PR using ProjectMu for Policy 1 special files in PrEvalSettingsManager
    [Tags]           PrEval  ProjectMu

    ${branch_name}=      Set Variable    PR_Rand_${{random.randint(0, 10000)}}
    ${file_to_modify}=   Set Variable    BaseTools${/}Source${/}C${/}GenFv${/}GenFv.c

    Reset git repo to main branch  ${ws_root}  ${master_branch}
    Make new branch  ${branch_name}  ${ws_root}

    Append To File  ${ws_root}${/}${file_to_modify}
    ...  Hello World!! Making a change for fun.

    Stage changed file  ${file_to_modify}  ${ws_root}
    Commit changes  "Changes"  ${ws_root}

    # Core CI test  package dependency # Policy 3
    ${pkgs}=  Stuart pr evaluation  ${core_ci_file}  MdePkg,MdeModulePkg,UefiCpuPkg  ${master_branch}  ${EMPTY}  ${ws_root}
    Confirm same contents  ${pkgs}  MdePkg,MdeModulePkg,UefiCpuPkg

    [Teardown]  Delete branch  ${branch_name}  ${master_branch}  ${ws_root}

Test Stuart PR using ProjectMu for Policy 2 in package change of private inf file
    [Tags]           PrEval  ProjectMu

    ${branch_name}=      Set Variable    PR_Rand_${{random.randint(0, 10000)}}
    ${file_to_modify}=   Set Variable    MdePkg${/}Library${/}BaseLib${/}BaseLib.inf

    Reset git repo to main branch  ${ws_root}  ${master_branch}
    Make new branch  ${branch_name}  ${ws_root}

    Append To File  ${ws_root}${/}${file_to_modify}
    ...  Hello World!! Making a change for fun.

    Stage changed file  ${file_to_modify}  ${ws_root}
    Commit changes  "Changes"  ${ws_root}

    # Core CI test same package  # policy 2
    ${pkgs}=  Stuart pr evaluation  ${core_ci_file}  MdePkg  ${master_branch}  ${EMPTY}  ${ws_root}
    Confirm same contents  ${pkgs}  MdePkg

    # Core CI test another package and make sure a it doesn't need to build
    ${pkgs}=  Stuart pr evaluation  ${core_ci_file}  MdeModulePkg  ${master_branch}  ${EMPTY}  ${ws_root}
    Should Be Empty    ${pkgs}

    [Teardown]  Delete branch  ${branch_name}  ${master_branch}  ${ws_root}


Test Stuart PR using ProjectMu for Policy 3 for package dependency on change of public header file
    [Tags]           PrEval  ProjectMu

    ${branch_name}=      Set Variable    PR_Rand_${{random.randint(0, 10000)}}
    ${file_to_modify}=   Set Variable    MdePkg${/}Include${/}Protocol${/}DevicePath.h

    Reset git repo to main branch  ${ws_root}  ${master_branch}
    Make new branch  ${branch_name}  ${ws_root}

    Append To File  ${ws_root}${/}${file_to_modify}
    ...  Hello World!! Making a change for fun.

    Stage changed file  ${file_to_modify}  ${ws_root}
    Commit changes  "Changes"  ${ws_root}

    # Core CI test  package dependency # Policy 3
    ${pkgs}=  Stuart pr evaluation  ${core_ci_file}  MdeModulePkg,UefiCpuPkg  ${master_branch}  ${EMPTY}  ${ws_root}
    Confirm same contents  ${pkgs}  MdeModulePkg,UefiCpuPkg

    [Teardown]  Delete branch  ${branch_name}  ${master_branch}  ${ws_root}

Test Stuart PR using ProjectMu for Policy 3 for package dependency on change of public header file not dependent
    [Tags]           PrEval  ProjectMu

    ${branch_name}=      Set Variable    PR_Rand_${{random.randint(0, 10000)}}
    ${file_to_modify}=   Set Variable    PcAtChipsetPkg${/}Include${/}Guid${/}PcAtChipsetTokenSpace.h

    Reset git repo to main branch  ${ws_root}  ${master_branch}
    Make new branch  ${branch_name}  ${ws_root}

    Append To File  ${ws_root}${/}${file_to_modify}
    ...  Hello World!! Making a change for fun.

    Stage changed file  ${file_to_modify}  ${ws_root}
    Commit changes  "Changes"  ${ws_root}

    # Core CI test  package dependency # Policy 3
    ${pkgs}=  Stuart pr evaluation  ${core_ci_file}  MdePkg,MdeModulePkg,UefiCpuPkg  ${master_branch}  ${EMPTY}  ${ws_root}
    Should Be Empty    ${pkgs}

    [Teardown]  Delete branch  ${branch_name}  ${master_branch}  ${ws_root}

Test Stuart PR using ProjectMu for Policy 3 for package dependency on change of package dec file
    [Tags]           PrEval  ProjectMu

    ${branch_name}=      Set Variable    PR_Rand_${{random.randint(0, 10000)}}
    ${file_to_modify}=   Set Variable    UefiCpuPkg${/}UefiCpuPkg.dec

    Reset git repo to main branch  ${ws_root}  ${master_branch}
    Make new branch  ${branch_name}  ${ws_root}

    Append To File  ${ws_root}${/}${file_to_modify}
    ...  Hello World!! Making a change for fun.

    Stage changed file  ${file_to_modify}  ${ws_root}
    Commit changes  "Changes"  ${ws_root}

    # Core CI test  package dependency # Policy 3
    ${pkgs}=  Stuart pr evaluation  ${core_ci_file}  MdePkg,MdeModulePkg,PcAtChipsetPkg  ${master_branch}  ${EMPTY}  ${ws_root}
    Confirm same contents  ${pkgs}  PcAtChipsetPkg

    [Teardown]  Delete branch  ${branch_name}  ${master_branch}  ${ws_root}

Test Stuart PR using ProjectMu for all policies when a PR contains a deleted file
    [Tags]           PrEval  Delete  ProjectMu

    ${branch_name}=      Set Variable    PR_Rand_${{random.randint(0, 10000)}}
    ${file_to_modify}=   Set Variable    MdeModulePkg${/}Application${/}HelloWorld${/}HelloWorld.c

    Reset git repo to main branch  ${ws_root}  ${master_branch}
    Make new branch  ${branch_name}  ${ws_root}

    Remove File  ${ws_root}${/}${file_to_modify}

    Stage changed file  ${file_to_modify}  ${ws_root}
    Commit changes  "Changes"  ${ws_root}

    ${pkgs}=  Stuart pr evaluation  ${core_ci_file}  MdePkg  ${master_branch}  ${EMPTY}  ${ws_root}
    Should Be Empty    ${pkgs}

    [Teardown]  Delete branch  ${branch_name}  ${master_branch}  ${ws_root}

Test Stuart PR using ProjectMu for all policies when a PR contains a deleted folder
    [Tags]           PrEval  Delete  ProjectMu

    ${branch_name}=      Set Variable    PR_Rand_${{random.randint(0, 10000)}}
    ${file_to_modify}=   Set Variable    MdeModulePkg${/}Application${/}HelloWorld

    Reset git repo to main branch  ${ws_root}  ${master_branch}
    Make new branch  ${branch_name}  ${ws_root}

    Remove Directory  ${ws_root}${/}${file_to_modify}  True

    Stage changed file  ${file_to_modify}  ${ws_root}
    Commit changes  "Changes"  ${ws_root}

    # Platform CI test DSC dependnency on implementation file # Policy 4
    ${pkgs}=  Stuart pr evaluation  ${core_ci_file}  SecurityPkg  ${master_branch}  ${EMPTY}  ${ws_root}
    Should Be Empty    ${pkgs}

    [Teardown]  Delete branch  ${branch_name}  ${master_branch}  ${ws_root}

Test Stuart PR using ProjectMu for all policies when a PR contains multiple levels of deleted folders
    [Tags]           PrEval  Delete  ProjectMu

    ${branch_name}=      Set Variable    PR_Rand_${{random.randint(0, 10000)}}
    ${file_to_modify}=   Set Variable    UefiCpuPkg${/}CpuDxe

    Reset git repo to main branch  ${ws_root}  ${master_branch}
    Make new branch  ${branch_name}  ${ws_root}

    Remove Directory  ${ws_root}${/}${file_to_modify}  True

    Stage changed file  ${file_to_modify}  ${ws_root}
    Commit changes  "Changes"  ${ws_root}

    # Platform CI test DSC dependnency on implementation file # Policy 4
    ${pkgs}=  Stuart pr evaluation  ${core_ci_file}  SecurityPkg  ${master_branch}  ${EMPTY}  ${ws_root}
    Should Be Empty    ${pkgs}

    [Teardown]  Delete branch  ${branch_name}  ${master_branch}  ${ws_root}

Test Stuart PR using ProjectMu for all policies when a PR contains file added
    [Tags]           PrEval  Add  ProjectMu

    ${branch_name}=       Set Variable    PR_Rand_${{random.randint(0, 10000)}}
    ${file_to_move}=      Set Variable    MdePkg${/}Library${/}BaseS3StallLib${/}S3StallLib.c
    ${location_to_move}=  Set Variable    MdePkg${/}Library${/}BaseLib

    Reset git repo to main branch  ${ws_root}  ${master_branch}
    Make new branch  ${branch_name}  ${ws_root}

    Move File  ${ws_root}${/}${file_to_move}  ${ws_root}${/}${location_to_move}

    Stage changed file  ${location_to_move}  ${ws_root}
    Commit changes  "Changes"  ${ws_root}

    # Platform CI test DSC dependnency on implementation file # Policy 4
    ${pkgs}=  Stuart pr evaluation  ${core_ci_file}  MdeModulePkg  ${master_branch}  ${EMPTY}  ${ws_root}
    Should Be Empty    ${pkgs}

    [Teardown]  Delete branch  ${branch_name}  ${master_branch}  ${ws_root}

Test Stuart PR for all policies when a PR contains directory added
    [Tags]           PrEval  Add

    ${branch_name}=       Set Variable    PR_Rand_${{random.randint(0, 10000)}}
    ${file_to_move}=      Set Variable    MdePkg${/}Library${/}BaseS3StallLib
    ${location_to_move}=  Set Variable    MdeModulePkg${/}Library

    Reset git repo to main branch  ${ws_root}  ${master_branch}
    Make new branch  ${branch_name}  ${ws_root}

    Move Directory  ${ws_root}${/}${file_to_move}  ${ws_root}${/}${location_to_move}

    Stage changed file  ${location_to_move}  ${ws_root}
    Commit changes  "Changes"  ${ws_root}

    # Platform CI test DSC dependnency on implementation file # Policy 4
    ${pkgs}=  Stuart pr evaluation  ${core_ci_file}  UefiCpuPkg  ${master_branch}  ${EMPTY}  ${ws_root}
    Should Be Empty    ${pkgs}

    [Teardown]  Delete branch  ${branch_name}  ${master_branch}  ${ws_root}

Test Stuart PR for changing a file at the root of repo
    [Tags]           PrEval

    ${branch_name}=      Set Variable    PR_Rand_${{random.randint(0, 10000)}}
    ${file_to_modify}=   Set Variable    edksetup.bat

    Reset git repo to main branch  ${ws_root}  ${master_branch}
    Make new branch  ${branch_name}  ${ws_root}

    Append To File  ${ws_root}${/}${file_to_modify}
    ...  Hello World!! Making a change for fun.

    Stage changed file  ${file_to_modify}  ${ws_root}
    Commit changes  "Changes"  ${ws_root}

    # Platform CI test DSC dependnency on implementation file # Policy 4
    ${pkgs}=  Stuart pr evaluation  ${core_ci_file}  MdePkg  ${master_branch}  ${EMPTY}  ${ws_root}
    Should Be Empty    ${pkgs}

    [Teardown]  Delete branch  ${branch_name}  ${master_branch}  ${ws_root}
