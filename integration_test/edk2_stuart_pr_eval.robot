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
${repo_url}           https://github.com/tianocore/edk2.git
${master_branch}      master
${ws_dir}             edk2
${core_ci_file}       .pytool/CISettings.py
${platform_ci_file}   OvmfPkg${/}PlatformCI${/}PlatformBuild.py

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

*** Test Cases ***

Test Stuart PR for Policy 1 special files in PrEvalSettingsManager
    [Tags]           PrEval  Edk2

    ${branch_name}=      Set Variable    PR_Rand_${{random.randint(0, 10000)}}
    ${file_to_modify}=   Set Variable    BaseTools${/}Source${/}C${/}GenFv${/}GenFv.c

    Reset git repo to main branch  ${ws_root}  ${master_branch}
    Make new branch  ${branch_name}  ${ws_root}

    Append To File  ${ws_root}${/}${file_to_modify}
    ...  Hello World!! Making a change for fun.

    Stage changed file  ${file_to_modify}  ${ws_root}
    Commit changes  "Changes"  ${ws_root}

    # Core CI test  package dependency # Policy 3
    ${pkgs}=  Stuart pr evaluation  ${core_ci_file}  MdePkg,MdeModulePkg,ArmVirtPkg  ${master_branch}  ${EMPTY}  ${ws_root}
    Confirm same contents  ${pkgs}  MdePkg,MdeModulePkg,ArmVirtPkg

    [Teardown]  Delete branch  ${branch_name}  ${master_branch}  ${ws_root}

Test Stuart PR for Policy 2 in package change of private inf file
    [Tags]           PrEval  Edk2

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


Test Stuart PR for Policy 3 for package dependency on change of public header file
    [Tags]           PrEval  Edk2

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

Test Stuart PR for Policy 3 for package dependency on change of public header file not dependent
    [Tags]           PrEval  Edk2

    ${branch_name}=      Set Variable    PR_Rand_${{random.randint(0, 10000)}}
    ${file_to_modify}=   Set Variable    CryptoPkg${/}Include${/}Library${/}TlsLib.h

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

Test Stuart PR for Policy 3 for package dependency on change of package dec file
    [Tags]           PrEval  Edk2

    ${branch_name}=      Set Variable    PR_Rand_${{random.randint(0, 10000)}}
    ${file_to_modify}=   Set Variable    SecurityPkg${/}SecurityPkg.dec

    Reset git repo to main branch  ${ws_root}  ${master_branch}
    Make new branch  ${branch_name}  ${ws_root}

    Append To File  ${ws_root}${/}${file_to_modify}
    ...  Hello World!! Making a change for fun.

    Stage changed file  ${file_to_modify}  ${ws_root}
    Commit changes  "Changes"  ${ws_root}

    # Core CI test  package dependency # Policy 3
    ${pkgs}=  Stuart pr evaluation  ${core_ci_file}  MdePkg,MdeModulePkg,ArmVirtPkg  ${master_branch}  ${EMPTY}  ${ws_root}
    Confirm same contents  ${pkgs}  ArmVirtPkg

    [Teardown]  Delete branch  ${branch_name}  ${master_branch}  ${ws_root}

Test Stuart PR for Policy 4 module c file changed that platform dsc depends on
    [Tags]           PrEval  Edk2

    ${branch_name}=      Set Variable    PR_Rand_${{random.randint(0, 10000)}}
    ${file_to_modify}=   Set Variable    MdeModulePkg${/}Core${/}Dxe${/}DxeMain.h

    Reset git repo to main branch  ${ws_root}  ${master_branch}
    Make new branch  ${branch_name}  ${ws_root}

    Append To File  ${ws_root}${/}${file_to_modify}
    ...  Hello World!! Making a change for fun.

    Stage changed file  ${file_to_modify}  ${ws_root}
    Commit changes  "Changes"  ${ws_root}

    # Platform CI test DSC dependnency on implementation file # Policy 4
    ${pkgs}=  Stuart pr evaluation  ${platform_ci_file}  OvmfPkg  ${master_branch}  ${EMPTY}  ${ws_root}
    Confirm same contents  ${pkgs}  OvmfPkg

    [Teardown]  Delete branch  ${branch_name}  ${master_branch}  ${ws_root}

Test Stuart PR for Policy 4 module c file changed that platform dsc does not depend on
    [Tags]           PrEval  Edk2

    ${branch_name}=      Set Variable    PR_Rand_${{random.randint(0, 10000)}}
    ${file_to_modify}=   Set Variable    MdeModulePkg${/}Application${/}HelloWorld${/}HelloWorld.c

    Reset git repo to main branch  ${ws_root}  ${master_branch}
    Make new branch  ${branch_name}  ${ws_root}

    Append To File  ${ws_root}${/}${file_to_modify}
    ...  Hello World!! Making a change for fun.

    Stage changed file  ${file_to_modify}  ${ws_root}
    Commit changes  "Changes"  ${ws_root}

    # Platform CI test DSC dependnency on implementation file # Policy 4
    ${pkgs}=  Stuart pr evaluation  ${platform_ci_file}  OvmfPkg  ${master_branch}  ${EMPTY}  ${ws_root}
    Should Be Empty    ${pkgs}

    [Teardown]  Delete branch  ${branch_name}  ${master_branch}  ${ws_root}

Test Stuart PR for all policies when a PR contains a deleted file
    [Tags]           PrEval  Delete  Edk2

    ${branch_name}=      Set Variable    PR_Rand_${{random.randint(0, 10000)}}
    ${file_to_modify}=   Set Variable    MdeModulePkg${/}Application${/}HelloWorld${/}HelloWorld.c

    Reset git repo to main branch  ${ws_root}  ${master_branch}
    Make new branch  ${branch_name}  ${ws_root}

    Remove File  ${ws_root}${/}${file_to_modify}

    Stage changed file  ${file_to_modify}  ${ws_root}
    Commit changes  "Changes"  ${ws_root}

    # Platform CI test DSC dependnency on implementation file # Policy 4
    ${pkgs}=  Stuart pr evaluation  ${platform_ci_file}  OvmfPkg  ${master_branch}  ${EMPTY}  ${ws_root}
    Should Be Empty    ${pkgs}

    [Teardown]  Delete branch  ${branch_name}  ${master_branch}  ${ws_root}

Test Stuart PR for all policies when a PR contains a deleted folder
    [Tags]           PrEval  Delete  Edk2

    ${branch_name}=      Set Variable    PR_Rand_${{random.randint(0, 10000)}}
    ${file_to_modify}=   Set Variable    MdeModulePkg${/}Application${/}HelloWorld

    Reset git repo to main branch  ${ws_root}  ${master_branch}
    Make new branch  ${branch_name}  ${ws_root}

    Remove Directory  ${ws_root}${/}${file_to_modify}  True

    Stage changed file  ${file_to_modify}  ${ws_root}
    Commit changes  "Changes"  ${ws_root}

    # Platform CI test DSC dependnency on implementation file # Policy 4
    ${pkgs}=  Stuart pr evaluation  ${platform_ci_file}  OvmfPkg  ${master_branch}  ${EMPTY}  ${ws_root}
    Should Be Empty    ${pkgs}

    [Teardown]  Delete branch  ${branch_name}  ${master_branch}  ${ws_root}

Test Stuart PR for all policies when a PR contains multiple levels of deleted folders
    [Tags]           PrEval  Delete  Edk2

    ${branch_name}=      Set Variable    PR_Rand_${{random.randint(0, 10000)}}
    ${file_to_modify}=   Set Variable    UefiCpuPkg${/}CpuDxe

    Reset git repo to main branch  ${ws_root}  ${master_branch}
    Make new branch  ${branch_name}  ${ws_root}

    Remove Directory  ${ws_root}${/}${file_to_modify}  True

    Stage changed file  ${file_to_modify}  ${ws_root}
    Commit changes  "Changes"  ${ws_root}

    # Platform CI test DSC dependnency on implementation file # Policy 4
    ${pkgs}=  Stuart pr evaluation  ${platform_ci_file}  OvmfPkg  ${master_branch}  ${EMPTY}  ${ws_root}
    Confirm same contents  ${pkgs}  OvmfPkg

    [Teardown]  Delete branch  ${branch_name}  ${master_branch}  ${ws_root}

Test Stuart PR for all policies when a PR contains file added
    [Tags]           PrEval  Add  Edk2

    ${branch_name}=       Set Variable    PR_Rand_${{random.randint(0, 10000)}}
    ${file_to_move}=      Set Variable    MdePkg${/}Library${/}BaseS3StallLib${/}S3StallLib.c
    ${location_to_move}=  Set Variable    MdePkg${/}Library${/}BaseLib

    Reset git repo to main branch  ${ws_root}  ${master_branch}
    Make new branch  ${branch_name}  ${ws_root}

    Move File  ${ws_root}${/}${file_to_move}  ${ws_root}${/}${location_to_move}

    Stage changed file  ${location_to_move}  ${ws_root}
    Commit changes  "Changes"  ${ws_root}

    # Platform CI test DSC dependnency on implementation file # Policy 4
    ${pkgs}=  Stuart pr evaluation  ${platform_ci_file}  OvmfPkg  ${master_branch}  ${EMPTY}  ${ws_root}
    Confirm same contents  ${pkgs}  OvmfPkg

    [Teardown]  Delete branch  ${branch_name}  ${master_branch}  ${ws_root}

Test Stuart PR for all policies when a PR contains directory added
    [Tags]           PrEval  Add  Edk2

    ${branch_name}=       Set Variable    PR_Rand_${{random.randint(0, 10000)}}
    ${file_to_move}=      Set Variable    MdePkg${/}Library${/}BaseS3StallLib
    ${location_to_move}=  Set Variable    MdeModulePkg${/}Library

    Reset git repo to main branch  ${ws_root}  ${master_branch}
    Make new branch  ${branch_name}  ${ws_root}

    Move Directory  ${ws_root}${/}${file_to_move}  ${ws_root}${/}${location_to_move}

    Stage changed file  ${location_to_move}  ${ws_root}
    Commit changes  "Changes"  ${ws_root}

    # Platform CI test DSC dependnency on implementation file # Policy 4
    ${pkgs}=  Stuart pr evaluation  ${platform_ci_file}  OvmfPkg  ${master_branch}  ${EMPTY}  ${ws_root}
    Should Be Empty    ${pkgs}

    [Teardown]  Delete branch  ${branch_name}  ${master_branch}  ${ws_root}

Test Stuart PR for changing a file at the root of repo
    [Tags]           PrEval  Edk2

    ${branch_name}=      Set Variable    PR_Rand_${{random.randint(0, 10000)}}
    ${file_to_modify}=   Set Variable    edksetup.bat

    Reset git repo to main branch  ${ws_root}  ${master_branch}
    Make new branch  ${branch_name}  ${ws_root}

    Append To File  ${ws_root}${/}${file_to_modify}
    ...  Hello World!! Making a change for fun.

    Stage changed file  ${file_to_modify}  ${ws_root}
    Commit changes  "Changes"  ${ws_root}

    # Platform CI test DSC dependnency on implementation file # Policy 4
    ${pkgs}=  Stuart pr evaluation  ${platform_ci_file}  OvmfPkg  ${master_branch}  ${EMPTY}  ${ws_root}
    Should Be Empty    ${pkgs}

    [Teardown]  Delete branch  ${branch_name}  ${master_branch}  ${ws_root}
