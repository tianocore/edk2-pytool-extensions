*** Settings ***
Documentation     A shared set of common keywords for stuart operations and git operations
#
# Copyright (c), Microsoft Corporation
# SPDX-License-Identifier: BSD-2-Clause-Patent

Library  Process
Library  OperatingSystem

# Suite Setup

*** Variables ***

#Test output location
${TEST_OUTPUT}          ${TEST_OUTPUT_BASE}

*** Keywords ***

### list comparison helper ###
Confirm same contents
    [Arguments]  ${actual}  ${expected}
    @{epkgs}=  Split String  ${expected}  ,
    @{apkgs}=  Split String  ${actual}  ,

    FOR  ${a}  IN  @{apkgs}
      Should Contain  ${expected}  ${a}
    END

    FOR  ${b}  IN  @{epkgs}
      Should Contain  ${actual}  ${b}
    END

### Git operations ###
Clone the git repo
    [Arguments]    ${git_url}   ${ws_name}

    Log To console    cloning ${git_url} to ${TEST_OUTPUT}
    ${result}=  Run Process       git.exe   clone   ${git_url}   ${ws_name}
    ...  cwd=${TEST_OUTPUT}  stdout=stdout.txt  stderr=stderr.txt
    Log Many  stdout: ${result.stdout}  stderr: ${result.stderr}

    ${result}=  Run Process  git  fetch  --all  --prune
    ...  cwd=${TEST_OUTPUT}${/}${ws_name}  stdout=stdout.txt  stderr=stderr.txt
    Log Many  stdout: ${result.stdout}  stderr: ${result.stderr}
    Should Be Equal As Integers  ${result.rc}  0

Reset git repo to main branch
    [Arguments]     ${ws}  ${main_branch_name}

    # checkout remote tag for origin/master
    ${result}=  Run Process  git  checkout  origin/${main_branch_name}
    ...  cwd=${ws}  stdout=stdout.txt  stderr=stderr.txt
    Log Many	stdout: ${result.stdout}  stderr: ${result.stderr}
    Should Be Equal As Integers  ${result.rc}  0

    # clean non ignored files quietly to avoid log overflow
    ${result}=  Run Process  git  clean  -qfd  cwd=${ws}
    Log Many  stdout: ${result.stdout}  stderr: ${result.stderr}
    Should Be Equal As Integers  ${result.rc}  0

    # reset to restore files
    ${result}=  Run Process  git  reset  --hard
    ...  cwd=${ws}  stdout=stdout.txt  stderr=stderr.txt
    Log Many  stdout: ${result.stdout}  stderr: ${result.stderr}
    Should Be Equal As Integers  ${result.rc}  0

Make new branch
    [Arguments]    ${name}  ${ws}
    ${result}=   Run Process    git  checkout  -b  ${name}
    ...  cwd=${ws}  shell=True
    Log Many	stdout: ${result.stdout}  stderr: ${result.stderr}
    Should Be Equal As Integers  ${result.rc}  0

Delete branch
    [Arguments]    ${name}  ${to_branch}  ${ws}
    Run Keyword  Switch branch  ${to_branch}  ${ws}
    ${result}=   Run Process    git  branch  -D  ${name}
    ...  cwd=${ws}  shell=True
    Log Many	stdout: ${result.stdout}  stderr: ${result.stderr}
    Should Be Equal As Integers  ${result.rc}  0

Switch branch
    [Arguments]    ${name}  ${ws}
    ${result}=   Run Process    git  checkout  ${name}
    ...  cwd=${ws}  shell=True
    Log Many	stdout: ${result.stdout}  stderr: ${result.stderr}
    Should Be Equal As Integers  ${result.rc}  0

Stage changed file
    [Arguments]    ${file_path}  ${ws}
    ${result}=   Run Process    git  add  ${file_path}
    ...  cwd=${ws}  shell=True
    Log Many	stdout: ${result.stdout}  stderr: ${result.stderr}
    Should Be Equal As Integers  ${result.rc}  0

Commit changes
    [Arguments]    ${msg}  ${ws}
    ${result}=   Run Process    git  commit  -m  ${msg}
    ...  cwd=${ws}  shell=True
    Log Many	stdout: ${result.stdout}  stderr: ${result.stderr}
    Should Be Equal As Integers  ${result.rc}  0

### Stuart operations ###
Stuart setup
    [Arguments]  ${setting_file}  ${arch}  ${target}  ${packages}  ${tool_chain}  ${ws}
    Log to console  Stuart Setup
    ${result}=   Run Process    stuart_setup
    ...  -c  ${setting_file}  -a  ${arch}  TOOL_CHAIN_TAG\=${tool_chain}  -t  ${target}  -p  ${packages}  TARGET\=${target}
    ...  cwd=${ws}  stdout=stdout.txt  stderr=stderr.txt
    Log Many	stdout: ${result.stdout}  stderr: ${result.stderr}
    Should Be Equal As Integers  ${result.rc}  0

Stuart ci setup
    [Arguments]  ${setting_file}  ${arch}  ${target}  ${packages}  ${tool_chain}  ${ws}
    Log to console  Stuart CI Setup
    ${result}=   Run Process    stuart_ci_setup
    ...  -c  ${setting_file}  -a  ${arch}  TOOL_CHAIN_TAG\=${tool_chain}  -t  ${target}  -p  ${packages}  TARGET\=${target}
    ...  cwd=${ws}  stdout=stdout.txt  stderr=stderr.txt
    Log Many	stdout: ${result.stdout}  stderr: ${result.stderr}
    Should Be Equal As Integers  ${result.rc}  0

Stuart update
    [Arguments]  ${setting_file}  ${arch}  ${target}  ${packages}  ${tool_chain}  ${ws}
    Log to console  Stuart Update
    ${result}=   Run Process    stuart_update
    ...  -c  ${setting_file}  -a  ${arch}  TOOL_CHAIN_TAG\=${tool_chain}  -t  ${target}  -p  ${packages}  TARGET\=${target}
    ...  cwd=${ws}  stdout=stdout.txt  stderr=stderr.txt
    Log Many	stdout: ${result.stdout}  stderr: ${result.stderr}
    Should Be Equal As Integers  ${result.rc}  0

Stuart platform build
    [Arguments]  ${setting_file}  ${arch}  ${target}  ${tool_chain}  ${ws}
    Log to console  Stuart Build
    ${result}=   Run Process    stuart_build
    ...  -c  ${setting_file}  -a  ${arch}  TOOL_CHAIN_TAG\=${tool_chain}  TARGET\=${target}
    ...  cwd=${ws}  stdout=stdout.txt  stderr=stderr.txt
    Log Many	stdout: ${result.stdout}  stderr: ${result.stderr}
    Should Be Equal As Integers  ${result.rc}  0

Stuart platform run
    [Arguments]  ${setting_file}  ${arch}  ${target}  ${tool_chain}  ${addtional_flags}  ${ws}
    Log to console  Stuart Build Run
    ${result}=   Run Process    stuart_build
    ...  -c  ${setting_file}  -a  ${arch}  TOOL_CHAIN_TAG\=${tool_chain}  TARGET\=${target}  --FlashOnly  ${addtional_flags}
    ...  cwd=${ws}  stdout=stdout.txt  stderr=stderr.txt
    Log Many	stdout: ${result.stdout}  stderr: ${result.stderr}
    Should Be Equal As Integers  ${result.rc}  0

Stuart CI build
    [Arguments]  ${setting_file}  ${archs}  ${targets}  ${packages}  ${tool_chain}  ${ws}
    Log to console  Stuart CI Build
    ${result}=   Run Process    stuart_ci_build
    ...  -c  ${setting_file}  -a  ${archs}  -t  ${targets}  -p  ${packages}  TOOL_CHAIN_TAG\=${tool_chain}
    ...  cwd=${ws}  stdout=stdout.txt  stderr=stderr.txt
    Log Many	stdout: ${result.stdout}  stderr: ${result.stderr}
    Should Be Equal As Integers  ${result.rc}  0

Stuart pr evaluation
    [Documentation]  Run Pr Eval
    [Arguments]  ${setting_file}  ${packages}  ${base_ref}  ${other_build_flags}  ${ws}

    ${result}=   Run Process    stuart_pr_eval
    ...  -c  ${setting_file}  -p  ${packages}  --pr-target  origin/${base_ref}
    ...  --output-csv-format-string  {pkgcsv}
    ...  cwd=${ws}  stdout=stdout.txt  stderr=stderr.txt
    Log Many  stdout: ${result.stdout}  stderr: ${result.stderr}
    Should Be Equal As Integers  ${result.rc}  0
    Return From Keyword    ${result.stdout}

### Edk2 BaseTools Build operations ###
Build BaseTools
    [Arguments]  ${tool_chain}  ${ws}
    Log to console  Compile basetools
    ${result}=   Run Process    python
    ...  BaseTools/Edk2ToolsBuild.py  -t  ${tool_chain}
    ...  cwd=${ws}  shell=True  stdout=stdout.txt  stderr=stderr.txt
    Log Many	stdout: ${result.stdout}  stderr: ${result.stderr}
    Should Be Equal As Integers  ${result.rc}  0
