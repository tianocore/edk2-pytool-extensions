# @file test_repo_resolver.py
# This contains unit tests for repo resolver
#
##
# Copyright (c) Microsoft Corporation
#
# SPDX-License-Identifier: BSD-2-Clause-Patent
##
import logging
import os
import unittest
from edk2toolext.environment import repo_resolver
from edk2toollib.utility_functions import RemoveTree
import tempfile
import pathlib
import pytest


def get_first_file(folder: pathlib.Path) -> pathlib.Path:
    for file_path in folder.iterdir():
        if file_path.is_file():
            return file_path
    return None


def test_resolve_all(tmp_path, octocat_dep):
    d1 = dict(octocat_dep)
    d1["Commit"] = "a30c19e3f13765a3b48829788bc1cb8b4e95cee4"
    d2 = dict(octocat_dep)
    d2["Commit"] = "bb4cc8d3b2e14b3af5df699876dd4ff3acd00b7f"
    d3 = dict(octocat_dep)
    d3["Commit"] = "d0dd1f61b33d64e29d8bc1372a94ef6a2fee76a9"

    repos = repo_resolver.resolve_all(tmp_path, [d1, d2, d3], force=True)

    for repo in repos:
        assert len(list(pathlib.Path(repo).iterdir())) > 0


def test_clone_from_with_bad_reference(tmp_path):
    # Clone the repo from a bad reference
    repo_path2 = tmp_path / "repo2"
    bad_repo_path = tmp_path / "bad_repo"
    dep = {"Url": "https://github.com/octocat/Spoon-Knife", "ReferencePath": bad_repo_path}
    repo_resolver.clone_repo(repo_path2, dep)
    assert len(list(repo_path2.iterdir())) > 0


def test_checkout_branch(tmp_path, octocat_dep):
    # Clone the repo
    octocat_dep["Branch"] = "main"

    repo_resolver.clone_repo(tmp_path, octocat_dep)
    details = repo_resolver.repo_details(tmp_path)
    assert details["Branch"] == "main"

    # Checkout same branch
    repo_resolver.checkout(tmp_path, octocat_dep)
    details = repo_resolver.repo_details(tmp_path)
    assert details["Branch"] == "main"

    # Dep for the rest of the tests
    octocat_dep["Branch"] = "test-branch"

    # Checkout different branch with ignore_dep_state_mismatch
    repo_resolver.checkout(tmp_path, octocat_dep, ignore_dep_state_mismatch=True)
    details = repo_resolver.repo_details(tmp_path)
    assert details["Branch"] == "main"

    # Checkout different branch without force
    with pytest.raises(Exception):
        repo_resolver.checkout(tmp_path, octocat_dep)

    # Checkout different branch with force
    repo_resolver.checkout(tmp_path, octocat_dep, force=True)
    details = repo_resolver.repo_details(tmp_path)
    assert details["Branch"] == "test-branch"


def test_checkout_bad_branch(tmp_path, octocat_dep):
    # Clone the repo
    octocat_dep["Branch"] = "main"

    repo_resolver.clone_repo(tmp_path, octocat_dep)
    details = repo_resolver.repo_details(tmp_path)
    assert details["Branch"] == "main"

    # Checkout bad branch without forcing
    octocat_dep["Branch"] = "does not exist"

    with pytest.raises(Exception):
        repo_resolver.checkout(tmp_path, octocat_dep)

    # Checkout bad branch with forcing
    with pytest.raises(repo_resolver.GitCommandError):
        repo_resolver.checkout(tmp_path, octocat_dep, force=True)


def test_will_delete_dirty_repo(tmp_path, octocat_dep):
    octocat_dep["Commit"] = "d0dd1f61b33d64e29d8bc1372a94ef6a2fee76a9"

    repo_resolver.resolve(tmp_path, octocat_dep)
    folder_path = tmp_path / octocat_dep["Path"]
    file_path = get_first_file(folder_path)
    # make sure the file already exists
    assert file_path.is_file()

    with open(file_path, "a+") as out_file:
        out_file.write("Make sure we don't delete this")
    assert file_path.exists()

    octocat_dep["Commit"] = "bb4cc8d3b2e14b3af5df699876dd4ff3acd00b7f"

    try:
        repo_resolver.resolve(tmp_path, octocat_dep, force=True)
    except:
        pytest.fail("We shouldn't fail when we are forcing")


def test_will_switch_branches(tmp_path, octocat_dep):
    octocat_dep["Branch"] = "main"

    repo_resolver.resolve(tmp_path, octocat_dep)
    folder_path = tmp_path / octocat_dep["Path"]

    octocat_dep["Branch"] = "test-branch"
    repo_resolver.resolve(tmp_path, octocat_dep, force=True)

    details = repo_resolver.repo_details(folder_path)
    assert details["Url"] == octocat_dep["Url"]
    assert details["Branch"] == octocat_dep["Branch"]


# check to make sure that we can clone a branch correctly
def test_clone_branch_repo(tmp_path, octocat_dep):
    octocat_dep["Branch"] = "main"
    
    # create an empty directory- and set that as the workspace
    repo_resolver.resolve(tmp_path, octocat_dep)
    folder_path = tmp_path / octocat_dep["Path"]

    details = repo_resolver.repo_details(folder_path)
    assert details["Url"] == octocat_dep["Url"]
    assert details["Branch"] == octocat_dep["Branch"]


def test_clone_branch_existing_folder(tmp_path, octocat_dep):
    # Resolve when folder exists but is empty
    octocat_dep["Branch"] = "main"

    folder_path = tmp_path / octocat_dep["Path"]
    folder_path.mkdir(parents=True, exist_ok=True)

    repo_resolver.resolve(tmp_path, octocat_dep)
    details = repo_resolver.repo_details(folder_path)
    assert details["Url"] == octocat_dep["Url"]
    assert details["Branch"] == octocat_dep["Branch"]


# don't create a git repo, create the folder, add a file, try to clone in the folder, it should throw an exception
def test_wont_delete_files(tmp_path, octocat_dep):
    octocat_dep["Branch"] = "main"
    folder_path = tmp_path / octocat_dep["Path"]

    folder_path.mkdir(parents=True, exist_ok=True)
    file_path = folder_path / "test.txt"

    with open(file_path, "w+") as out_file:
        out_file.write("Make sure we don't delete this")

    assert file_path.is_file()

    with pytest.raises(Exception):
        repo_resolver.resolve(tmp_path, octocat_dep)
        pytest.fail("We shouldn't make it here")
    assert file_path.is_file()


# don't create a git repo, create the folder, add a file, try to clone in the folder, will force it to happen
def test_will_delete_files(tmp_path, octocat_dep):
    octocat_dep["Commit"] = "d0dd1f61b33d64e29d8bc1372a94ef6a2fee76a9"
    folder_path = tmp_path / octocat_dep["Path"]
    folder_path.mkdir(parents=True, exist_ok=True)
    file_path = folder_path / "test.txt"
    with open(file_path, "w+") as out_file:
        out_file.write("Make sure we don't delete this")
    assert file_path.exists()
    try:
        repo_resolver.resolve(tmp_path, octocat_dep, force=True)
    except:
        pytest.fail("We shouldn't fail when we are forcing")
    details = repo_resolver.repo_details(folder_path)
    assert details["Url"] == octocat_dep['Url']


# don't create a git repo, create the folder, add a file, try to clone in the folder, will ignore it.
def test_will_ignore_files(tmp_path, octocat_dep):
    octocat_dep["Commit"] = "d0dd1f61b33d64e29d8bc1372a94ef6a2fee76a9"
    folder_path = tmp_path / octocat_dep["Path"]
    folder_path.mkdir(parents=True, exist_ok=True)
    file_path = folder_path / "test.txt"
    with open(file_path, "w+") as out_file:
        out_file.write("Make sure we don't delete this")

    assert file_path.exists()
    repo_resolver.resolve(tmp_path, octocat_dep, ignore=True)


def test_wont_delete_dirty_repo(tmp_path, octocat_dep):
    octocat_dep["Commit"] = "d0dd1f61b33d64e29d8bc1372a94ef6a2fee76a9"
    repo_resolver.resolve(tmp_path, octocat_dep)
    folder_path = tmp_path / octocat_dep["Path"]

    file_path = get_first_file(folder_path)
    # make sure the file already exists
    assert file_path.is_file()
    with open(file_path, "a+") as out_file:
        out_file.write("Make sure we don't delete this")

    assert file_path.exists()

    with pytest.raises(Exception):
        repo_resolver.resolve(tmp_path, octocat_dep, update_ok=True)

    # Get passed this with ignore=true
    repo_resolver.resolve(tmp_path, octocat_dep, ignore=True)


# check to make sure we can clone a commit correctly
def test_clone_commit_repo(tmp_path, octocat_dep):
    # create an empty directory- and set that as the workspace
    octocat_dep["Commit"] = "d0dd1f61b33d64e29d8bc1372a94ef6a2fee76a9"
    repo_resolver.resolve(tmp_path, octocat_dep)
    folder_path = tmp_path / octocat_dep["Path"]
    details = repo_resolver.repo_details(folder_path)

    assert details["Url"] == octocat_dep['Url']
    assert details["Head"]["HexSha"] == octocat_dep['Commit']


# check to make sure we support short commits
def test_clone_short_commit_repo(tmp_path, octocat_dep):
    octocat_dep["Commit"] = "d0dd1f6"
    repo_resolver.resolve(tmp_path, octocat_dep)
    folder_path = tmp_path / octocat_dep["Path"]
    details = repo_resolver.repo_details(folder_path)

    assert details["Url"] == octocat_dep['Url']
    assert details["Head"]["HexShaShort"] == octocat_dep['Commit']

    # Resolve again, making sure we don't fail if repo already exists.
    repo_resolver.resolve(tmp_path, octocat_dep)


# check to make sure we can clone a commit correctly
def test_fail_update(tmp_path, octocat_dep):
    octocat_dep["Commit"] = "d0dd1f61b33d64e29d8bc1372a94ef6a2fee76a9"
    # create an empty directory- and set that as the workspace
    repo_resolver.resolve(tmp_path, octocat_dep)
    folder_path = tmp_path / octocat_dep["Path"]
    details = repo_resolver.repo_details(folder_path)

    assert details["Url"] == octocat_dep['Url']
    assert details["Head"]["HexSha"] == octocat_dep['Commit']

    # first we checkout
    dep = dict(octocat_dep)
    dep["Commit"] = "bb4cc8d3b2e14b3af5df699876dd4ff3acd00b7f"
    with pytest.raises(Exception):
        repo_resolver.resolve(tmp_path, dep)

    details = repo_resolver.repo_details(folder_path)
    assert details["Url"] == octocat_dep['Url']
    assert details["Head"]["HexSha"] == octocat_dep["Commit"]


def test_does_update(tmp_path, octocat_dep):
    # create an empty directory- and set that as the workspace
    octocat_dep["Commit"] = "bb4cc8d3b2e14b3af5df699876dd4ff3acd00b7f"
    repo_resolver.resolve(tmp_path, octocat_dep)
    folder_path = tmp_path / octocat_dep["Path"]

    details = repo_resolver.repo_details(folder_path)

    assert details["Url"] == octocat_dep["Url"]
    assert details["Head"]["HexSha"], octocat_dep["Commit"]

    octocat_dep["Commit"] = "bb4cc8d3b2e14b3af5df699876dd4ff3acd00b7f"
    # next we checkout and go to the later commit
    try:
        repo_resolver.resolve(tmp_path, octocat_dep, update_ok=True)
    except:
        pytest.fail("We are not supposed to throw an exception")

    details = repo_resolver.repo_details(folder_path)

    assert details["Url"] == octocat_dep["Url"]
    assert details["Head"]["HexSha"], octocat_dep["Commit"]


def test_cant_switch_urls(tmp_path, octocat_dep):
    # create an empty directory- and set that as the workspace
    octocat_dep["Branch"] = "main"
    repo_resolver.resolve(tmp_path, octocat_dep)
    folder_path = tmp_path / octocat_dep["Path"]

    details = repo_resolver.repo_details(folder_path)

    assert details["Url"] == octocat_dep["Url"]

    # first we checkout
    hello_world_dep = dict(octocat_dep)
    hello_world_dep["Url"] = "https://github.com/octocat/Hello-World"
    with pytest.raises(Exception):
        repo_resolver.resolve(tmp_path, hello_world_dep)

    details = repo_resolver.repo_details(folder_path)
    assert details["Url"] == octocat_dep['Url']


def test_ignore(tmp_path, octocat_dep):
    # create an empty directory- and set that as the workspace
    octocat_dep["Branch"] = "bb4cc8d3b2e14b3af5df699876dd4ff3acd00b7f"
    repo_resolver.resolve(tmp_path, octocat_dep)
    folder_path = tmp_path / octocat_dep["Path"]

    details = repo_resolver.repo_details(folder_path)

    assert details["Url"] == octocat_dep['Url']

    # first we checkout
    hello_world_dep = dict(octocat_dep)
    hello_world_dep["Url"] = "https://github.com/octocat/Hello-World"
    repo_resolver.resolve(tmp_path, hello_world_dep, ignore=True)

    details = repo_resolver.repo_details(folder_path)
    assert details["Url"] == octocat_dep['Url']


def test_will_switch_urls(tmp_path, octocat_dep):
    octocat_dep["Branch"] = "main"
    # create an empty directory- and set that as the workspace
    repo_resolver.resolve(tmp_path, octocat_dep)

    folder_path = tmp_path / octocat_dep["Path"]

    details = repo_resolver.repo_details(folder_path)

    assert details["Url"] == octocat_dep['Url']

    # first we checkout
    hello_world_dep = dict(octocat_dep)
    hello_world_dep["Url"] = "https://github.com/octocat/Hello-World"
    hello_world_dep["Branch"] = "master"
    try:
        repo_resolver.resolve(tmp_path, hello_world_dep, force=True)
    except:
        pytest.fail("We shouldn't fail when we are forcing")

    details = repo_resolver.repo_details(folder_path)
    assert details["Url"] == hello_world_dep['Url']


def test_submodule(tmp_path):

    class Submodule():
        def __init__(cls, path, recursive):
            cls.path = path
            cls.recursive = recursive

    submodule_path = "Common/MU_TIANO"
    deps = {"Url": "https://github.com/microsoft/mu_tiano_platforms"}
    repo_resolver.clone_repo(tmp_path, deps)

    build_folder = tmp_path / "Build"
    build_folder.mkdir(parents=True, exist_ok=True)
    tmp_file = build_folder / "tempfile.txt"
    with open(tmp_file, 'x') as f:
        f.write("Temp edit")
        assert tmp_file.is_file()

        repo_resolver.clean(tmp_path, ignore_files=["Build/tempfile.txt"])
        assert tmp_file.is_file()

    repo_resolver.clean(tmp_path)
    assert tmp_file.is_file() is False

    repo_resolver.submodule_resolve(tmp_path, Submodule(submodule_path, True))

@pytest.fixture(scope="session")
def octocat_ref(tmp_path_factory):
    tmp_path = tmp_path_factory.mktemp("octocat")
    dep = {
        "Url": "https://github.com/octocat/Spoon-Knife",
        "Path": tmp_path,
        "Branch": "main",
        "Full": True
    }
    repo_resolver.clone_repo(tmp_path, dep)
    return tmp_path

@pytest.fixture(scope="function")
def octocat_dep(octocat_ref):
    return {
        "Url": "https://github.com/octocat/Spoon-Knife",
        "Path": "test_repo",
        "ReferencePath": octocat_ref
    }
