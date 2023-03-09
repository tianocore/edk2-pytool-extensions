# @file repo_resolver.py
# This module supports git operations (git repos).
##
# Copyright (c) Microsoft Corporation
#
# SPDX-License-Identifier: BSD-2-Clause-Patent
##
"""This module supports all git operations for edk2-pytool-extensions.

edk2-pytool-extensions has consolidated all git functionality within the repo_resolver module, which relies
on the GitPython PyPi module.  This module provides functionality to clone, checkout, and clean repos and
submodules along with providing common information about the repo or submodule.

The intent is to keep all git functionality consolidated in this module. Currently edk2_ci_setup.py,
edk2_setup.py, and git_dependency.py use this module to perform git operations.
"""
import os
from logging import getLogger
from edk2toolext import edk2_logging
from git import Repo, GitCommandError, InvalidGitRepositoryError, NoSuchPathError
from git.cmd import Git
from git.util import rmtree
from pathlib import Path


logger = getLogger(__name__)


def resolve(file_system_path, dependency, force=False, ignore=False, update_ok=False):
    """Resolves a particular repo.

    Args:
        file_system_path (Pathlike): path to repo
        dependency (Dict): contains Path, Commit, Branch
        force (bool): If it is OK to update the commit or branch
        ignore (bool): If it is OK to ignore errors or not.
        update_ok (bool): If it is OK to update the commit or branch

    Raises:
        (Exception): An error resolving a repo and ignore=False
    """
    logger.info("Checking for dependency {0}".format(dependency["Path"]))
    git_path = os.path.abspath(file_system_path)

    # check if we have a path in our dependency
    if "Path" in dependency and not git_path.endswith(os.path.relpath(dependency["Path"])):
        # if we don't already the the path from the dependency at the end of the path we've been giving
        git_path = os.path.join(git_path, dependency["Path"])
    logger.info(f"Resolving at {git_path}")

    ##########################################################################
    #         Determine if we can, and how to checkout the repo              #
    ##########################################################################

    details = repo_details(git_path)

    ##########################################################################
    # 1. The directory does not exist, we can clone into it                  #
    ##########################################################################
    if not details["Path"].is_dir():
        logger.info(f"Cloning at {git_path}")
        clone_repo(git_path, dependency)
        checkout(git_path, dependency, True, False)
        return

    ##########################################################################
    # 2. The directory is empty, we can clone and checkout.                  #
    ##########################################################################
    if not any(details["Path"].iterdir()):
        clone_repo(git_path, dependency)
        checkout(git_path, dependency, True, False)
        return

    ##########################################################################
    # 3. Files are present, but it is not a git repo. Only clone and         #
    #    checkout if force is True.                                          #
    ##########################################################################
    if not details["Initialized"]:
        if force:
            clear_folder(git_path)
            logger.warning(
                f"Folder {git_path} is not a git repo and is being overwritten!")
            clone_repo(git_path, dependency)
            checkout(git_path, dependency, True, False)
            return
        else:
            if (ignore):
                logger.warning(
                    f"Folder {git_path} is not a git repo but Force parameter not used.  "
                    "Ignore State Allowed.")
                return
            else:
                logger.critical(
                    f"Folder {git_path} is not a git repo and it is not empty.")
                raise Exception(
                    f"Folder {git_path} is not a git repo and it is not empty")

    ##########################################################################
    # 4. A git repo exists, but it is dirty. Only re-clone and checkout if   #
    #    force is True.                                                      #
    ##########################################################################
    if details["Dirty"]:
        if force:
            clear_folder(git_path)
            logger.warning(
                f"Folder {git_path} is a git repo but is dirty and is being overwritten as requested!")
            clone_repo(git_path, dependency)
            checkout(git_path, dependency, True, False)
            return
        else:
            if (ignore):
                logger.warning(
                    f"Folder {git_path} is a git repo but is dirty and Force parameter not used.  "
                    "Ignore State Allowed.")
                return
            else:
                logger.critical(
                    f"Folder {git_path} is a git repo and is dirty.")
                raise Exception(
                    f"Folder {git_path} is a git repo and is dirty.")

    ##########################################################################
    # 5. The origin of the repo does not match. Only re-clone from the       #
    #    correct origin and checkout if force is True.                       #
    ##########################################################################
    if details["Url"] != dependency["Url"]:
        if force:
            clear_folder(git_path)
            logger.warning(
                f"Folder {git_path} is a git repo but it is at a different repo and is "
                "being overwritten as requested!")
            clone_repo(git_path, dependency)
            checkout(git_path, dependency, True, False)
            return
        else:
            if ignore:
                logger.warning(
                    f"Folder {git_path} is a git repo pointed at a different remote.  "
                    "Can't checkout or sync state")
                return
            else:
                logger.critical("The URL of the git Repo {2} in the folder {0} does not match {1}".format(
                    git_path, dependency["Url"], repo_details(git_path).url))
                raise Exception("The URL of the git Repo {2} in the folder {0} does not match {1}".format(
                    git_path, dependency["Url"], repo_details(git_path).url))

    ##########################################################################
    # 6. The repo is normal, Perform a regular checkout.                     #
    ##########################################################################
    checkout(git_path, dependency, update_ok, ignore, force)
    return


def resolve_all(workspace_path, dependencies, force=False, ignore=False, update_ok=False, omnicache_dir=None):
    """Resolves all repos.

    Args:
        workspace_path (Pathlike): workspace root
        dependencies (List[Dict]): Dict contains Path, Commit, Branch
        force (bool): If it is OK to update the commit or branch
        ignore (bool): If it is OK to ignore errors or not.
        update_ok (bool): If it is OK to update the commit or branch
        omnicache_dir (:obj:`bool`, optional): Omnicache path, if used

    Raises:
        (Exception): An error resolving a repo and ignore=False
    """
    repos = []
    if force:
        logger.info("Resolving dependencies by force")
    if update_ok:
        logger.info("Resolving dependencies with updates as needed")
    for dependency in dependencies:
        dep_path = dependency["Path"]
        logger.log(edk2_logging.PROGRESS, f"Syncing {dep_path}")
        if "ReferencePath" not in dependency and omnicache_dir:
            dependency["ReferencePath"] = omnicache_dir
        if "ReferencePath" in dependency:  # make sure that the omnicache dir is relative to the working directory
            dependency["ReferencePath"] = os.path.join(workspace_path, dependency["ReferencePath"])
        git_path = os.path.join(workspace_path, dep_path)
        repos.append(git_path)
        resolve(git_path, dependency, force, ignore, update_ok)

    # print out the details- this is optional
    for dependency in dependencies:
        git_path = os.path.join(workspace_path, dependency["Path"])
        details = repo_details(git_path)
        # print out details
        logger.info("{3} = Git Details: Url: {0} Branch {1} Commit {2}".format(
            details["Url"], details["Branch"], details["Head"]["HexSha"], dependency["Path"]))

    return repos


def repo_details(abs_file_system_path):
    """Return information about the repo.

    if self.valid is False, all other return members are set to default values
    and should not be expected to be correct.

    Args:
        abs_file_system_path (PathLike): repo directory

    Returns:
        (obj): Object with data members listed above
    """
    details = {
        "Path": Path(abs_file_system_path),
        "Valid": False,
        "GitVersion": ".".join(map(str, Git().version_info)),
        "Initialized": False,
        "Bare": False,
        "Dirty": False,
        "Url": None,
        "Head": None,
        "Branch": None,
        "Submodules": [],
        "Remotes": [],
        "Worktrees": []
    }

    try:
        with Repo(abs_file_system_path) as repo:
            # Active Branch
            details["Branch"] = 'HEAD' if repo.head.is_detached else repo.active_branch.name

            # Worktrees
            worktree_list = []
            worktrees = repo.git.worktree("list", "--porcelain", "-z")
            for worktree in filter(lambda worktree: worktree.startswith("worktree"), worktrees.split('\0')):
                worktree_list.append(Path(worktree.split(" ")[1]))
                details["Worktrees"] = worktree_list

            # head information
            details["Head"] = {"HexSha": str(repo.head.commit.hexsha), "HexShaShort": str(repo.head.commit.hexsha[:7])}
            details["Valid"] = True
            details["Bare"] = repo.bare
            details["Dirty"] = repo.is_dirty(untracked_files=True)
            details["Initialized"] = True
            details["Url"] = repo.remotes.origin.url
    except (InvalidGitRepositoryError, NoSuchPathError):
        pass
    return details


def clear_folder(abs_file_system_path):
    """Cleans the folder.

    Args:
        abs_file_system_path (PathLike): Directory to delete.
    """
    logger.warning("WARNING: Deleting contents of folder {0} to make way for Git repo".format(
        abs_file_system_path))
    rmtree(abs_file_system_path)


def clone_repo(abs_file_system_path, DepObj):
    """Clones the repo in the folder using the dependency object.

    Args:
        abs_file_system_path (PathLike): destination to clone
        DepObj (Dict): dict containing Commit, Full, Branch, etc

    Returns:
        ((PathLike, Bool)): (destination, result)
    """
    logger.info("Cloning repo: {0}".format(DepObj["Url"]))
    dest = abs_file_system_path

    if not os.path.isdir(dest):
        os.makedirs(dest, exist_ok=True)

    # Generate the clone flags
    shallow = False
    branch = None
    reference = None

    if "Commit" in DepObj:
        shallow = False
    if "Full" in DepObj and DepObj["Full"] is True:
        shallow = False
    if "Branch" in DepObj:
        shallow = True
        branch = DepObj["Branch"]
    if "ReferencePath" in DepObj and os.path.exists(DepObj["ReferencePath"]):
        reference = os.path.abspath(DepObj["ReferencePath"])

    # Used to generate clone params from flags
    def _build_params_list(branch=None, shallow=None, reference=None):
        params = []
        if branch:
            shallow = True
            params.append('--branch')
            params.append(branch)
            params.append('--single-branch')
        if shallow:
            params.append('--depth=5')
        if reference:
            params.append('--reference')
            params.append('reference')
        else:
            params.append("--recurse-submodules")  # if we don't have a reference we can just recurse the submodules

    # Run the command
    try:
        repo = Repo.clone_from(DepObj["Url"], dest, multi_options=_build_params_list(branch, shallow, reference))
    except GitCommandError:
        repo = None

    if repo is None:
        if "ReferencePath" not in DepObj:
            return (dest, False)

        # attempt a retry without the reference
        logger.warning("Reattempting to clone without a reference. {0}".format(DepObj["Url"]))

        try:
            repo = Repo.clone_from(DepObj["Url"], dest, multi_options=_build_params_list(branch, shallow))
        except GitCommandError:
            return (dest, False)

    # Repo cloned, perform submodule update if necessary
    if reference:
        repo.git.submodule('update', '--init', '--recursive', '--reference', reference)
    repo.close()
    return (dest, True)


def checkout(abs_file_system_path, dep, update_ok=False, ignore_dep_state_mismatch=False, force=False):
    """Checks out a commit or branch.

    Args:
        abs_file_system_path (PathLike): The path to the repo
        dep (Dict): A dictionary containing a either a Commit or Branch, and also a Path
        update_ok (bool): If it is OK to update the commit or branch
        ignore_dep_state_mismatch (bool): Whether a mismatch will result in an exception or not.
        force (bool): If it is OK to update the commit or branch

    Raises:
        (Exception): dependency state mismatch if ignore_dep_state_mismatch = False
        (GitCommandError): If the commit or branch does not exist locally and on the remote
    """
    details = repo_details(abs_file_system_path)
    with Repo(abs_file_system_path) as repo:
        if "Commit" in dep:
            commit = dep["Commit"]
            if update_ok or force:
                repo.git.fetch()
                try:
                    repo.git.checkout(commit)
                except GitCommandError:
                    repo.git.fetch()
                    repo.git.checkout(commit)
                repo.git.submodule("update", "--init", "--recursive")
            else:
                head = details["Head"]
                if commit in [head["HexSha"], head["HexShaShort"]]:
                    logger.debug(
                        f"Dependency {dep['Path']} state ok without update")
                elif ignore_dep_state_mismatch:
                    logger.warning(
                        f"Dependency {dep['Path']} is not in sync with requested commit.  Ignore state allowed")
                else:
                    logger.critical(
                        f"Dependency {dep['Path']} is not in sync with requested commit.  Fail.")
                    raise Exception(
                        f"Dependency {dep['Path']} is not in sync with requested commit.  Fail.")
            return

        elif "Branch" in dep:
            branch = dep["Branch"]
            if update_ok or force:
                repo.git.fetch()
                try:
                    repo.git.checkout(branch)
                except GitCommandError:
                    # try to fetch it and try to checkout again
                    logger.info("We failed to checkout this branch, we'll try to fetch")
                    repo.git.fetch(branch=branch)
                    repo.git.checkout(branch=branch)
                repo.git.submodule("update", "--init", "--recursive")
            else:
                if details["Branch"] == dep["Branch"]:
                    logger.debug(
                        f"Dependency {dep['Path']} state ok without update")
                elif ignore_dep_state_mismatch:
                    logger.warning(
                        f"Dependency {dep['Path']} is not in sync with requested branch.  Ignore state allowed")
                else:
                    error = "Dependency {0} is not in sync with requested branch. Expected: {1}. Got {2} Fail.".format(
                        dep["Path"], dep["Branch"], details["Branch"])
                    logger.critical(error)
                    raise Exception(error)
            return

        else:
            raise Exception("Branch or Commit must be specified for {0}".format(dep["Path"]))


def clean(abs_file_system_path, ignore_files=[]):
    """Resets and cleans the repo.

    Args:
        abs_file_system_path (PathLike): repo directory
        ignore_files (list): list of files to ignore when performing a clean

    Raises:
        (GitCommandError): The command is invalid
        (InvalidGitRepositoryError): The repo is in an invalid format
        (NoSuchPathError): The path does not exist
    """
    with Repo(abs_file_system_path) as repo:
        repo.git.reset("--hard")
        params = ["-xffd"]
        for file in ignore_files:
            params.append("-e")
            params.append(file)
        repo.git.clean(*params)


def submodule_clean(abs_file_system_path, submodule):
    """Resets and cleans a submodule of the repo.

    Args:
        abs_file_system_path (PathLike): repo directory
        submodule (obj): object containing path (relative) attribute
        ignore_files (list, optional): list of files to ignore when performing a clean. Defaults to [].

    Raises:
        (GitCommandError): The command is invalid
        (InvalidGitRepositoryError): The repo is in an invalid format
        (NoSuchPathError): The path does not exist
        (ValueError): submodule's path was invalid
    """
    with Repo(abs_file_system_path) as repo:
        s = next(filter(lambda s: Path(s.path) == Path(submodule.path), repo.submodules), None)

        if s is None:
            raise ValueError(f"Submodule {submodule.path} does not exist")

        if s.module_exists():
            clean(os.path.join(abs_file_system_path, submodule.path))


def submodule_resolve(abs_file_system_path, submodule, omnicache_path=None):
    """Resolves a submodule to the specified branch and commit in .gitmodules.

    On the submodule, first performs a submodule sync followed by a submodule update --init.

    Args:
        abs_file_system_path (PathLike): repo directory
        submodule (obj): object containing attributes: path (relative) and recursive
        omnicache_path (PathLike | None): absolute path to the omnicache, if used

    Raises:
        (GitCommandError): The command is invalid
        (InvalidGitRepositoryError): The repo is in an invalid format
        (NoSuchPathError): The path does not exist
    """
    with Repo(abs_file_system_path) as repo:

        logger.debug(f'Syncing {submodule.path}')
        repo.git.submodule('sync', '--', submodule.path)

        params = ['update', '--init']
        if submodule.recursive:
            params.append("--recursive")
        if omnicache_path:
            params.append('--reference')
            params.append(omnicache_path)
        params.append(submodule.path)
        logger.debug(f'Updating {submodule.path}')
        repo.git.submodule(*params)

    with Repo(Path(abs_file_system_path, submodule.path)) as _:
        logger.debug(f'{submodule.path} is valid and resolved.')
