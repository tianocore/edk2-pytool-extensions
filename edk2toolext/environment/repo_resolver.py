# @file repo_resolver.py
# This module supports git operations (git repos).
##
# Copyright (c) Microsoft Corporation
#
# SPDX-License-Identifier: BSD-2-Clause-Patent
##
"""This module supports git operations."""
import os
import logging
from edk2toolext import edk2_logging
from edk2toolext.edk2_git import Repo
from typing import Union
from pathlib import Path

# this follows a documented flow chart


# checks out dependency at git_path
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
    logger = logging.getLogger("git")
    logger.info("Checking for dependency {0}".format(dependency["Path"]))
    git_path = os.path.abspath(file_system_path)

    # check if we have a path in our dependency
    if "Path" in dependency and not git_path.endswith(os.path.relpath(dependency["Path"])):
        # if we don't already the the path from the dependency at the end of the path we've been giving
        git_path = os.path.join(git_path, dependency["Path"])
    logging.info(f"Resolving at {git_path}")
    ##
    # NOTE - this process is defined in the Readme.md including flow chart for this behavior
    ##
    if not os.path.isdir(git_path):
        logging.info(f"Cloning at {git_path}")
        _, repo = clone_repo(git_path, dependency)
        checkout(repo, dependency, True, False)
        return repo

    folder_empty = len(os.listdir(git_path)) == 0
    if folder_empty:  # if the folder is empty, we can clone into it
        _, r = clone_repo(git_path, dependency)
        checkout(git_path, dependency, r, True, False)
        return r

    repo = Repo(git_path)
    if not repo.initialized:  # if there isn't a .git folder in there
        if force:
            clear_contents(repo)
            logger.warning(f'Folder {git_path} is not a git repo and is being overwritten!')
            _, repo = clone_repo(repo, dependency)
            checkout(repo, dependency, True, False)
            return repo
        else:
            if (ignore):
                logger.warning(
                    "Folder {0} is not a git repo but Force parameter not used.  "
                    "Ignore State Allowed.".format(git_path))
                return repo
            else:
                logger.critical(
                    "Folder {0} is not a git repo and it is not empty.".format(git_path))
                raise Exception(
                    "Folder {0} is not a git repo and it is not empty".format(git_path))

    if repo.dirty:
        if force:
            clear_contents(repo)
            logger.warning(
                "Folder {0} is a git repo but is dirty and is being overwritten as requested!".format(git_path))
            _, repo = clone_repo(repo, dependency)
            checkout(repo, dependency, True, False)
            return repo
        else:
            if (ignore):
                logger.warning(
                    "Folder {0} is a git repo but is dirty and Force parameter not used.  "
                    "Ignore State Allowed.".format(git_path))
                return repo
            else:
                logger.critical(
                    "Folder {0} is a git repo and is dirty.".format(git_path))
                raise Exception(
                    "Folder {0} is a git repo and is dirty.".format(git_path))

    if repo.remotes.origin.url != dependency["Url"]:
        if force:
            clear_contents(repo)
            logger.warning(
                "Folder {0} is a git repo but it is at a different repo and is "
                "being overwritten as requested!".format(git_path))
            _, repo = clone_repo(repo, dependency)
            checkout(repo, dependency, True, False)
            return repo
        else:
            if ignore:
                logger.warning(
                    "Folder {0} is a git repo pointed at a different remote.  "
                    "Can't checkout or sync state".format(git_path))
                return
            else:
                logger.critical("The URL of the git Repo {2} in the folder {0} does not match {1}".format(
                    git_path, dependency["Url"], repo.remotes.origin.url))
                raise Exception("The URL of the git Repo {2} in the folder {0} does not match {1}".format(
                    git_path, dependency["Url"], repo.remotes.origin.url))
    # if we've gotten here, we should just checkout as normal
    checkout(repo, dependency, update_ok, ignore, force)
    return repo

##
# dependencies is a list of objects - it has Path, Commit, Branch,


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
    logger = logging.getLogger("git")
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
        GitDetails = get_details(git_path)
        # print out details
        logger.info("{3} = Git Details: Url: {0} Branch {1} Commit {2}".format(
            GitDetails["Url"], GitDetails["Branch"], GitDetails["Commit"], dependency["Path"]))

    return repos


def get_details(repo: Union[Repo, Path]):
    """Gets the Url, Branch, and Commit of a particular repo.

    Args:
        repo (Repo, Path): Repo objet or absolute path to location

    Returns:
        (Dict): Url, Branch, Commit
    """
    if type(repo) is not Repo:
        repo = Repo(repo)

    url = repo.remotes.origin.url
    active_branch = repo.active_branch
    head = repo.head.commit
    return {"Url": url, "Branch": active_branch, "Commit": head}


def clear_contents(repo: Union[Repo, Path] = None):
    """Cleans the contents.

    Args:
        repo (Repo, Path): Repo objet or absolute path to location
    """
    if type(repo) is not Repo:
        repo = Repo(repo)

    logger = logging.getLogger("git")
    logger.warning(f'WARNING: Deleting contents of folder {repo} to make way for Git repo')
    repo.delete()


def clone_repo(repo: Union[Repo, Path], DepObj):
    """Clones the repo in the folder using the dependency object.

    Args:
        repo (Repo, Path): Repo objet or absolute path to location
        DepObj (Dict): dict containing Commit, Full, Branch, etc

    Returns:
        (Tuple[PathLike, bool]): (destination, result)
    """
    if type(repo) is not Repo:
        repo = Repo(repo)
    logger = logging.getLogger("git")
    logger.log(edk2_logging.get_progress_level(), "Cloning repo: {0}".format(DepObj["Url"]))
    dest = str(repo.path)
    if not os.path.isdir(dest):
        os.makedirs(dest, exist_ok=True)
    shallow = False
    branch = None
    if "Commit" in DepObj:
        shallow = False
    if "Full" in DepObj and DepObj["Full"] is True:
        shallow = False
    if "Branch" in DepObj:
        shallow = True
        branch = DepObj["Branch"]

    reference = None
    if "ReferencePath" in DepObj and os.path.exists(DepObj["ReferencePath"]):
        reference = os.path.abspath(DepObj["ReferencePath"])
    repo = Repo.clone_from(DepObj["Url"], dest, branch=branch, shallow=shallow, reference=reference)

    if repo is None:
        if "ReferencePath" in DepObj:
            # attempt a retry without the reference
            logger.warning("Reattempting to clone without a reference. {0}".format(DepObj["Url"]))
            repo = Repo.clone_from(DepObj["Url"], dest, branch=branch, shallow=shallow)

    return (dest, repo)


def checkout(repo: Union[Repo, Path], dep, update_ok=False, ignore_dep_state_mismatch=False, force=False):
    """Checks out a commit or branch.

    Args:
        repo (Repo, Path): Repo objet or absolute path to location
        dep (Dict): A dictionary containing a either a Commit or Branch, and also a Path
        update_ok (bool): If it is OK to update the commit or branch
        ignore_dep_state_mismatch (bool): Whether a mismatch will result in an exception or not.
        force (bool): If it is OK to update the commit or branch

    Raises:
        (Exception): dependency state mismatch if ignore_dep_state_mismatch = False

    !!! tip
        Either abs_file_system_path or repo is necessary. Not both.
    """
    logger = logging.getLogger("git")
    if type(repo) is not Repo:
        repo = Repo(repo)
    if "Commit" in dep:
        commit = dep["Commit"]
        if update_ok or force:
            repo.fetch()
            result = repo.checkout(commit=commit)
            if result is False:
                repo.fetch()
                repo.checkout(commit=commit)
            repo.submodule("update", "--init", "--recursive")
        else:
            if repo.head.commit == commit or repo.head.commit[:7] == commit:
                logger.debug(
                    "Dependency {0} state ok without update".format(dep["Path"]))
                return
            elif ignore_dep_state_mismatch:
                logger.warning(
                    "Dependency {0} is not in sync with requested commit.  Ignore state allowed".format(dep["Path"]))
                return
            else:
                logger.critical(
                    "Dependency {0} is not in sync with requested commit.  Fail.".format(dep["Path"]))
                raise Exception(
                    "Dependency {0} is not in sync with requested commit.  Fail.".format(dep["Path"]))

    elif "Branch" in dep:
        branch = dep["Branch"]
        if update_ok or force:
            repo.fetch()
            result = repo.checkout(branch=branch)
            if result is False:  # we failed to do this
                # try to fetch it and try to checkout again
                logger.info("We failed to checkout this branch, we'll try to fetch")
                repo.fetch(branch=branch)
                repo.checkout(branch=branch)
            repo.submodule("update", "--init", "--recursive")
        else:
            if repo.active_branch == dep["Branch"]:
                logger.debug(
                    "Dependency {0} state ok without update".format(dep["Path"]))
                return
            elif ignore_dep_state_mismatch:
                logger.warning(
                    "Dependency {0} is not in sync with requested branch.  Ignore state allowed".format(dep["Path"]))
                return
            else:
                error = "Dependency {0} is not in sync with requested branch. Expected: {1}. Got {2} Fail.".format(
                    dep["Path"], dep["Branch"], repo.active_branch)
                logger.critical(error)
                raise Exception(error)
    else:
        raise Exception(
            "Branch or Commit must be specified for {0}".format(dep["Path"]))
