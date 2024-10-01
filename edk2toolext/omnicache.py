##
# Copyright (c) Microsoft Corporation
#
# SPDX-License-Identifier: BSD-2-Clause-Patent
##
# spell-checker:ignore rtags
"""Omnicache tool for lessening network usage and time of cloning repositories."""

import argparse
import datetime
import logging
import os
import sys
import uuid
from io import StringIO
from typing import Optional

import yaml
from edk2toollib.utility_functions import RunCmd

from edk2toolext import edk2_logging

# Omnicache version 0.11+ design notes:
# 1. Only a single remote per URL will be permitted.
# 2. Remote names inside omnicache will be UUIDs generated when a new URL is added.
# 3. Users may specify names for remotes, but they will be treated simply as "display names" without git significance.
# 4. As many objects as possible will be cached for any given remote; so all remotes will fetch tags.
# 4a. To avoid tag name collisions between remotes, tags will be fetched into per-remote namespaces.
# 5. Older omnicaches will be updated to meet the above design points when first encountered by the script.
# 5a. This implementation takes care that the underlying git construction is compatible (but not performant) when an
#     older omnicache interacts with it. Older omnicache should not crash when encountering a newer omnicache directory
#     but may take a lot of slow and unecessary actions to "re-initialize" it.

OMNICACHE_VERSION = "0.12"

# Prior to version 0.11, an "omnicache.yaml" file in the root of the omnicache repo was used to manage the cache
# configuration. Starting with 0.11, git config entries are used directly. If the file below is present, it will be
# removed to force re-initialization of the omnicache by older omnicache instances. (e.g. if an old branch with a prior
# implementation of omnicache is being built and uses the same cache directory)
PRE_0_11_OMNICACHE_FILENAME = "omnicache.yaml"


class Omnicache:
    """Class for managing an omnicache instance."""

    def __init__(self, cachepath: str, create: bool = False, convert: bool = True) -> None:
        """Initializes an omnicache.

        Args:
            cachepath (str): path to the omnicache git repo
            create (bool):  create a new omnicache instance if it doesn't exist
            convert (bool): if an old (but compatible) omnicache already exists, at cachepath, convert it to this
                version of Omnicache
        """
        self.path = cachepath
        self._InvalidateUrlLookupCache()

        (valid, isConversionCandidate) = self._ValidateOmnicache()
        if not valid:
            if create and not isConversionCandidate:
                self._InitOmnicache()
            elif convert and isConversionCandidate:
                self._ConvertOmnicache()
            else:
                logging.critical("Omnicache at {0} not valid, and cannot create/convert.".format(cachepath))
                raise RuntimeError("Invalid cache path: {0}".format(cachepath))

    def _ValidateOmnicache(self) -> tuple:
        """Validates whether self.path has a valid omnicache instance.

        Returns:
            (bool, bool): valid, convertible

        NOTE: "valid" is True if a compatible Omnicache exists at self.path
        NOTE: "convertible" is True if an older Omnicache that can be converted exists at self.path.
        """
        logging.info("Checking if {0} is valid omnicache.".format(self.path))
        if not os.path.isdir(self.path):
            logging.debug("{0} does not exist - not valid (not convertible).".format(self.path))
            return (False, False)
        out = StringIO()
        ret = RunCmd("git", "rev-parse --is-bare-repository", workingdir=self.path, outstream=out)
        if ret != 0:
            logging.debug("{0} error getting repo state - not valid (not convertible).".format(self.path))
            return (False, False)
        if out.getvalue().strip().lower() == "true":
            if os.path.exists(os.path.join(self.path, PRE_0_11_OMNICACHE_FILENAME)):
                logging.debug("{0} - old config file present. not valid (is convertible).".format(self.path))
                return (False, True)
            out = StringIO()
            ret = RunCmd("git", "config --local omnicache.metadata.version", workingdir=self.path, outstream=out)
            if ret != 0:
                logging.debug("{0} - error retrieving omnicache version. not valid (is convertible).".format(self.path))
                return (False, True)
            if out.getvalue().strip() == OMNICACHE_VERSION:
                logging.debug("{0} - matching omnicache version. valid (convertible don't care).".format(self.path))
                return (True, True)
            else:
                logging.debug("{0} - non-matching omnicache version. not valid (is convertible).".format(self.path))
                return (False, True)
        logging.debug("{0} - not a bare repo. not valid (not convertible).".format(self.path))
        return (False, False)

    def _InitOmnicache(self) -> int:
        """Initializes a new omnicache instance."""
        logging.critical("Initializing Omnicache in {0}".format(self.path))
        os.makedirs(self.path, exist_ok=True)
        ret = RunCmd("git", "init --bare", workingdir=self.path)
        if ret != 0:
            return ret
        # by default, git fetch is single-threaded. This configuration allows git to use a "reasonable" default
        # (presently equal to the number of cpus) to execute the fetch in parallel.
        ret = RunCmd("git", "config --local fetch.parallel 0", workingdir=self.path)
        if ret != 0:
            return ret

        return RunCmd(
            "git", "config --local omnicache.metadata.version {0}".format(OMNICACHE_VERSION), workingdir=self.path
        )

    def _ConvertOmnicache(self) -> int:
        """Converts an existing bare git repo from a previous omnicache version to the current omnicache version."""
        logging.info("Converting Omnicache in {0} to latest format.".format(self.path))
        if os.path.exists(os.path.join(self.path, PRE_0_11_OMNICACHE_FILENAME)):
            os.remove(os.path.join(self.path, PRE_0_11_OMNICACHE_FILENAME))
        remotes = Omnicache.GetRemotes(self.path)
        logging.info("Renaming non-UUID remotes with UUID.")
        for name, _ in remotes.items():
            if not Omnicache._IsValidUuid(name):
                logging.info("Converting remote {0} to UUID".format(name))
                # Rename the remote with a valid UUID
                newName = str(uuid.uuid4())
                ret = RunCmd("git", "remote rename {0} {1}".format(name, newName), workingdir=self.path)
                if ret != 0:
                    # rename failed; try removal.
                    logging.warn("Failed to rename {0}. Attempting to remove it.".format(name))
                    ret = RunCmd("git", "remote remove {0}".format(name), workingdir=self.path)
                    if ret != 0:
                        logging.critical("Failed to rename or remove {0} - skipping.".format(name))
                        continue
                # Remove previous fetch config entries and regenerate them. Proceed to create new ones even if it fails.
                RunCmd("git", "config --local --unset-all remote.{0}.fetch".format(newName), workingdir=self.path)
                RunCmd(
                    "git",
                    "config --local --add remote.{0}.fetch +refs/heads/*:refs/remotes/{0}/*".format(newName),
                    workingdir=self.path,
                )
                RunCmd(
                    "git",
                    "config --local --add remote.{0}.fetch refs/tags/*:refs/rtags/{0}/*".format(newName),
                    workingdir=self.path,
                )
                # Add the original name as a display name
                RunCmd(
                    "git", "config --local omnicache.{0}.displayname {1}".format(newName, name), workingdir=self.path
                )
                logging.info("Remote {0} converted to {1}.".format(name, newName))
        # delete any tags in the global name space (older omnicaches fetched all tags into the global tag namespace)
        logging.info("Removing global tags")
        out = StringIO()
        RunCmd("git", "tag -l", workingdir=self.path, outstream=out)
        tags = " ".join(out.getvalue().splitlines())
        RunCmd("git", "tag -d {0}".format(tags), workingdir=self.path)
        # remove duplicates
        logging.info("Removing remotes with duplicate URLs")
        knownUrls = []
        remotes = Omnicache.GetRemotes(self.path)
        for name, url in remotes.items():
            if url not in knownUrls:
                logging.info("Retaining remote {0} with unique URL {1}".format(name, url))
                knownUrls.append(url)
            else:
                logging.info("Removing remote {0} with duplicate URL {1}".format(name, url))
                RunCmd("git", "remote remove {0}".format(name), workingdir=self.path)
                RunCmd("git", "config --local --unset omnicache.{0}.displayname".format(name), workingdir=self.path)
        # by default, git fetch is single-threaded. This configuration allows git to use a "reasonable" default
        # (presently equal to the number of cpus) to execute the fetch in parallel.
        ret = RunCmd("git", "config --local fetch.parallel 0", workingdir=self.path)
        if ret != 0:
            return ret
        # write current omnicache version into cache
        logging.info("Writing Omnicache version")
        return RunCmd(
            "git", "config --local omnicache.metadata.version {0}".format(OMNICACHE_VERSION), workingdir=self.path
        )

    def _RefreshUrlLookupCache(self) -> None:
        """Refreshes the URL lookup cache."""
        if len(self.urlLookupCache) == 0:
            logging.info("Regenerating URL lookup cache.")
            out = StringIO()
            ret = RunCmd("git", r"config --local --get-regexp remote\..*?\.url", workingdir=self.path, outstream=out)
            if ret != 0:
                return None
            # output is in the form: remote.<name>.url <url>
            for remote in out.getvalue().splitlines():
                self.urlLookupCache[remote.split()[1]] = ".".join(remote.split()[0].split(".")[1:-1])

    def _InvalidateUrlLookupCache(self) -> None:
        """Invalidates the URL lookup cache."""
        logging.debug("Invalidating URL lookup cache.")
        self.urlLookupCache = {}

    def _LookupRemoteForUrl(self, url: str) -> Optional[str]:
        """Returns the git remote name for the specified URL, or None if it doesn't exist."""
        self._RefreshUrlLookupCache()
        if url in self.urlLookupCache:
            return self.urlLookupCache[url]
        return None

    def AddRemote(self, url: str, name: Optional[str] = None) -> int:
        """Adds a remote for the specified URL to the omnicache.

        Args:
            url (str): URL for which to add a remote
            name(str, optional): provides a "display name" to be associated with this remote.
        """
        # if we already have this remote (i.e. a remote with this URL exists), then just update.
        if self._LookupRemoteForUrl(url) is not None:
            return self.UpdateRemote(url, newName=name)
        # otherwise create it.
        logging.info("Adding new remote for url {0}".format(url))
        newName = str(uuid.uuid4())
        ret = RunCmd("git", "remote add {0} {1}".format(newName, url), workingdir=self.path)
        if ret != 0:
            return ret
        self._InvalidateUrlLookupCache()
        # add display name, if specified
        if name is not None:
            ret = RunCmd(
                "git", "config --local omnicache.{0}.displayname {1}".format(newName, name), workingdir=self.path
            )
            if ret != 0:
                return ret
        # add a special fetch refspec to fetch remote tags into a per-remote local namespace.
        return RunCmd(
            "git",
            "config --local --add remote.{0}.fetch refs/tags/*:refs/rtags/{0}/*".format(newName),
            workingdir=self.path,
        )

    def RemoveRemote(self, url: str) -> int:
        """Removes the remote for the specified url from the cache."""
        name = self._LookupRemoteForUrl(url)
        if name is None:
            logging.critical("Failed to remove node for url {0}: such a remote does not exist.".format(url))
            return 1
        logging.info("Removing remote for url {0}".format(url))
        ret = RunCmd("git", "remote remove {0}".format(name), workingdir=self.path)
        self._InvalidateUrlLookupCache()
        return ret

    def UpdateRemote(self, oldUrl: str, newUrl: Optional[str] = None, newName: Optional[str] = None) -> int:
        """Updates the remote.

        Args:
            oldUrl (str): current url for the remote
            newUrl (str, optional): updates the remote to point to the new URL.
            newName (str, optional): updates the "displayname" for the remote.
        """
        remote = self._LookupRemoteForUrl(oldUrl)
        if remote is None:
            logging.critical("Failed to update node for url {0}: such a remote does not exist.".format(oldUrl))
            return 1
        if newName is not None:
            logging.info("Updating display name for url {0} to {1}".format(oldUrl, newName))
            ret = RunCmd(
                "git", "config --local omnicache.{0}.displayname {1}".format(remote, newName), workingdir=self.path
            )
            if ret != 0:
                return ret
        if newUrl is not None:
            logging.info("Updating url {0} to {1}".format(oldUrl, newUrl))
            ret = RunCmd("git", "remote set-url {0} {1}".format(remote, newUrl), workingdir=self.path)
            self._InvalidateUrlLookupCache()
            if ret != 0:
                return ret

        return 0

    def Fetch(self, jobs: int = 0) -> int:
        """Fetches all remotes."""
        logging.info("Fetching all remotes.")
        self._RefreshUrlLookupCache()
        # Tricky: we pass no-tags here, since we set up custom fetch refs for tags on a per-remote basis. This prevents
        # git from fetching the first set of tags into the global namespace.
        if jobs != 0:
            return RunCmd("git", "fetch --all -j {0} --no-tags".format(jobs), workingdir=self.path)
        else:
            return RunCmd("git", "fetch --all --no-tags", workingdir=self.path)

    def GetRemoteData(self) -> dict:
        """Gets Remote Data.

        Returns:
            (dict(dict)): {"<uuid>":{"url":<url>, "displayname":<displayname>}}

        Note: "displayname" may not be present if the remote has no display name.
        """
        logging.info("Retrieving all remote data")
        self._RefreshUrlLookupCache()
        remoteData = {}
        for url in self.urlLookupCache.keys():
            remoteData[self.urlLookupCache[url]] = {"url": url}

        out = StringIO()
        ret = RunCmd(
            "git", r"config --local --get-regexp omnicache\..*?\.displayname", workingdir=self.path, outstream=out
        )
        if ret != 0:
            return remoteData

        for displayName in out.getvalue().splitlines():
            remoteName = displayName.split()[0].split(".")[1]
            if remoteName in remoteData.keys():
                remoteData[remoteName].update({"displayname": displayName.split()[1]})
        return remoteData

    def List(self) -> None:
        """Prints the current set of remotes."""
        print("List OMNICACHE content:\n")
        remoteData = self.GetRemoteData()
        if len(remoteData) == 0:
            print("No remotes.")
        for name, data in remoteData.items():
            print("Id {0}: {1}".format(name, str(data)))

    @staticmethod
    def GetRemotes(path: str) -> dict:
        """Gets the remotes for the git repository at the specified path.

        Returns:
            (dict): {<remote>:<url>}
        """
        logging.info("Retreiving remotes")
        remotes = {}
        out = StringIO()

        ret = RunCmd("git", "remote -v", workingdir=path, outstream=out)
        if ret != 0:
            return remotes

        # Note: this loop assumes fetch and push URLs will be identical. If not, the last URL output will be the result.
        for remote in out.getvalue().splitlines():
            remoteInfo = remote.split()
            remotes[remoteInfo[0]] = remoteInfo[1]

        return remotes

    @staticmethod
    def _IsValidUuid(val: str) -> bool:
        """Returns whether the input is valid UUID."""
        try:
            uuid.UUID(str(val))
            return True
        except ValueError:
            pass
        return False


def ProcessInputConfig(omnicache: Omnicache, input_config: str) -> int:
    """Adds a list of remotes from a YAML config file to the omnicache."""
    logging.info("Adding remotes from {0}".format(input_config))
    with open(input_config) as icf:
        content = yaml.safe_load(icf)

    if "remotes" in content:
        for remote in content["remotes"]:
            # dict.get() used here to set name=None if no name specified in input cfg file.
            omnicache.AddRemote(remote["url"], name=remote.get("name"))

    return 0


def ScanDirectory(omnicache: Omnicache, scanpath: str) -> int:
    """Recursively scans a directory for git repositories and adds remotes and submodule remotes to omnicache."""
    logging.info("Scanning {0} for remotes to add.".format(scanpath))
    if not os.path.isdir(scanpath):
        logging.critical("specified scan path is invalid.")
        return -1

    for dirpath, dirnames, filenames in os.walk(scanpath):
        if ".git" in dirnames:
            newRemotes = Omnicache.GetRemotes(dirpath)
            for name, url in newRemotes.items():
                omnicache.AddRemote(url, name)

        if ".gitmodules" in filenames:
            out = StringIO()
            ret = RunCmd("git", "config --file .gitmodules --get-regexp url", workingdir=dirpath, outstream=out)
            if ret == 0:
                for submodule in out.getvalue().splitlines():
                    url = submodule.split()[1]
                    name = submodule.split()[0].split(".")[1]
                    omnicache.AddRemote(url, name)

    return 0


def Export(omnicache: Omnicache, exportPath: str) -> int:
    """Exports omnicache configuration to YAML."""
    logging.info("Exporting omnicache config for {0} to {1}".format(omnicache.path, exportPath))
    content = []
    for name, data in omnicache.GetRemoteData().items():
        remoteToWrite = {"url": data["url"]}
        if "displayname" in data:
            remoteToWrite["name"] = data["displayname"]
        else:
            remoteToWrite["name"] = name
        content.append(remoteToWrite)

    with open(exportPath, "w") as ocf:
        yaml.dump({"remotes": content}, ocf)

    return 0


def get_cli_options() -> argparse.Namespace:
    """Add CLI arguments to argparse for controlling the omnicache."""
    parser = argparse.ArgumentParser(
        description="Tool to provide easy method create and manage the OMNICACHE",
    )
    parser.add_argument(dest="cache_dir", help="path to an existing or desired OMNICACHE directory")
    parser.add_argument(
        "--scan",
        dest="scan",
        default=None,
        help="Scans the path provided for top-level folders with repos to add to the OMNICACHE",
    )
    parser.add_argument(
        "--new", dest="new", help="Initialize the OMNICACHE.  MUST NOT EXIST", action="store_true", default=False
    )
    parser.add_argument(
        "--init",
        dest="init",
        help="Initialize the OMNICACHE if it doesn't already exist",
        action="store_true",
        default=False,
    )
    parser.add_argument(
        "-l", "--list", dest="list", default=False, action="store_true", help="List config of OMNICACHE"
    )
    parser.add_argument(
        "-a",
        "--add",
        dest="add",
        nargs=2,
        action="append",
        help="Add config entry to OMNICACHE <name> <url>",
        default=[],
    )
    parser.add_argument(
        "-c",
        "--configfile",
        dest="input_config_file",
        default=None,
        help="Add new entries from config file to OMNICACHE",
    )
    parser.add_argument(
        "-e",
        "--exportConfig",
        dest="output_config_file",
        default=None,
        help="Export current omnicache config as a yaml file",
    )
    group = parser.add_mutually_exclusive_group()
    group.add_argument(
        "-u",
        "--update",
        "--fetch",
        dest="fetch",
        action="store_true",
        help="Update the Omnicache.  All cache changes also cause a fetch",
        default=False,
    )
    group.add_argument(
        "--no-fetch",
        dest="no_fetch",
        action="store_true",
        help="Prevent auto-fetch if implied by other arguments.",
        default=False,
    )
    group.add_argument(
        "--fetch-jobs",
        dest="fetch_jobs",
        type=int,
        help="Specify the number of parallel threads (jobs) for fetch operation.",
        default=0,
    )
    parser.add_argument(
        "-r",
        "--remove",
        dest="remove",
        nargs=1,
        action="append",
        help="remove config entry from OMNICACHE <name>",
        default=[],
    )
    parser.add_argument("--version", action="version", version="%(prog)s " + OMNICACHE_VERSION)
    parser.add_argument(
        "--debug", dest="debug", help="Output all debug messages to console", action="store_true", default=False
    )
    args = parser.parse_args()
    return args


def main() -> int:
    """Main entry point to managing the omnicache."""
    # setup main console as logger
    logger = logging.getLogger("")
    logger.setLevel(logging.NOTSET)
    console = edk2_logging.setup_console_logging(False)
    logger.addHandler(console)

    args = get_cli_options()

    if args.debug:
        console.setLevel(logging.DEBUG)

    logging.info("Log Started: " + datetime.datetime.strftime(datetime.datetime.now(), "%A, %B %d, %Y %I:%M%p"))

    args.cache_dir = os.path.realpath(os.path.abspath(args.cache_dir))
    logging.debug("OMNICACHE dir: {0}".format(args.cache_dir))

    if args.input_config_file is not None:
        args.input_config_file = os.path.realpath(os.path.abspath(args.input_config_file))
        if not os.path.isfile(args.input_config_file):
            logging.critical("Invalid -c argument given.  File ({0}) isn't valid".format(args.input_config_file))
            return -4

    logging.debug("Args: " + str(args))

    omnicache = None
    auto_fetch = False
    # new: initialize omnicache and error if it already exists
    if args.new:
        if os.path.isdir(args.cache_dir):
            logging.critical("--new argument given but OMNICACHE path already exists!")
            return -1
        omnicache = Omnicache(args.cache_dir, create=True)
        auto_fetch = True

    # init: initialize omnicache if not already initialized.
    if args.init and omnicache is None:
        omnicache = Omnicache(args.cache_dir, create=True, convert=True)
        auto_fetch = True

    # Other args require omnicache, so check that it exists.
    if omnicache is None:
        omnicache = Omnicache(args.cache_dir)

    # add: add new source(s) to omnicache from command line arg.
    if len(args.add) > 0:
        for name, url in args.add:
            ret = omnicache.AddRemote(url, name)
            if ret != 0:
                return -3
        auto_fetch = True

    # config: add or update sources(s) from config file.
    if args.input_config_file is not None:
        ret = ProcessInputConfig(omnicache, args.input_config_file)
        if ret != 0:
            return -4
        auto_fetch = True

    # remove: remove source(s) from omnicache as specified by command line arg.
    if len(args.remove) > 0:
        for url in args.remove:
            ret = omnicache.RemoveRemote(url)
            if ret != 0:
                return -4

    # scan: recursively scan the given directory and add all repos and submodules
    if args.scan is not None:
        ret = ScanDirectory(omnicache, args.scan)
        if ret != 0:
            return -5
        auto_fetch = True

    # fetch: update the omnicache with objects from its remotes.
    # Note: errors are ignored here, since transient network failures may occur that prevent cache update. Those just
    # mean the omnicache may be a a little stale which should not be fatal to users of the cache.
    if args.fetch or (auto_fetch and not args.no_fetch):
        omnicache.Fetch(args.fetch_jobs)

    # list: print out the omnicache contents.
    if args.list:
        omnicache.List()

    # export:
    if args.output_config_file:
        ret = Export(omnicache, args.output_config_file)
        if ret != 0:
            return -6

    return 0


if __name__ == "__main__":
    retcode = main()
    logging.shutdown()
    sys.exit(retcode)
