# @file var_dict.py
# This module contains code for a special overridable dictionary.
# This stores most of the build configuration data and allows
# extensive config sharing for the build process, pre-build, and
# post-build.
##
# Copyright (c) Microsoft Corporation
#
# SPDX-License-Identifier: BSD-2-Clause-Patent
##
"""A special overridable dictionary.

Stores most of the build configuration data and allows extensive config
sharing for the build process, pre-build, and post-build.
"""

import logging
from random import choice
from string import ascii_letters
from typing import Optional, TextIO


class EnvEntry(object):
    """A single Environment Variable entry for VarDict.

    Attributes:
        Value (obj): The value to store in the dictionary
        Comment (str): A debug comment specifying where / how the value was set
        overridable (bool): If the value can be overwritten in the future
    """

    def __init__(self, value: str, comment: str, overridable: str = False) -> None:
        """Inits an entry with the specified values."""
        self.Value = value
        self.Comment = comment
        self.Overrideable = overridable

    def PrintEntry(self, f: Optional[TextIO] = None) -> None:
        """Prints the value.

        Args:
            f (str): a file to write to instead of the terminal.
        """
        print("Value: %s" % self.Value, file=f)
        print("Comment: %s" % self.Comment, file=f)
        if self.Overrideable:
            print("Value overridable", file=f)
        print("**********************", file=f)

    #
    # Function used to override the value if option allows it
    #

    def SetValue(self, value: str, comment: str, overridable: Optional[bool] = False) -> bool:
        """Sets the value of the entry if it os overridable.

        Args:
            value (str): value to set
            comment (str): A debug comment specifying where / how the value was set
            overridable (bool): If the value can be overwritten in the future

        !!! warning
            Even if you set a value as overridable=False, another entity can
            call `AllowOverride()` and change the value anyway.
        """
        if (value == self.Value) and (overridable == self.Overrideable):
            return True

        if not self.Overrideable:
            logging.debug("Can't set value [%s] as it isn't overrideable. Previous comment %s" % (value, self.Comment))
            return False

        self.Value = value
        self.Comment = comment
        self.Overrideable = overridable
        return True

    def AllowOverride(self) -> bool:
        """Allows the value to be overwritten in the future."""
        self.Overrideable = True
        return True

    def GetValue(self) -> str:
        """Returns the value."""
        return self.Value


class VarDict(object):
    """An overridable dictionary to store build configuration data."""

    def __init__(self) -> None:
        """Inits an empty VarDict."""
        self.Logger = logging.getLogger("EnvDict")
        self.Dstore = {}  # a set of envs

    def GetEntry(self, key: str) -> Optional[EnvEntry]:
        """Returns an entry in the Dstore Dict."""
        return self.Dstore.get(key.upper())

    def __copy__(self) -> "VarDict":
        """Copies data into a new VarDict."""
        new_copy = VarDict()
        new_copy.Logger = self.Logger

        new_copy.Dstore = {}
        for key in self.Dstore:
            entry = self.GetEntry(key)
            value = entry.Value
            comment = entry.Comment
            override = entry.Overrideable
            new_copy.SetValue(key, value, comment, override)
        return new_copy

    def GetValue(self, k: str, default: Optional[str] = None) -> str:
        """Gets a value from the variable dictionary that was set during build.

        !!! note
            Values set in DSC, FDF, and CLI stored as strings

        Args:
            k (str): The key the value was stored as
            default (str): default value if key is not present

        Returns:
            (str): The value of the key, if present, else default value
        """
        if k is None:
            logging.debug("GetValue - Invalid Parameter key is None.")
            return None

        key = k.upper()
        en = self.GetEntry(key)
        if en is not None:
            self.Logger.debug("Key %s found.  Value %s" % (key, en.GetValue()))
            return en.GetValue()
        else:
            self.Logger.debug("Key %s not found" % key)
            return default

    def SetValue(self, k: str, v: str, comment: str, overridable: bool = False) -> bool:
        """Sets an environment variable to be used throughout the build.

        Args:
            k (str): The key to store the value under
            v (str): The value to store as a string, or None to store
                a non valued build variable
            comment (str): A comment to show where / how the variable was stored.
                Useful for debugging
            overridable (bool): Specifies if the variable is allowed to be override
                elsewhere in the build

        Returns:
            (bool): If the variable was successfully stored or not
        """
        key = k.upper()
        en = self.GetEntry(key)
        if v is None:
            value = "".join(choice(ascii_letters) for _ in range(20))
        else:
            value = str(v)
        self.Logger.debug("Trying to set key %s to value %s" % (k, v))
        if en is None:
            # new entry
            en = EnvEntry(value, comment, overridable)
            self.Dstore[key] = en
            return True

        return en.SetValue(value, comment, overridable)

    def AllowOverride(self, k: str) -> bool:
        """Forces the key/value pair to be overridable.

        Note: Even if overridable was specifically set to False,
        it still allows it.

        Args:
            k (str): The key the value was stored as

        Returns:
            (bool): if the key existed or not
        """
        key = k.upper()
        en = self.GetEntry(key)
        if en is not None:
            self.Logger.warning("Allowing Override for key %s" % k)
            en.AllowOverride()
            return True
        return False

    def GetBuildValue(self, key: str, BuildType: Optional[str] = None) -> str:
        """Get a build var value for given key and buildtype.

        !!! tip
            Build vars are defined by vars that start with BLD_

            BLD_*_<YOUR VAR HERE> means all build types

            BLD_DEBUG_<YOUR VAR HERE> means build of debug type

            BLD_RELEASE_<YOUR VAR HERE> means build of release type

            etc

        Args:
            key (str): The key the value was stored as
            BuildType (str): DEBUG/RELEASE

        Returns:
            (str): The value of the key, if present, else None
        """
        rv = None

        if BuildType is None:
            BuildType = self.GetValue("TARGET")

        if BuildType is None:
            logging.debug("GetBuildValue - Invalid Parameter BuildType is None and Target Not set. Key is: " + key)
            return None

        if key is None:
            logging.debug("GetBuildValue - Invalid Parameter key is None. BuildType is: " + BuildType)
            return None

        ty = BuildType.upper().strip()
        tk = key.upper().strip()
        # see if specific
        k = "BLD_" + ty + "_" + tk
        rv = self.GetValue(k)
        if rv is None:
            # didn't fine build type specific so check for generic
            k = "BLD_*_" + tk
            rv = self.GetValue(k)

        # return value...if not found should return None
        return rv

    def GetAllBuildKeyValues(self, BuildType: Optional[str] = None) -> dict:
        """Gets a dictionary for all build vars.

        !!! tip
            Build vars are defined by vars that start with BLD_

            BLD_*_<YOUR VAR HERE> means all build types

            BLD_DEBUG_<YOUR VAR HERE> means build of debug type

            BLD_RELEASE_<YOUR VAR HERE> means build of release type

            etc

        Args:
            BuildType (:obj:`str`, optional): DEBUG/RELEASE

        Returns:
            (dict): all keys, values in the environment which are build keys

        """
        returndict = {}
        if BuildType is None:
            BuildType = self.GetValue("TARGET")

        if BuildType is None:
            logging.debug("GetAllBuildKeyValues - Invalid Parameter BuildType is None and Target Not Set.")
            return returndict

        ty = BuildType.upper().strip()
        logging.debug("Getting all build keys for build type " + ty)

        # get all the generic build options
        for key, value in self.Dstore.items():
            if key.startswith("BLD_*_"):
                k = key[6:]
                returndict[k] = value.GetValue()

        # will override with specific for this build type
        # figure out offset part of key name to strip
        ks = len(ty) + 5
        for key, value in self.Dstore.items():
            if key.startswith("BLD_" + ty + "_"):
                k = key[ks:]
                returndict[k] = value.GetValue()

        return returndict

    def GetAllNonBuildKeyValues(self) -> dict:
        """Returns a dict of non Build Key values.

        Return a copy of the dictionary of all keys, values in the environment
        which are not Build Keys.
        """
        returndict = {}
        # get all the generic build options
        for key, value in self.Dstore.items():
            if not key.startswith("BLD_"):
                returndict[key] = value.GetValue()
        return returndict

    def PrintAll(self, fp: Optional[TextIO] = None) -> None:
        """Prints all variables.

        If fp is not none, writes to a fp also

        Args:
            fp (str): file pointer to print to
        """
        f = None
        if fp is not None:
            f = open(fp, "a+")
        for key, value in self.Dstore.items():
            print("Key = %s" % key, file=f)
            value.PrintEntry(f)
        if f:
            f.close()
