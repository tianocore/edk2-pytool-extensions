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

import logging


class EnvEntry(object):
    def __init__(self, value, comment, overridable=False):
        self.Value = value
        self.Comment = comment
        self.Overrideable = overridable

    def PrintEntry(self, f=None):
        print("Value: %s" % self.Value, file=f)
        print("Comment: %s" % self.Comment, file=f)
        if(self.Overrideable):
            print("Value overridable", file=f)
        print("**********************", file=f)
    #
    # Function used to override the value if option allows it
    #

    def SetValue(self, value, comment, overridable=False):
        if (value == self.Value) and (overridable == self.Overrideable):
            return True

        if(not self.Overrideable):
            logging.debug("Can't set value [%s] as it isn't overrideable. Previous comment %s" % (
                value, self.Comment))
            return False

        self.Value = value
        self.Comment = comment
        self.Overrideable = overridable
        return True

    def AllowOverride(self):
        self.Overrideable = True
        return True

    def GetValue(self):
        return self.Value


class VarDict(object):
    def __init__(self):
        self.Logger = logging.getLogger("EnvDict")
        self.Dstore = {}  # a set of envs

    def GetEntry(self, key):
        return self.Dstore.get(key.upper())

    def __copy__(self):
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

    def GetValue(self, k, default=None):
        if(k is None):
            logging.debug(
                "GetValue - Invalid Parameter key is None.")
            return None

        key = k.upper()
        en = self.GetEntry(key)
        if(en is not None):
            self.Logger.debug("Key %s found.  Value %s" % (key, en.GetValue()))
            return en.GetValue()
        else:
            self.Logger.debug("Key %s not found" % key)
            return default

    def SetValue(self, k, v, comment, overridable=False):
        key = k.upper()
        en = self.GetEntry(key)
        value = str(v)
        self.Logger.debug("Trying to set key %s to value %s" % (k, v))
        if(en is None):
            # new entry
            en = EnvEntry(value, comment, overridable)
            self.Dstore[key] = en
            return True

        return en.SetValue(value, comment, overridable)

    def AllowOverride(self, k):
        key = k.upper()
        en = self.GetEntry(key)
        if(en is not None):
            self.Logger.warn("Allowing Override for key %s" % k)
            en.AllowOverride()
            return True
        return False

    #
    # function used to get a build var value for given key and buildtype
    #
    # if BuildType is None
    # Build vars are defined by vars that start with BLD_
    #  BLD_*_<YOUR KEY HERE> means all build types
    #  BLD_DEBUG_<YOUR KEY HERE> means build of debug type
    #  BLD_RELEASE_<YOUR KEY HERE> means build of release type
    #  etc
    #

    def GetBuildValue(self, key, BuildType=None):
        rv = None

        if(BuildType is None):
            BuildType = self.GetValue("TARGET")

        if(BuildType is None):
            logging.debug(
                "GetBuildValue - Invalid Parameter BuildType is None and Target Not set. Key is: " + key)
            return None

        if(key is None):
            logging.debug(
                "GetBuildValue - Invalid Parameter key is None. BuildType is: " + BuildType)
            return None

        ty = BuildType.upper().strip()
        tk = key.upper().strip()
        # see if specific
        k = "BLD_" + ty + "_" + tk
        rv = self.GetValue(k)
        if(rv is None):
            # didn't fine build type specific so check for generic
            k = "BLD_*_" + tk
            rv = self.GetValue(k)

        # return value...if not found should return None
        return rv

    #
    # function used to get a dictionary for all build vars
    #
    # Build vars are defined by vars that start with BLD_
    #  BLD_*_<YOUR VAR HERE> means all build types
    #  BLD_DEBUG_<YOUR VAR HERE> means build of debug type
    #  BLD_RELEASE_<YOUR VAR HERE> means build of release type
    #  etc
    #
    def GetAllBuildKeyValues(self, BuildType=None):
        returndict = {}
        if(BuildType is None):
            BuildType = self.GetValue("TARGET")

        if(BuildType is None):
            logging.debug(
                "GetAllBuildKeyValues - Invalid Parameter BuildType is None and Target Not Set.")
            return returndict

        ty = BuildType.upper().strip()
        logging.debug("Getting all build keys for build type " + ty)

        # get all the generic build options
        for key, value in self.Dstore.items():
            if(key.startswith("BLD_*_")):
                k = key[6:]
                returndict[k] = value.GetValue()

        # will override with specific for this build type
        # figure out offset part of key name to strip
        ks = len(ty) + 5
        for key, value in self.Dstore.items():
            if(key.startswith("BLD_" + ty + "_")):
                k = key[ks:]
                returndict[k] = value.GetValue()

        return returndict

    def PrintAll(self, fp=None):
        f = None
        if(fp is not None):
            f = open(fp, 'a+')
        for key, value in self.Dstore.items():
            print("Key = %s" % key, file=f)
            value.PrintEntry(f)
        if(f):
            f.close()
