## @file
# manage multiple workspace file.
#
# This file is required to make Python interpreter treat the directory
# as containing package.
#
# file slightly modified from Edk2 BaseTools\Source\Python\Common\MultipleWorkspace.py
#
# Copyright (c) 2015 - 2018, Intel Corporation. All rights reserved.<BR>
# Copyright (c) Microsoft Corporation
#
# SPDX-License-Identifier: BSD-2-Clause-Patent
#
"""This file is required to make Python interpreter treat the directory as a containing package.

File is slightly modified from Edk2 BaseTools/Source/Python/Common/MultipleWorkspace.py
"""

import os
import warnings
from typing import Optional


class MultipleWorkspace(object):
    """This class manages multiple workspace behavior.

    Attributes:
        WORKSPACE (str): defined the current workspace
        PACKAGES_PATH (str): defined the other WORKSPACE
    """

    WORKSPACE = ""
    PACKAGES_PATH = None

    @classmethod
    def convertPackagePath(cls: "MultipleWorkspace", Ws: str, Path: str) -> str:
        """Convert path to match workspace.

        Args:
            cls (MultipleWorkspace): The class pointer
            Ws (str): The current WORKSPACE
            Path (str): Path to be converted to match workspace

        Returns:
            (str): Converted path.
        """
        if str(os.path.normcase(Path)).startswith(Ws):
            return os.path.join(Ws, Path[len(Ws) + 1 :])
        return Path

    @classmethod
    def setWs(cls: "MultipleWorkspace", Ws: str, PackagesPath: Optional[list[str]] = None) -> None:
        """Set WORKSPACE and PACKAGES_PATH environment.

        Args:
            cls (MultipleWorkspace): The class pointer
            Ws (str): initialize WORKSPACE variable
            PackagesPath (str): initialize PackagesPath variable
        """
        cls.WORKSPACE = Ws
        if PackagesPath:
            cls.PACKAGES_PATH = [
                cls.convertPackagePath(Ws, os.path.normpath(Path.strip())) for Path in PackagesPath.split(os.pathsep)
            ]
        else:
            cls.PACKAGES_PATH = []

    @classmethod
    def join(cls: "MultipleWorkspace", Ws: str, *p: str) -> str:
        """Rewrite os.path.join.

        Args:
            cls (MultipleWorkspace): The class pointer
            Ws (str): the current WORKSPACE
            *p (str): path of the inf/dec/dsc/fdf/conf file

        Returns:
            (str): absolute path of the specified file
        """
        warnings.warn(
            "MultipleWorkspace is deprecated. Use Edk2Path.GetAbsolutePathOnThisSystemFromEdk2RelativePath().",
            DeprecationWarning,
            stacklevel=2,
        )
        Path = os.path.join(Ws, *p)
        if not os.path.exists(Path):
            for Pkg in cls.PACKAGES_PATH:
                Path = os.path.join(Pkg, *p)
                if os.path.exists(Path):
                    return Path
            Path = os.path.join(Ws, *p)
        return Path

    @classmethod
    def relpath(cls: "MultipleWorkspace", Path: str, Ws: str) -> str:
        """Rewrite os.path.relpath.

        Args:
            cls (MultipleWorkspace): The class pointer
            Path (str): path of the inf/dec/dsc/fdf/conf file
            Ws (str): the current WORKSPACE

        Returns:
            (str): the relative path of specified file
        """
        warnings.warn(
            "MultipleWorkspace is deprecated. use Edk2Path.GetEdk2RelativePathOnThisSystemFromAbsolutePath().",
            DeprecationWarning,
            stacklevel=2,
        )
        for Pkg in cls.PACKAGES_PATH:
            if Path.lower().startswith(Pkg.lower()):
                Path = os.path.relpath(Path, Pkg)
                return Path
        if Path.lower().startswith(Ws.lower()):
            Path = os.path.relpath(Path, Ws)
        return Path

    @classmethod
    def getWs(cls: "MultipleWorkspace", Ws: str, Path: str) -> str:
        """Get valid workspace for the path.

        Args:
            cls (MultipleWorkspace): The class pointer
            Ws (str): the current WORKSPACE
            Path (str): path of the inf/dec/dsc/fdf/conf file

        Returns:
            (str): valid workspace relative to the specified file path
        """
        absPath = os.path.join(Ws, Path)
        if not os.path.exists(absPath):
            for Pkg in cls.PACKAGES_PATH:
                absPath = os.path.join(Pkg, Path)
                if os.path.exists(absPath):
                    return Pkg
        return Ws

    @classmethod
    def handleWsMacro(cls: "MultipleWorkspace", PathStr: str) -> str:
        """Handle the $(WORKSPACE) tag.

        If current workspace is an invalid path relative to the tool, replace it.

        Args:
            cls (MultipleWorkspace): The class pointer
            PathStr (str): The path string

        Returns:
            (Str): Path string including the $(WORKSPACE)
        """
        warnings.warn(
            "MultipleWorkspace is deprecated. Manually replace the $(WORKSPACE). If you believe "
            "this functionality needs a direct replacement, file an issue in edk2-pytool-extensions.",
            DeprecationWarning,
            stacklevel=2,
        )
        TAB_WORKSPACE = "$(WORKSPACE)"
        if TAB_WORKSPACE in PathStr:
            PathList = PathStr.split()
            if PathList:
                for i, str in enumerate(PathList):
                    MacroStartPos = str.find(TAB_WORKSPACE)
                    if MacroStartPos != -1:
                        Substr = str[MacroStartPos:]
                        Path = Substr.replace(TAB_WORKSPACE, cls.WORKSPACE).strip()
                        if not os.path.exists(Path):
                            for Pkg in cls.PACKAGES_PATH:
                                Path = Substr.replace(TAB_WORKSPACE, Pkg).strip()
                                if os.path.exists(Path):
                                    break
                        PathList[i] = str[0:MacroStartPos] + Path
            PathStr = " ".join(PathList)
        return PathStr

    @classmethod
    def getPkgPath(cls: "MultipleWorkspace") -> list[str]:
        """Get all package paths.

        Args:
            cls (MultipleWorkspace): class pointer

        Returns:
            (list[str]): Packages Path

        """
        return cls.PACKAGES_PATH
