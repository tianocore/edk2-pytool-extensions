# @file regenerate.py
# Regenerates the documentation for this repo
#
#
# Copyright (c) Microsoft Corporation
#
# SPDX-License-Identifier: BSD-2-Clause-Patent
##
import sys
import os
from xml.etree import ElementTree
from urllib.request import urlopen
import re
import subprocess
import traceback
import tempfile
import logging
import json
import requests
import zipfile
import io


def get_releases(owner, repo):
    url = f"https://api.github.com/repos/{owner}/{repo}/tags"
    operUrl = urlopen(url)
    tags = []
    if(operUrl.getcode() == 200):
        data = operUrl.read()
        json_data = json.loads(data)
        for tag_data in json_data:
            if "name" not in tag_data:
                continue
            tags.append(tag_data["name"])
    else:
        print("Error receiving data", operUrl.getcode())
    # TODO : check if we need to get further pages
    return tags


def run_cmd(cmd, verbose=False, cwd=None):
    if verbose:
        print(cmd)
    stdout = sys.stdout if verbose else subprocess.PIPE
    stderr = sys.stderr if verbose else subprocess.STDOUT
    c = subprocess.Popen(cmd, stdout=stdout, stderr=stderr, cwd=cwd, shell=True)
    c.wait()
    return c.returncode


def run_pip_install(pip_install_location, owner, repo, version, verbose=False):
    if pip_install_location is None:
        pip_install_location = tempfile.mkdtemp()
        # Get clone
        run_cmd(f"git clone https://github.com/{owner}/{repo}.git {pip_install_location}", verbose=True)
        run_cmd(f"git fetch --tags", cwd=pip_install_location, verbose=True)

    # checkout the right version
    run_cmd(f"git checkout {version}", cwd=pip_install_location, verbose=True)

    # find the setup.py
    pip_root = pip_install_location
    for root, dirs, files in os.walk(pip_install_location, topdown=True):
        if "setup.py" in files:
            pip_root = root
            break

    print(f"Installing {pip_root}")
    cmd = f"pip install -e {pip_root} --force-reinstall"

    if run_cmd(cmd, verbose=verbose) != 0:
        print(f"Failed to install {module}@{version}")
        sys.exit(1)
    return pip_install_location


if __name__ == "__main__":
    owner = "tianocore"
    repo = "edk2-pytool-library"
    module_name = "edk2-pytool-library"
    module = "edk2toollib"
    verbose = True
    tags = get_releases(owner, repo)
    pip_install_location = None
    # TODO save what version we currently have installed 
    output_dir = os.path.abspath(os.path.join(os.path.dirname(os.path.dirname(__file__)), "doc_output"))
    for version in tags:
        print(f"\n-----------\nDeploying {version}")
        pip_install_location = run_pip_install(pip_install_location, owner, repo, version, verbose)
        attempts = 0
        while attempts < 4:
            try:
                from edk2toollib import utility_functions
                generate_script = os.path.join(os.path.dirname(__file__), "generate.py")
                params = f'-deploy -ws "{pip_install_location}" --output_dir "{output_dir}"'
                ret = utility_functions.RunPythonScript(
                    generate_script, params, workingdir=os.getcwd(), outstream=sys.stdout, logging_level=logging.CRITICAL)
                if ret != 0:
                    raise ValueError(f"Returned value of {ret}")
                break
            except Exception:
                traceback.print_exc()
                attempts += 1
    print("Finished")
    # TODO reinstall the version we had installed before this started
    # TODO: setup a virtual environment?
