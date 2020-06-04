##
# This is the file that generates the documentation for edk2-pytools-extensions
#
##
# Copyright (c) Microsoft Corporation
#
# SPDX-License-Identifier: BSD-2-Clause-Patent
##
from edk2toolext.docgen import generate
import os

default_config = {
    "site_name": "edk2-pytool-extensions",
    "repo_url": "https://github.com/tianocore/edk2-pytool-extensions",
    "copyright": "SPDX-License-Identifier: BSD-2-Clause-Patent",
    "site_description": "Python tools supporting UEFI EDK2 firmware development",
    "site_url": "https://tianocore.github.io/edk2-pytool-extensions"
}


docgen = generate.DocGenerator()
workspace = os.path.abspath(os.path.dirname(__file__))
docgen.set_workspace(workspace)
docgen.set_config_defaults(**default_config)
docgen.set_verbose(True)
docgen.set_should_include_test_documentation(False)
docgen.add_doc_folder(os.path.join(workspace, "docs"))
docgen.set_target_module(os.path.join(workspace, "edk2toolext"))
docgen.generate()
docgen.deploy()
